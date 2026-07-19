#!/usr/bin/env bash
# G6 (GRASP-P Phase-0): 256 MiB streamed-PUT nginx shape test.
#
# Proves that the exact deploy-shape nginx vhost
#   location /upload { limit_req zone=blobput burst=20;
#                      client_max_body_size 0;
#                      proxy_request_buffering off;
#                      proxy_http_version 1.1;
#                      proxy_pass http://upstream; }
# streams a 256 MiB PUT body to the upstream WITHOUT buffering the whole
# request first, and returns the upstream response unmangled.
#
# PRIMARY RUN  (proxy_request_buffering off): upstream must see the first
#   body bytes < 2 s after the client starts a throttled ~6 s transfer.
# NEGATIVE CONTROL (proxy_request_buffering on): upstream must see the
#   first body bytes only near the END of the client transfer (> 3 s),
#   proving the methodology actually detects buffering.
#
# Requires: docker (no sudo), python3, curl, ss. Binds only
# 127.0.0.1:18080/18081 (falls back to 18980/18981 if busy).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIZE=268435456 # 256 MiB
FAILURES=()
CONTROL_WEAK=0

# ---------------------------------------------------------------- helpers
port_busy() { # $1 = port; true if something LISTENs on it
    ss -ltn 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {found=1} END {exit !found}'
}

field() { # $1 = "k=v k=v ..." line, $2 = key -> prints value
    tr ' ' '\n' <<<"$1" | awk -F= -v k="$2" '$1==k {print $2; exit}'
}

fsub() { python3 -c "print('%.3f' % (float('$1') - float('$2')))"; }
flt()  { python3 -c "import sys; sys.exit(0 if float('$1') <  float('$2') else 1)"; }
fgt()  { python3 -c "import sys; sys.exit(0 if float('$1') >  float('$2') else 1)"; }

check() { # $1 = label, $2 = 0/1 pass flag, $3 = detail
    if [ "$2" -eq 0 ]; then
        echo "  [PASS] $1 -- $3"
    else
        echo "  [FAIL] $1 -- $3"
        FAILURES+=("$1")
    fi
}

# ---------------------------------------------------------------- ports
NGINX_PORT=18080
SINK_PORT=18081
if port_busy "$NGINX_PORT" || port_busy "$SINK_PORT"; then
    echo "NOTE: 18080/18081 busy, falling back to 18980/18981"
    NGINX_PORT=18980
    SINK_PORT=18981
    if port_busy "$NGINX_PORT" || port_busy "$SINK_PORT"; then
        echo "FATAL: fallback ports 18980/18981 busy too" >&2
        exit 1
    fi
fi
echo "== G6: nginx :$NGINX_PORT -> sink :$SINK_PORT =="

# ---------------------------------------------------------------- cleanup
TMP="$(mktemp -d "${TMPDIR:-/tmp}/g6-nginx.XXXXXX")"
SINK_PID=""
NGX_CID=""
cleanup() {
    set +e
    if [ -n "$SINK_PID" ]; then
        kill "$SINK_PID" 2>/dev/null
        wait "$SINK_PID" 2>/dev/null
    fi
    [ -n "$NGX_CID" ] && docker stop -t 2 "$NGX_CID" >/dev/null 2>&1
    rm -rf "$TMP"
}
trap cleanup EXIT

# ---------------------------------------------------------------- fixture
echo "== generating 256 MiB random body =="
head -c "$SIZE" /dev/urandom > "$TMP/bigfile"
LOCAL_SHA="$(sha256sum "$TMP/bigfile" | awk '{print $1}')"
echo "   local sha256 = $LOCAL_SHA"

write_conf() { # $1 = proxy_request_buffering value: off | on
    cat > "$TMP/nginx.conf" <<EOF
worker_processes 1;
events {}
http {
    limit_req_zone \$binary_remote_addr zone=blobput:10m rate=10r/s;
    server {
        listen 127.0.0.1:${NGINX_PORT};
        location /upload {
            limit_req zone=blobput burst=20;
            client_max_body_size 0;
            proxy_request_buffering $1;
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:${SINK_PORT};
        }
    }
}
EOF
}

# ---------------------------------------------------------------- sink
echo "== starting upstream sink on 127.0.0.1:$SINK_PORT =="
python3 "$SCRIPT_DIR/upstream_sink.py" --port "$SINK_PORT" > "$TMP/sink.log" 2>&1 &
SINK_PID=$!
for _ in $(seq 1 50); do port_busy "$SINK_PORT" && break; sleep 0.1; done
port_busy "$SINK_PORT" || { echo "FATAL: sink never listened" >&2; cat "$TMP/sink.log" >&2; exit 1; }

# ---------------------------------------------------------------- nginx
if ! docker image inspect nginx:alpine >/dev/null 2>&1; then
    echo "== pulling nginx:alpine =="
    docker pull nginx:alpine
fi

start_nginx() {
    NGX_CID="$(docker run --rm -d --network host \
        -v "$TMP/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:alpine)"
    for _ in $(seq 1 50); do port_busy "$NGINX_PORT" && break; sleep 0.1; done
    if ! port_busy "$NGINX_PORT"; then
        echo "FATAL: nginx never listened on :$NGINX_PORT" >&2
        docker logs "$NGX_CID" 2>&1 | tail -30 >&2
        exit 1
    fi
}

stop_nginx() { # $1 = log file name to save docker logs into (under $TMP)
    docker logs "$NGX_CID" > "$TMP/$1" 2>&1 || true
    docker stop -t 2 "$NGX_CID" >/dev/null 2>&1 || true
    NGX_CID=""
}

do_put() { # $1 = resp file suffix; echoes "t0 rc http_code time_total"
    local t0 out rc
    t0="$(date +%s.%N)"
    set +e
    out="$(curl -sS -o "$TMP/resp_$1.json" -w '%{http_code} %{time_total}' \
        -T "$TMP/bigfile" --limit-rate 40M \
        "http://127.0.0.1:${NGINX_PORT}/upload" 2>"$TMP/curl_$1.err")"
    rc=$?
    set -e
    echo "$t0 $rc $out"
}

# ================================================================ PRIMARY
echo
echo "== PRIMARY RUN: proxy_request_buffering off (deploy shape) =="
write_conf off
start_nginx

read -r T0_P RC_P CODE_P TOTAL_P <<<"$(do_put primary)"
echo "   curl rc=$RC_P http=$CODE_P time_total=${TOTAL_P}s"
[ "$RC_P" -eq 0 ] || { echo "   curl stderr:"; cat "$TMP/curl_primary.err"; }

FC_LINE_P="$(grep ' first_chunk ' "$TMP/sink.log" | sed -n '1p' || true)"
BC_LINE_P="$(grep ' body_complete ' "$TMP/sink.log" | sed -n '1p' || true)"
FC_EPOCH_P="$(field "$FC_LINE_P" t_epoch)"
UP_SHA_P="$(field "$BC_LINE_P" sha256)"
UP_BYTES_P="$(field "$BC_LINE_P" bytes)"
DELAY_P="$(fsub "${FC_EPOCH_P:-0}" "$T0_P")"

RESP_SHA_P=""
RESP_BYTES_P=""
if [ -s "$TMP/resp_primary.json" ]; then
    read -r RESP_SHA_P RESP_BYTES_P <<<"$(python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
print(d.get("sha256",""), d.get("bytes",""))' "$TMP/resp_primary.json")"
fi

stop_nginx nginx_primary.log

echo "   upstream first_chunk delay after transfer start: ${DELAY_P}s"
echo "   upstream saw bytes=$UP_BYTES_P sha256=$UP_SHA_P"
echo
echo "-- primary assertions --"
[ "$RC_P" -eq 0 ] && [ "$CODE_P" = "200" ]; check "a. HTTP 200" $? "curl rc=$RC_P http_code=$CODE_P"

if [ "$RESP_SHA_P" = "$LOCAL_SHA" ] && [ "$RESP_BYTES_P" = "$SIZE" ] \
   && [ "$UP_SHA_P" = "$LOCAL_SHA" ] && [ "$UP_BYTES_P" = "$SIZE" ]; then ok=0; else ok=1; fi
check "b. sha256+bytes unmangled" $ok "resp sha=$RESP_SHA_P bytes=$RESP_BYTES_P (local $LOCAL_SHA)"

if [ -n "$FC_EPOCH_P" ] && flt "$DELAY_P" 2.0 && fgt "$TOTAL_P" 4.0; then ok=0; else ok=1; fi
check "c. streaming proof" $ok "first_chunk after ${DELAY_P}s while client transfer took ${TOTAL_P}s (need <2s and >4s)"

NGLOG_ISSUES="$(grep -E 'client intended to send too large body|\[(error|crit|alert|emerg)\]' \
    "$TMP/nginx_primary.log" || true)"
[ -z "$NGLOG_ISSUES" ]; check "d. clean nginx logs" $? "${NGLOG_ISSUES:-no too-large-body / error-level lines}"

# ================================================================ CONTROL
echo
echo "== NEGATIVE CONTROL: proxy_request_buffering on =="
write_conf on
start_nginx

read -r T0_C RC_C CODE_C TOTAL_C <<<"$(do_put control)"
echo "   curl rc=$RC_C http=$CODE_C time_total=${TOTAL_C}s"

FC_LINE_C="$(grep ' first_chunk ' "$TMP/sink.log" | sed -n '2p' || true)"
BC_LINE_C="$(grep ' body_complete ' "$TMP/sink.log" | sed -n '2p' || true)"
FC_EPOCH_C="$(field "$FC_LINE_C" t_epoch)"
UP_SHA_C="$(field "$BC_LINE_C" sha256)"
DELAY_C="$(fsub "${FC_EPOCH_C:-0}" "$T0_C")"

stop_nginx nginx_control.log

echo "   upstream first_chunk delay after transfer start: ${DELAY_C}s (buffered path)"
echo
echo "-- control assertion --"
if [ "$RC_C" -eq 0 ] && [ "$CODE_C" = "200" ] && [ "$UP_SHA_C" = "$LOCAL_SHA" ] \
   && [ -n "$FC_EPOCH_C" ] && fgt "$DELAY_C" 3.0; then
    echo "  [PASS] e. buffering detected -- first_chunk only after ${DELAY_C}s (client transfer ${TOTAL_C}s): methodology distinguishes buffered vs streamed"
else
    CONTROL_WEAK=1
    echo "  [WEAK] e. control did NOT show clear buffering: delay=${DELAY_C}s total=${TOTAL_C}s rc=$RC_C http=$CODE_C"
    echo "         The streaming-proof methodology could not be validated; treat gate as inconclusive."
fi

# ================================================================ summary
echo
echo "== sink log =="
sed 's/^/   /' "$TMP/sink.log"
echo "== nginx primary log (tail) =="
tail -5 "$TMP/nginx_primary.log" | sed 's/^/   /'
echo
echo "== SUMMARY =="
echo "   streamed (buffering off): first_chunk +${DELAY_P}s of ${TOTAL_P}s transfer"
echo "   buffered (buffering on):  first_chunk +${DELAY_C}s of ${TOTAL_C}s transfer"
if [ "${#FAILURES[@]}" -eq 0 ] && [ "$CONTROL_WEAK" -eq 0 ]; then
    echo "G6 PASS"
    exit 0
elif [ "${#FAILURES[@]}" -eq 0 ]; then
    echo "G6 INCONCLUSIVE (primary assertions passed, negative control weak)"
    exit 3
else
    echo "G6 FAIL: ${FAILURES[*]}"
    exit 1
fi
