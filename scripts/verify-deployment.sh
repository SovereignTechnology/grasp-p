#!/bin/sh
set -eu

usage() {
    echo "Usage: $0 <public-base-url>" >&2
    echo "Example: $0 https://ngit.example.com" >&2
}

if [ "$#" -ne 1 ]; then
    usage
    exit 2
fi

base_url=${1%/}
case "${base_url}" in
    http://*|https://*) ;;
    *)
        echo "public base URL must start with http:// or https://" >&2
        exit 2
        ;;
esac

for required_command in curl grep mktemp; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        echo "missing required command: ${required_command}" >&2
        exit 2
    fi
done

temporary_directory=$(mktemp -d)
cleanup() {
    rm -rf -- "${temporary_directory}"
}
trap cleanup EXIT HUP INT TERM

nip11_body=${temporary_directory}/nip11.json
websocket_headers=${temporary_directory}/websocket.headers

curl \
    --fail \
    --silent \
    --show-error \
    --connect-timeout 5 \
    --max-time 15 \
    --retry 20 \
    --retry-all-errors \
    --retry-max-time 120 \
    --header 'Accept: application/nostr+json' \
    --output "${nip11_body}" \
    "${base_url}"

if command -v jq >/dev/null 2>&1; then
    jq -e '
        (.pubkey | type == "string" and length == 64) and
        (.supported_nips | type == "array")
    ' "${nip11_body}" >/dev/null
else
    grep -q '"pubkey"' "${nip11_body}"
    grep -q '"supported_nips"' "${nip11_body}"
fi
echo "ok: NIP-11 relay information"

set +e
curl \
    --http1.1 \
    --silent \
    --show-error \
    --connect-timeout 5 \
    --max-time 5 \
    --dump-header "${websocket_headers}" \
    --output /dev/null \
    --header 'Connection: Upgrade' \
    --header 'Upgrade: websocket' \
    --header 'Sec-WebSocket-Version: 13' \
    --header 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    "${base_url}"
websocket_curl_status=$?
set -e

if ! grep -Eq '^HTTP/[0-9.]+ 101([[:space:]]|$)' "${websocket_headers}"; then
    echo "WebSocket upgrade failed (curl status ${websocket_curl_status})" >&2
    cat "${websocket_headers}" >&2
    exit 1
fi
echo "ok: WebSocket upgrade"

if [ "${VERIFY_METRICS:-true}" = true ]; then
    curl \
        --fail \
        --silent \
        --show-error \
        --connect-timeout 5 \
        --max-time 15 \
        --output /dev/null \
        "${base_url}/metrics"
    echo "ok: Prometheus metrics"
fi

echo "deployment verified: ${base_url}"
