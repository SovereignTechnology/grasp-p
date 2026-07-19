#!/usr/bin/env python3
"""G6 upstream sink (GRASP-P Phase-0).

Minimal HTTP/1.1 server that accepts PUT /upload, streams the body in
1 MiB chunks through sha256 (never holding the whole body in memory),
and answers 200 with {"sha256": ..., "bytes": N}.

It logs machine-parseable timing lines to stdout (flushed immediately):

    SINK req=<n> request_line  t_mono=<s> t_epoch=<s> raw=<request-line>
    SINK req=<n> first_chunk   t_mono=<s> t_epoch=<s> n=<bytes-in-first-read>
    SINK req=<n> body_complete t_mono=<s> t_epoch=<s> bytes=<N> sha256=<hex>

t_mono is time.monotonic() (for intra-process deltas); t_epoch is
time.time() (for correlating with client-side wall-clock timestamps on
the same host).
"""

import argparse
import hashlib
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

CHUNK = 1024 * 1024  # 1 MiB


def log(event, seq, **kv):
    parts = [
        "SINK req=%d %s" % (seq, event),
        "t_mono=%.6f" % time.monotonic(),
        "t_epoch=%.6f" % time.time(),
    ]
    parts += ["%s=%s" % (k, v) for k, v in kv.items()]
    print(" ".join(parts), flush=True)


class SinkHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seq = 0

    # Called by handle_one_request() immediately after the request line
    # has been read off the socket -- this is the "request line arrived"
    # timestamp.
    def parse_request(self):
        SinkHandler.seq += 1
        self._seq = SinkHandler.seq
        raw = self.raw_requestline[:80].decode("latin-1", "replace").strip()
        log("request_line", self._seq, raw=raw.replace(" ", "_"))
        return super().parse_request()

    def do_PUT(self):
        if self.path != "/upload":
            self.send_error(404, "not found")
            return

        hasher = hashlib.sha256()
        total = 0
        first_seen = False
        te = (self.headers.get("Transfer-Encoding") or "").lower()

        def feed(data):
            nonlocal total, first_seen
            if not first_seen:
                first_seen = True
                log("first_chunk", self._seq, n=len(data))
            hasher.update(data)
            total += len(data)

        try:
            if "chunked" in te:
                # Minimal chunked-transfer decoder.
                while True:
                    line = self.rfile.readline(1024).strip()
                    if b";" in line:
                        line = line.split(b";", 1)[0]
                    size = int(line, 16)
                    if size == 0:
                        while True:  # drain trailers
                            t = self.rfile.readline(1024)
                            if t in (b"\r\n", b"\n", b""):
                                break
                        break
                    remaining = size
                    while remaining:
                        data = self.rfile.read(min(CHUNK, remaining))
                        if not data:
                            raise EOFError("EOF inside chunk")
                        feed(data)
                        remaining -= len(data)
                    self.rfile.readline(1024)  # chunk-trailing CRLF
            else:
                length = int(self.headers.get("Content-Length", "0"))
                remaining = length
                while remaining > 0:
                    want = min(CHUNK, remaining)
                    # read1() returns as soon as *any* bytes are available
                    # (up to `want`), so first_chunk marks true first-byte
                    # arrival rather than "first full MiB arrived".
                    if hasattr(self.rfile, "read1"):
                        data = self.rfile.read1(want)
                    else:
                        data = self.rfile.read(want)
                    if not data:
                        raise EOFError("EOF before Content-Length satisfied")
                    feed(data)
                    remaining -= len(data)
        except Exception as exc:  # noqa: BLE001 - report and drop conn
            log("body_error", self._seq, err=repr(exc).replace(" ", "_"))
            self.close_connection = True
            return

        digest = hasher.hexdigest()
        log("body_complete", self._seq, bytes=total, sha256=digest)

        body = json.dumps({"sha256": digest, "bytes": total}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # suppress default access log
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18081)
    args = ap.parse_args()

    srv = HTTPServer((args.host, args.port), SinkHandler)
    log("listening", 0, host=args.host, port=args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
