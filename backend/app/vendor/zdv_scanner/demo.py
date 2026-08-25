import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import ScanEngine
from .fuzzer import Fuzzer
from .report import write_report
from .target import Target

BODY = b"""<html><head><title>Demo Admin Panel</title></head>
<body><h1>Login</h1>
<form><input name="user" value="admin"><input name="password" value="admin"></form>
</body></html>"""


class DemoServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/boom"):
            self.send_error(500, "Internal Server Error")
            return
        body = BODY
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49 (Unix)")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), DemoServerHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    target = Target(host="127.0.0.1", port=port, name=f"demo server (http://127.0.0.1:{port})")
    print(f"scanning demo target at http://127.0.0.1:{port}")
    result = ScanEngine().scan(target)
    print(write_report(result, fmt="markdown"))
    fuzz_result = Fuzzer().fuzz(target, corpus=["/"], iterations=30)
    print(f"fuzzing: {fuzz_result.requests} requests, {len(fuzz_result.anomalies)} anomalies")
    httpd.shutdown()
