
import os
from pathlib import Path
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Always serve files from this script's own folder
BASE_DIR = Path(__file__).resolve().parent

class Handler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript",
        ".css": "text/css",
        ".bin": "application/octet-stream",
        ".appcache": "text/cache-manifest",
    }

    def end_headers(self):
        path = getattr(self, "path", "").split("?")[0].lower()

        if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico")):
            self.send_header("Cache-Control", "public, max-age=604800")
        else:
            self.send_header("Cache-Control", "no-cache, must-revalidate")

        super().end_headers()

server = ThreadingHTTPServer(
    ("0.0.0.0", 8000),
    partial(Handler, directory=str(BASE_DIR))
)

print("SploitTester Local Host")
print("Serving folder:", BASE_DIR)
print("Local URL: http://localhost:8000/")
print("Network URL: http://192.168.1.75:8000/")

try:
    server.serve_forever()
except KeyboardInterrupt:
    print("\nServer stopped.")
    server.server_close()

