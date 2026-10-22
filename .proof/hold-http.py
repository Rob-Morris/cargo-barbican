from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
import time
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  print("Real age-lock request received",self.path,flush=True)
  time.sleep(300)
ThreadingHTTPServer(("127.0.0.1",38941),Handler).serve_forever()
