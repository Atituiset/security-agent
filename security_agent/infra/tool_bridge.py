"""Per-attempt authenticated loopback bridge for local Agent tool transports."""
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import contextmanager
from security_agent.core.contracts import validate


@contextmanager
def tool_bridge(descriptors):
    tools = {tool.name: tool for tool in descriptors}
    token = secrets.token_urlsafe(32)
    mutex = threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)
        def log_message(self, *args):
            pass
        def do_POST(self):
            if self.headers.get('Authorization') != 'Bearer ' + token:
                self.send_error(403); return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 1_000_000:
                    raise ValueError('invalid request size')
                request = json.loads(self.rfile.read(size))
                if self.path == '/list':
                    response = [{'name': t.name, 'description': t.description, 'schema': t.schema} for t in tools.values()]
                elif self.path == '/call':
                    tool = tools[request['name']]
                    validate(request['arguments'], tool.schema)
                    with mutex:
                        response = tool.execute(request['arguments'])
                else:
                    raise ValueError('unknown endpoint')
                data = json.dumps(response, ensure_ascii=True).encode()
                self.send_response(200)
            except Exception as exc:
                data = json.dumps({'error': f'{type(exc).__name__}: {exc}'}).encode()
                self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data))); self.end_headers()
            try:
                self.wfile.write(data)
            except BrokenPipeError:
                pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    # Wait for bounded active tool callbacks before the attempt is sealed.
    server.daemon_threads = False
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield {'SECURITY_TOOL_URL': f'http://127.0.0.1:{server.server_port}', 'SECURITY_TOOL_TOKEN': token}
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
