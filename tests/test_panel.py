import base64
import http.client
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('panel_module', Path(__file__).resolve().parents[1] / 'panel/panel.py')
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        pwd = Path(self.tmp.name) / 'password'; pwd.write_text('test-password')
        self.password_patch = patch.object(panel, 'PASSFILE', pwd); self.password_patch.start()
        self.server = panel.ThreadingHTTPServer(('127.0.0.1', 0), panel.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.auth = 'Basic ' + base64.b64encode(b'admin:test-password').decode()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.password_patch.stop(); self.tmp.cleanup()

    def request(self, method='GET', path='/api/routes', data=None, auth=True, csrf=True, origin=None):
        headers = {}
        if auth: headers['Authorization'] = self.auth
        if csrf: headers['X-Panel-Token'] = panel.CSRF
        if origin: headers['Origin'] = origin
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request(method, path, body=json.dumps(data) if data is not None else None, headers=headers)
        res = conn.getresponse(); body = res.read(); status = res.status; conn.close()
        return status, json.loads(body) if body else None

    def test_routes_require_authentication(self):
        with patch.object(panel, 'manager', side_effect=AssertionError('unauthorized read')):
            self.assertEqual(self.request(auth=False)[0], 401)

    def test_load_and_save_routes(self):
        rules = {'manual-ru': [], 'manual-exit': ['8.8.8.8/32'], 'domain-ru': [], 'domain-exit': []}
        result = {'rules': rules, 'revision': 'revision-one'}
        def backend(*args, body=None):
            if args == ('routes',) and body is None: return result
            if args == ('routes-save',) and body == result: return dict(result, revision='revision-two')
            raise AssertionError('Wrong API dispatch')
        with patch.object(panel, 'manager', side_effect=backend):
            self.assertEqual(self.request(), (200, result))
            self.assertEqual(self.request('POST', '/api/routes-save', result),
                             (200, dict(result, revision='revision-two')))

    def test_save_rejects_missing_csrf_and_foreign_origin(self):
        with patch.object(panel, 'manager', side_effect=AssertionError('unsafe write')):
            self.assertEqual(self.request('POST', '/api/routes-save', {}, csrf=False)[0], 403)
            self.assertEqual(self.request('POST', '/api/routes-save', {}, origin='https://evil.example')[0], 403)

    def test_malformed_json_shape_is_client_error(self):
        self.assertEqual(self.request('POST', '/api/routes-save', [])[0], 400)


if __name__ == '__main__': unittest.main()
