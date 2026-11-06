"""Exercise the installed publisher against a loopback Hydra fixture."""
import json
import os
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SHA = 'a' * 40


class Hydra(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        self.requests.append(self.path)
        meta = {'hellasSrc': {'revision': SHA}, 'component': {'value': 'cli'}}
        if self.path == '/jobset/hellas/hellas-cli/evals':
            data = {'evals': [{'id': 100, 'jobsetevalinputs': meta},
                              {'id': 101, 'jobsetevalinputs': meta}]}
        elif self.path == '/jobset/hellas/hellas-gpu/evals':
            data = {'evals': []}
        elif self.path == '/eval/101':
            data = {'id': 101, 'jobsetevalinputs': meta}
        elif self.path in ('/eval/100/builds', '/eval/101/builds'):
            data = [{'project': 'hellas', 'jobset': 'hellas-cli', 'job': 'channel',
                     'finished': 1, 'buildstatus': 0}]
        else:
            self.send_error(404)
            return
        encoded = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_):
        pass


class DispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Hydra)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def run_publish(self, *args):
        Hydra.requests = []
        env = os.environ.copy()
        env.pop('GHCR_TOKEN', None)
        env['HYDRA_URL'] = f'http://127.0.0.1:{self.server.server_port}'
        return subprocess.run([os.environ['HELLAS_PUBLISH_BIN'], '--dry-run', *args],
                              env=env, text=True, capture_output=True, check=False)

    def test_exact_evaluation_is_checked_even_when_newer_same_revision_exists(self):
        result = self.run_publish('--revision', SHA, '--jobset', 'hellas-cli', '--evaluation', '101')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('/eval/101', Hydra.requests)
        self.assertIn('awaiting the other green channel', result.stdout)

    def test_revision_mismatch_is_rejected(self):
        result = self.run_publish('--revision', 'b' * 40, '--jobset', 'hellas-cli', '--evaluation', '101')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('evaluation does not match dispatch', result.stderr)

    def test_missing_dispatch_values_never_fall_back_to_latest(self):
        result = self.run_publish('--revision', '', '--jobset', '', '--evaluation', '')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(Hydra.requests, [])


if __name__ == '__main__':
    unittest.main()
