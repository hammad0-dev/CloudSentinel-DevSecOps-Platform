import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from app import application


class FixtureTests(unittest.TestCase):
    def request(self, path, query):
        status = []
        body = b"".join(application({"PATH_INFO": path, "QUERY_STRING": query}, lambda s, h: status.append(s)))
        return status[0], body.decode()

    def test_sqli_synthetic_only(self):
        self.assertIn("demo-one", self.request("/test/sqli", "id=1")[1])
        self.assertNotIn("demo-two", self.request("/test/sqli", "id=1")[1])
        self.assertIn("demo-two", self.request("/test/sqli", "id=1%20OR%201=1")[1])

    def test_xss_reflection(self):
        self.assertIn("<script>alert(1)</script>", self.request("/test/xss", "q=%3Cscript%3Ealert(1)%3C/script%3E")[1])

    def test_health(self):
        self.assertEqual(("200 OK", "fixture-ready"), self.request("/health", ""))

    def test_scope(self):
        self.assertEqual("404 Not Found", self.request("/admin", "")[0])

    def test_health_ignores_payloads_and_never_opens_database(self):
        with patch('app.sqlite3.connect', side_effect=AssertionError('health must not use SQLite')):
            self.assertEqual(('200 OK', 'fixture-ready'), self.request('/health', 'id=1%20OR%201=1&q=%3Cscript%3Ebad%3C/script%3E'))

    def test_handlers_need_no_outbound_network(self):
        with patch('socket.socket', side_effect=AssertionError('no outbound sockets')):
            self.assertEqual('200 OK', self.request('/health', '')[0])
            self.assertIn('demo-two', self.request('/test/sqli', 'id=1%20OR%201=1')[1])
            self.assertIn('<script>alert(1)</script>', self.request('/test/xss', 'q=%3Cscript%3Ealert(1)%3C/script%3E')[1])

    def test_sqlite_files_are_disposable_on_success_and_query_failure(self):
        original = tempfile.TemporaryDirectory
        with original(prefix='cs-fixture-offline-') as root:
            def isolated(**kwargs):
                self.assertEqual(kwargs['dir'], '/tmp')
                return original(prefix=kwargs['prefix'], dir=root)
            with patch('app.tempfile.TemporaryDirectory', side_effect=isolated):
                for query in ('id=1', 'id=1%20OR%201=1', 'id=invalid_syntax'):
                    self.request('/test/sqli', query)
                    self.assertEqual(list(Path(root).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
