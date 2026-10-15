import unittest
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


if __name__ == "__main__":
    unittest.main()
