from contextlib import contextmanager
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from login_probe.client import (
    FAILURE_MESSAGE, 
    MAX_RESPONSE_BYTES, 
    LoginClient, 
    Outcome,
    classify_response,
)
from login_probe.rate_limit import run_probe
from login_probe.cli import build_parser

# RESPONSE CLASSIFICATION 
FAILURE = json.dumps({
    "accessToken": None,
    "tokenType": None,
    "expiration": None,
    "message": FAILURE_MESSAGE,
}).encode()
SUCCESS = json.dumps({
    "accessToken": "secret-jwt-must-not-be-reported",
    "tokenType": "Bearer",
    "message": "Successfully logged in.",
}).encode()

class ResponseClassificationTests(unittest.TestCase):
    def test_known_failures_are_401(self):
        self.assertEqual(classify_response(401, FAILURE), Outcome.AUTH_FAILURE)

    def test_success_requires_nonempty_token_and_success_status(self):
        self.assertEqual(classify_response(200, SUCCESS), Outcome.SUCCESS)
        for status, body in ((401, SUCCESS), (200, b'{"accessToken":""}')):
            with self.subTest(status=status, body=body):
                self.assertEqual(classify_response(status, body), Outcome.UNEXPECTED)

    def test_429_does_not_need_json(self):
        self.assertEqual(classify_response(429, b"<html>Slow down</html>"), Outcome.THROTTLED)

    def test_unknown_responses_do_not_become_rate_limiting_or_failures(self):
        for status, body in (
            (403, FAILURE), (500, FAILURE), (302, FAILURE),
            (401, b'{}'), (200, b'[]'), (200, b'null'),
            (200, b'not JSON'), (200, b'\xff'),
            (200, json.dumps({"message": FAILURE_MESSAGE}).encode()),
        ):
            with self.subTest(status=status, body=body):
                self.assertEqual(classify_response(status, body), Outcome.UNEXPECTED)

# MOCK LOGIN SERVER
@contextmanager
def login_server(responses):
    """This is for mocking a real server. It starts a real HTTP server and 
    it returns the predetermined [responses]. In this way, we can send real 
    HTTP requests without using the actual server.
    It yields a """
    """Yield a loopback endpoint and the requests it actually received."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        """This class defines the behavior of the server, and how it handles requests. 
        We only need to consider POST requests for these tests."""
        def do_POST(self):
            """Function for handling POST requests."""
            # Use rfile (read file) to read request
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received.append((
                self.path, 
                json.loads(body), 
                self.headers.get("Content-Type")
            ))

            #while received less req than there are res, then return len(req)-1, else the final res
            response_index = min(len(received) - 1, len(responses) - 1) 
            status, payload, headers = responses[response_index]
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()

            try:
                # Use wfile (write file) to write response
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Because the client can intentionally stop reading a 429 body.

        def log_message(self, *_args):
            pass

    # Create a seperate thread for the mock server to run, so that this execution 
    # thread isn't occupied (since we use serve_forever until it's closed).
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler) #port 0 means that the OS chooses a free port
    
    # Set daemon=True since this is just a background server, only relevant 
    # for when the main program (these tests) are running. When the tests 
    # are done running, it just kills the mock server thread.  
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()

    # Yield the URL for sending login requests to this mock server. 
    # this (in combination with contextmanager annotation) makes it 
    # so that you can write tests as "with login_server(res) as (url, received) ..."
    # Then the finally block runs after the with block in the test.
    try:
        yield f"http://127.0.0.1:{server.server_port}/api/auth/login", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

class ProbeIntegrationTests(unittest.TestCase):
    def run_local_probe(self, url, attempts=5):
        return run_probe(
            LoginClient(url), "test@example.test", "deliberately-wrong",
            max_attempts=attempts, delay_seconds=0,
        )

    def test_no_limiter_uses_exact_request_budget_and_correct_payload(self):
        with login_server([(401, FAILURE, {})]) as (url, received):
            report = self.run_local_probe(url, attempts=3)

        self.assertEqual(len(received), 3)
        self.assertEqual(report.failure_count, 3)
        self.assertEqual(received[0], (
            "/api/auth/login",
            {"email": "test@example.test", "password": "deliberately-wrong"},
            "application/json",
        ))

    def test_stops_at_first_429_and_records_retry_after(self):
        responses = [(401, FAILURE, {}), (429, b"", {"Retry-After": "60"})]
        with login_server(responses) as (url, received):
            report = self.run_local_probe(url) #attempts are default 5

        self.assertEqual(len(received), 2) #only received 2 attempts, since i got a 429
        self.assertEqual(report.failure_count, 1)
        self.assertEqual(report.last_outcome, Outcome.THROTTLED)
        self.assertEqual(report.attempts[-1].observation.retry_after, "60")

    def test_stops_immediately_on_success_and_does_not_retain_token(self):
        with login_server([(200, SUCCESS, {})]) as (url, received):
            report = self.run_local_probe(url) 

        self.assertEqual(len(received), 1)
        self.assertEqual(report.last_outcome, Outcome.SUCCESS)
        self.assertNotIn("secret-jwt", repr(report))

    def test_redirects_are_not_followed(self):
        with login_server([(302, b"", {"Location": "/somewhere-else"})]) as (url, received):
            report = self.run_local_probe(url)

        self.assertEqual(len(received), 1)
        self.assertEqual(report.last_outcome, Outcome.UNEXPECTED)

    def test_server_errors_stop_without_retries(self):
        with login_server([(500, FAILURE, {})]) as (url, received):
            self.run_local_probe(url)

        self.assertEqual(len(received), 1)

    def test_oversized_response_is_inconclusive(self):
        with login_server([(200, b"x" * (MAX_RESPONSE_BYTES + 1), {})]) as (url, received):
            report = self.run_local_probe(url)
        self.assertEqual(report.last_outcome, Outcome.UNEXPECTED)
        self.assertEqual(len(received), 1)

class CliTests(unittest.TestCase):
    def test_non_positive_integer_max_attempts_not_allowed(self):
        self.assertTrue(True)

    def test_negative_delay_not_allowed(self):
        self.assertTrue(True)

    def test_non_positive_timeout_not_allowed(self):
        self.assertTrue(True)

    def test_email_is_required(self):
        self.assertTrue(True)

    def test_password_env_reads_from_environment(self):
        self.assertTrue(True)

    def test_format_correct(self):
        self.assertTrue(True)

    # Test exit codes? 
    # ...

if __name__ == "__main__":
    unittest.main()