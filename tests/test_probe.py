from contextlib import contextmanager, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from unittest.mock import patch
from login_probe.client import (
    FAILURE_MESSAGE, 
    MAX_RESPONSE_BYTES, 
    LoginClient, 
    Observation,
    Outcome,
    classify_response,
)
from login_probe.rate_limit import Attempt, ProbeReport, run_probe
from login_probe.cli import DEFAULT_URL, build_parser, format as format_report, main

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
    """Exercise CLI decisions without sending requests to a real backend."""

    def setUp(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.enterContext(redirect_stdout(self.stdout))
        self.enterContext(redirect_stderr(self.stderr))
        self.client_type = self.enterContext(patch("login_probe.cli.LoginClient"))
        self.probe = self.enterContext(patch("login_probe.cli.run_probe"))
        self.prompt = self.enterContext(patch("login_probe.cli.getpass", return_value="wrong-password"))
        self.enterContext(patch(
            "login_probe.cli.shutil.get_terminal_size", return_value=os.terminal_size((80, 24))
        ))
        self.probe.return_value = self.make_report(Outcome.THROTTLED, 429)

    @staticmethod
    def make_report(outcome, status):
        return ProbeReport(
            (Attempt(1, Observation(outcome, status, 12.5, "60", "test observation")),),
            max_attempts=20,
            delay_seconds=0.5,
        )

    def test_parser_defaults(self):
        args = build_parser().parse_args(["--email", "test@example.test"])
        self.assertEqual(args.url, DEFAULT_URL)
        self.assertEqual(args.max_attempts, 20)
        self.assertEqual(args.delay, 0.5)
        self.assertEqual(args.timeout, 10.0)
        self.assertIsNone(args.password_env)

    def test_invalid_numeric_arguments_are_rejected(self):
        cases = {
            "--max-attempts": ("0", "-1", "1.5", "nan", "abc"),
            "--delay": ("-1", "nan", "inf", "-inf", "abc"),
            "--timeout": ("0", "-1", "nan", "inf", "abc"),
        }
        for option, values in cases.items():
            for value in values:
                with self.subTest(option=option, value=value):
                    with self.assertRaises(SystemExit) as error:
                        main(["--email", "test@example.test", f"{option}={value}"])
                    self.assertEqual(error.exception.code, 2)
        self.client_type.assert_not_called()
        self.prompt.assert_not_called()
        self.probe.assert_not_called()

    def test_zero_delay_and_positive_fractional_timeout_are_allowed(self):
        args = build_parser().parse_args([
            "--email", "test", "--delay", "0", "--timeout", "0.25", "--max-attempts", "1"
        ])
        self.assertEqual((args.delay, args.timeout, args.max_attempts), (0, 0.25, 1))

    def test_missing_or_blank_email_is_rejected(self):
        for arguments in ([], ["--email", ""], ["--email", "   "]):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit) as error:
                main(arguments)
            self.assertEqual(error.exception.code, 2)
        self.client_type.assert_not_called()
        self.prompt.assert_not_called()
        self.probe.assert_not_called()

    def test_invalid_url_is_reported_before_password_prompt(self):
        self.client_type.side_effect = ValueError("URL must be an absolute http:// or https:// address")
        with self.assertRaises(SystemExit) as error:
            main(["--email", "test", "--url", "/relative"])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("URL must be", self.stderr.getvalue())
        self.prompt.assert_not_called()
        self.probe.assert_not_called()

    def test_interactive_password_and_defaults_are_forwarded(self):
        self.assertEqual(main(["--email", "test@example.test"]), 0)
        self.client_type.assert_called_once_with(DEFAULT_URL, timeout=10.0)
        self.prompt.assert_called_once()
        self.probe.assert_called_once_with(
            self.client_type.return_value, "test@example.test", "wrong-password",
            max_attempts=20, delay_seconds=0.5,
        )
        self.assertIn("Starting probe", self.stdout.getvalue())
        self.assertIn("PROBE REPORT", self.stdout.getvalue())
        self.assertNotIn("wrong-password", self.stdout.getvalue())

    def test_password_env_and_custom_options_are_forwarded(self):
        with patch.dict(os.environ, {"LOGIN_PROBE_TEST_PASSWORD": "wrong-from-environment"}):
            result = main([
                "--email", "test@example.test", "--url", "http://localhost:9000/login",
                "--max-attempts", "3", "--delay", "0.1", "--timeout", "2",
                "--password-env", "LOGIN_PROBE_TEST_PASSWORD",
            ])
        self.assertEqual(result, 0)
        self.prompt.assert_not_called()
        self.client_type.assert_called_once_with("http://localhost:9000/login", timeout=2.0)
        self.probe.assert_called_once_with(
            self.client_type.return_value, "test@example.test", "wrong-from-environment",
            max_attempts=3, delay_seconds=0.1,
        )
        self.assertNotIn("wrong-from-environment", self.stdout.getvalue())

    def test_missing_or_empty_environment_password_is_rejected(self):
        for variables in ({}, {"LOGIN_PROBE_TEST_PASSWORD": ""}):
            with self.subTest(variables=variables), patch.dict(os.environ, variables, clear=True):
                with self.assertRaises(SystemExit) as error:
                    main(["--email", "test", "--password-env", "LOGIN_PROBE_TEST_PASSWORD"])
                self.assertEqual(error.exception.code, 2)
        self.prompt.assert_not_called()
        self.probe.assert_not_called()

    def test_empty_prompted_password_is_rejected(self):
        self.prompt.return_value = ""
        with self.assertRaises(SystemExit) as error:
            main(["--email", "test"])
        self.assertEqual(error.exception.code, 2)
        self.probe.assert_not_called()

    def test_main_exit_codes_for_all_outcomes(self):
        for outcome, status, expected in (
            (Outcome.THROTTLED, 429, 0),
            (Outcome.AUTH_FAILURE, 401, 1),
            (Outcome.SUCCESS, 200, 2),
            (Outcome.UNEXPECTED, 500, 2),
            (Outcome.NETWORK_ERROR, None, 2),
        ):
            with self.subTest(outcome=outcome):
                self.probe.return_value = self.make_report(outcome, status)
                self.assertEqual(main(["--email", "test"]), expected)

    def test_password_prompt_interruptions_return_130_without_probing(self):
        for exception in (KeyboardInterrupt, EOFError):
            with self.subTest(exception=exception):
                self.prompt.side_effect = exception()
                self.assertEqual(main(["--email", "test"]), 130)
        self.probe.assert_not_called()
        self.assertIn("Probe interrupted", self.stderr.getvalue())

    def test_probe_interruption_returns_130_without_report(self):
        self.probe.side_effect = KeyboardInterrupt()
        self.assertEqual(main(["--email", "test"]), 130)
        self.assertIn("Probe interrupted", self.stderr.getvalue())
        self.assertNotIn("PROBE REPORT", self.stdout.getvalue())

    def test_help_exits_without_prompting_or_probing(self):
        with self.assertRaises(SystemExit) as error:
            main(["--help"])
        self.assertEqual(error.exception.code, 0)
        self.assertIn("--password-env", self.stdout.getvalue())
        self.client_type.assert_not_called()
        self.prompt.assert_not_called()
        self.probe.assert_not_called()

    def test_format_includes_each_observation_and_run_settings(self):
        report = ProbeReport((
            Attempt(1, Observation(Outcome.AUTH_FAILURE, 401, 12.5)),
            Attempt(2, Observation(Outcome.THROTTLED, 429, 7.25, "60", "HTTP 429 observed")),
        ), max_attempts=5, delay_seconds=0.25)
        output = format_report(report)
        for expected in (
            "PROBE REPORT", "Requests made: 2", "Delay between each request (s): 0.25",
            "Login Attempt Number 1", "Login Attempt Number 2",
            "Response status code: 401", "Response status code: 429",
            "12.5", "7.25", "Retry-After header from response: '60'", "HTTP 429 observed",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, output)
        self.assertNotIn("accessToken", output)

    def test_format_handles_missing_status_and_retry_after(self):
        report = ProbeReport((
            Attempt(1, Observation(Outcome.NETWORK_ERROR, None, 10.0, detail="Request failed (TimeoutError).")),
        ), max_attempts=5, delay_seconds=0)
        output = format_report(report)
        self.assertIn("Response status code: None", output)
        self.assertIn("Retry-After header from response: None", output)
        self.assertIn("Request failed (TimeoutError).", output)

    def test_module_entrypoint_propagates_no_throttling_exit_code(self):
        """Known bug: __main__.py discards main()'s return value. Remove the
        decorator when the entrypoint is fixed; this test should then pass.
        The subprocess uses a real local fixture, not the parent-process mocks.
        """
        environment = os.environ.copy()
        environment["LOGIN_PROBE_TEST_PASSWORD"] = "deliberately-wrong"
        with login_server([(401, FAILURE, {})]) as (url, received):
            result = subprocess.run([
                sys.executable, "-m", "login_probe", "--url", url,
                "--email", "test@example.test", "--password-env", "LOGIN_PROBE_TEST_PASSWORD",
                "--max-attempts", "1", "--delay", "0",
            ], cwd=Path(__file__).resolve().parents[1], env=environment,
                capture_output=True, text=True, timeout=10)
        self.assertEqual(len(received), 1)
        self.assertIn("PROBE REPORT", result.stdout)
        self.assertEqual(result.returncode, 1, result.stderr)

if __name__ == "__main__":
    unittest.main()
