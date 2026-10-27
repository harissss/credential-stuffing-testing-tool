"""Command-line interface and a report containing only the measured evidence."""

import argparse
from getpass import getpass
import math
import os
import sys
import shutil

from .client import LoginClient, Outcome
from .rate_limit import ProbeReport, run_probe


DEFAULT_URL = "http://localhost:8080/api/auth/login"

# Functions for defining "types" of numbers, used for basically setting constraints when parsing numbers 
def positive_integer(value: str) -> int:
    try:
        result = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if result < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return result

def finite_number(value: str) -> float:
    try:
        result = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a finite number") from None
    if not math.isfinite(result):
        raise argparse.ArgumentTypeError("must be a finite number")
    return result

def nonnegative_number(value: str) -> float:
    result = finite_number(value)
    if result < 0:
        raise argparse.ArgumentTypeError("must be at least zero")
    return result

def positive_number(value: str) -> float:
    result = finite_number(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return result

# Use argparse to parse command line input
def build_parser() -> argparse.ArgumentParser:
    """Builds and returns the parser for running the tool."""
    parser = argparse.ArgumentParser(
        description="Tool for observing if there is rate limiting implemented at a login endpoint within some amount of attempts. " \
        "Intended to be used with a dedicated test account and an incorrect password. " \
        "Exit codes: 0 (rate limiting observed), 1 (attempts exhausted, rate limiting not observed), 2 (unexpected end to test; accidental successful login, unexpected response, or network error)."
    )
    parser.add_argument("--url", default=DEFAULT_URL, help=f"url of login endpoint (default: {DEFAULT_URL})")
    parser.add_argument("--email", required=True, help="email of a dedicated, existing test account")
    parser.add_argument("--max-attempts", type=positive_integer, default=20, help="request budget (default: 20)")
    parser.add_argument(
        "--delay", type=nonnegative_number, default=0.5,
        help="seconds to wait after a failed response before the next request (default: 0.5)",
    )
    parser.add_argument(
        "--timeout", type=positive_number, default=10.0,
        help="socket inactivity timeout in seconds, not a total run deadline (default: 10)",
    )
    parser.add_argument(
        "--password-env", metavar="VARIABLE", #read from environment (incase accidentally correct; passing as parameter is unsafe)
        help="read the incorrect test password from this environment variable; otherwise prompt privately",
    )
    return parser

def format(report : ProbeReport) -> str:
    """Function for building a formatted string of a ProbeReport. 
    Used to print the result of a probe into the terminal."""
    lines = []

    # Info about probe
    width = shutil.get_terminal_size().columns
    info_line="PROBE REPORT".center(width, "-")
    attemps_line=f"Requests made: {len(report.attempts)}"
    delay_line=f"Delay between each request (s): {report.delay_seconds}"
    lines.append(info_line)
    lines.append(attemps_line)
    lines.append(delay_line)

    # Build summaries of the attempt observations
    for attempt in report.attempts: 
        attempt_summary = []
        attempt_summary.append("\t" + f"Login Attempt Number {attempt.number}:")
        attempt_summary.append("\t\t" + "Outcome: " + str(attempt.observation.outcome))
        attempt_summary.append("\t\t" + "Response status code: " + str(attempt.observation.status))
        attempt_summary.append("\t\t" + "Retry-After header from response: " + str(attempt.observation.retry_after))
        attempt_summary.append("\t\t" + "Time to get response (ms): " + str(attempt.observation.duration_ms))
        attempt_summary.append("\t\t" + "Details about this attempt: " + attempt.observation.detail)
        lines.append(os.linesep.join(attempt_summary)) 

    lines.append("".center(width, "-"))

    return os.linesep.join(lines)

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.email.strip():
        parser.error("--email can't be blank")
    try:
        client = LoginClient(args.url, timeout=args.timeout)
    except ValueError as error:
        parser.error(str(error)) # print error to terminal, exit

    try:
        if args.password_env is not None:
            password = os.environ.get(args.password_env)
            if not password:
                parser.error("--password-env must name an existing, non-empty environment variable")
        else: # read password securely with getpass
            password = getpass("Deliberately incorrect test password (hidden): ")
            if not password:
                parser.error("test password must not be empty")

        print(f"Starting probe: at most {args.max_attempts} sequential requests. CTRL+C to stop.", flush=True)
        report = run_probe(
            client, args.email, password,
            max_attempts=args.max_attempts, delay_seconds=args.delay,
        )
    except (KeyboardInterrupt, EOFError):
        print("\nProbe interrupted; the final request may have reached the server. No conclusion produced.", file=sys.stderr)
        return 130

    print(format(report))
    
    if report.last_outcome is Outcome.THROTTLED: # Rate limiting observed within request budget
        return 0
    elif report.last_outcome is Outcome.AUTH_FAILURE: # Rate limiting not observed within request budget
        return 1 
    else: # Unexpected end to probe
        return 2
