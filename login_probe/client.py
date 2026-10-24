"""Send one login attempt and describe observations, never credentials or tokens."""

from dataclasses import dataclass
from enum import Enum
import http.client
import json
import math
from time import perf_counter
from urllib.parse import urlsplit
from http import HTTPStatus

FAILURE_MESSAGE = "Email or password is incorrect. Please try again."
MAX_RESPONSE_BYTES = 1024*64 

class Outcome(str, Enum):
    """Enum class for specifying classifications of the outcomes of making a request 
    to the server (i.e., the type of response that the client received)."""
    AUTH_FAILURE = "authentication_failure"
    THROTTLED = "throttled"
    SUCCESS = "successful_login"
    UNEXPECTED = "unexpected_response"
    NETWORK_ERROR = "network_error"

@dataclass(frozen=True)
class Observation:
    """Class for storing relevant data of an observation that was made after getting the 
    response of some login request. It stores the request Outcome, the response status code, 
    the duration of the request handling (and sending/receiving request and response) in ms,
    the Retry-After header from the response, and details about the specific observation made.
    """
    outcome: Outcome
    status: int | None
    duration_ms: float
    retry_after: str | None = None
    detail: str = ""

def classify_response(status: int, body: bytes) -> Outcome:
    """Function for classifying the HTTP response of the server. This function 
    uses the Spring Boot response contract, not status codes alone. Read about 
    the Spring Boot response contract in the README.md file."""
    if status == HTTPStatus.TOO_MANY_REQUESTS: 
        return Outcome.THROTTLED

    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        return Outcome.UNEXPECTED

    if not isinstance(payload, dict):
        return Outcome.UNEXPECTED

    token = payload.get("accessToken")
    if 200 <= status < 300 and isinstance(token, str) and token.strip():
        return Outcome.SUCCESS

    # Unauthorized attemps
    if (
        status == HTTPStatus.UNAUTHORIZED #unauthorized
        and "accessToken" in payload
        and token is None
        and payload.get("message") == FAILURE_MESSAGE
    ):
        return Outcome.AUTH_FAILURE
    
    return Outcome.UNEXPECTED

class LoginClient:
    """Class for establishing a connection with a server at [url], 
    so that login requests can be sent."""
    def __init__(self, url: str, timeout: float = 5.0):
        # Check input
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite number greater than zero")
        if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in url):
            raise ValueError("URL must not contain whitespace or control characters")
        try:
            target = urlsplit(url)
            port = target.port
            hostname = target.hostname
        except ValueError:
            raise ValueError("URL has an invalid host or port") from None
        if target.scheme not in ("http", "https") or not hostname:
            raise ValueError("URL must be an absolute http:// or https:// address")
        if target.username is not None or target.password is not None:
            raise ValueError("URL must not contain embedded credentials")
        if target.fragment:
            raise ValueError("URL must not contain a fragment")
        # http.client expects an ASCII request target. Need to URL encode (aka percent-encode)
        # paths containing non-ASCII characters before passing them to this tool.
        try:
            url.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("URL must be ASCII. Percent-encode non-ASCII characters") from None

        # Set class properties
        self._connection_type = (
            http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
        )
        self._hostname = hostname
        self._port = port
        self._path = target.path or "/"
        if target.query:
            self._path += "?" + target.query
        self._timeout = timeout

    def attempt(self, email: str, password: str) -> Observation:
        """Method for making exactly one login POST request with [email] and [password]. 
        It does not retry or follow redirects."""
        body = json.dumps({"email": email, "password": password}).encode("utf-8")
        connection = self._connection_type(self._hostname, self._port, timeout=self._timeout)
        started = perf_counter()
        status = None
        retry_after = None
        try:
            connection.request(
                "POST",
                self._path,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "login-probe/0.1.0",
                },
            )
            response = connection.getresponse()
            duration = perf_counter() - started
            status = response.status
            # Only preserve the one header needed for iteration 1. Raw bodies,
            # cookies, JWTs, and arbitrary server messages never enter a report.
            retry_after = response.getheader("Retry-After")
            if status == HTTPStatus.TOO_MANY_REQUESTS:
                # The status is sufficient; an HTML error page or broken body
                # must not hide an observed 429.
                outcome = Outcome.THROTTLED
                detail = "HTTP 429 (too many requests) observed; limiter scope and recovery are unmeasured."
            else:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    outcome = Outcome.UNEXPECTED
                    detail = "Response exceeded the 64 KiB read limit."
                else:
                    outcome = classify_response(status, payload)
                    detail = (
                        "Response did not match the known login contract."
                        if outcome == Outcome.UNEXPECTED else ""
                    )
        except (OSError, http.client.HTTPException) as error:
            duration = (perf_counter() - started)
            outcome = Outcome.NETWORK_ERROR
            # Exception text can include server-controlled data. Keep only its
            # type, and do not retry: the server may have counted this request.
            detail = f"Request failed ({type(error).__name__})."
        finally:
            connection.close()

        return Observation(
            outcome=outcome,
            status=status,
            duration_ms=duration * 1000,
            retry_after=retry_after,
            detail=detail,
        )
