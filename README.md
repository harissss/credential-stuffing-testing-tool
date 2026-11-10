# Login Probe

A small Python command-line tool for checking whether an API login endpoint
returns HTTP 429 after repeated failed login attempts. It records each attempt's
outcome, HTTP status, timing, and optional `Retry-After` header.

The current version tests one dedicated account with a deliberately incorrect
password. It is an early step toward testing credential-stuffing defenses, rather
than a complete credential-stuffing simulator or a general security scanner.
Use it against systems you own or have permission to test.

## Requirements

- Python 3.11 or newer.
- An accessible login endpoint matching the response contract below.
- An existing, dedicated test account and an intentionally incorrect password.

The tool and tests use only Python's standard library. No third-party packages
are needed to run them from the repository root.

## Quick start

Clone the repository and open a terminal in its root directory. With the target
backend running, start a small probe:

```powershell
python -m login_probe --email test@example.test --max-attempts 10
```

Replace the example email with the email of an existing test account. The tool
prompts for an incorrect password using `getpass`. An unknown account may trigger
different controls from a real account, so use a dedicated registered user.

The default endpoint is `http://localhost:8080/api/auth/login`. To use another
endpoint and change the request pace:

```powershell
python -m login_probe --url http://localhost:9000/login --email test@example.test --max-attempts 20 --delay 0.25 --timeout 5
```

### Noninteractive use

Provide the **name** of an environment variable with `--password-env` to skip the
password prompt. For example, in PowerShell, using a disposable incorrect value:

```powershell
$env:LOGIN_PROBE_PASSWORD = 'deliberately-wrong-test-value'
python -m login_probe --email test@example.test --password-env LOGIN_PROBE_PASSWORD
Remove-Item Env:LOGIN_PROBE_PASSWORD
```

The password itself is not a CLI argument. Environment variables are not secret
storage, and an assignment typed into a shell may remain in its history. For
automation, supply the variable through the execution environment. `getpass` may
fall back to echoed input if hidden terminal input is unavailable; use the
environment option in noninteractive environments.

## Command-line options

```powershell
python -m login_probe --help
```

| Option           | Default                                | Purpose                                                            |
| ---------------- | -------------------------------------- | ------------------------------------------------------------------ |
| `--url`          | `http://localhost:8080/api/auth/login` | Absolute HTTP or HTTPS login URL                                   |
| `--email`        | Required                               | Email of the dedicated test account                                |
| `--max-attempts` | `20`                                   | Positive integer request budget                                    |
| `--delay`        | `0.5`                                  | Nonnegative seconds between a failed response and the next request |
| `--timeout`      | `10`                                   | Positive socket inactivity timeout, in seconds                     |
| `--password-env` | Not set                                | Environment variable containing the incorrect test password        |

The delay is not a fixed request rate: response processing takes additional time.
The timeout is not a total runtime deadline. Press Ctrl+C to interrupt a run;
the current version does not print a partial report after interruption.

## Supported API contract

The request is a JSON POST with these fixed field names:

```json
{
  "email": "test@example.test",
  "password": "deliberately-wrong-test-value"
}
```

The classifier currently targets a specific response format, originally used by
a Spring Boot backend. It does not detect arbitrary authentication API schemas.

### Recognized authentication failure

HTTP **401**, a present `accessToken` field containing `null`, and this exact
message are required:

```json
{
  "accessToken": null,
  "tokenType": null,
  "expiration": null,
  "message": "Email or password is incorrect. Please try again."
}
```

`tokenType` and `expiration` are illustrative; the classifier does not check them.
HTTP 200 with the same failure body is currently an unexpected response.

### Recognized success

Any HTTP 2xx response with a nonempty string `accessToken` is classified as a
successful login. Other fields are not validated. The probe stops immediately
if this occurs, since its intended input is an incorrect password.

### Throttling and other responses

| Observation                                        | Classification  | Action                                |
| -------------------------------------------------- | --------------- | ------------------------------------- |
| Recognized HTTP 401 failure                        | `AUTH_FAILURE`  | Continue within the attempt budget    |
| HTTP 429, regardless of body                       | `THROTTLED`     | Stop; record `Retry-After` if present |
| HTTP 2xx with a nonempty token                     | `SUCCESS`       | Stop                                  |
| Unrecognized response, redirect, or oversized body | `UNEXPECTED`    | Stop                                  |
| Connection, socket timeout, or HTTP protocol error | `NETWORK_ERROR` | Stop without retrying                 |

Requests are sequential. There are no automatic retries, redirect following,
cookie persistence, concurrent requests, or credential-list imports. Each attempt
opens its own connection. HTTPS uses default certificate verification. Response
bodies are read up to a 64 KiB limit plus one byte to detect oversize; a 429 is
classified without reading its body.

## Output and interpretation

The terminal report includes the number of requests attempted, the configured
delay, and each attempt's outcome, HTTP status, `Retry-After`, timing, and detail.
No report file is saved. Credentials and access tokens are not stored in the
report; response bodies are used temporarily for classification.

HTTP 429 is evidence that the server rejected a request as too frequent. The
first 429 observed in a run is not necessarily the backend's configured
threshold: earlier traffic, shared source addresses, and time-window boundaries
can affect it. If the budget is exhausted with recognized failures, the finding
is **no explicit HTTP 429 throttling observed within this budget at this pace**.
It does not establish that no protection exists.

### Exit codes

The CLI's `main()` function defines these results:

| Code  | Meaning                                                                                       |
| ----- | --------------------------------------------------------------------------------------------- |
| `0`   | HTTP 429 observed within the attempt budget                                                   |
| `1`   | Budget exhausted with recognized failures; no HTTP 429 observed                               |
| `2`   | Invalid arguments, an unexpected response, a network error, or an accidental successful login |
| `130` | Password input or probing interrupted by Ctrl+C or end-of-input                               |

## Scope and limitations

- Detection currently relies on HTTP 429. Delays, CAPTCHA requirements, or
  account lockout expressed through other responses are not identified.
- Lockout duration, recovery, limiter scope, and CAPTCHA enforcement are not tested.
- The tool does not establish whether throttling originates in the application,
  a reverse proxy, or another component.
- Timings for received responses measure time through receipt of the response
  headers, excluding the body read. Error timings include time until failure.
  These values alone cannot establish deliberate server-side delays.
- `Retry-After` is displayed verbatim and is neither interpreted nor verified.
- A connection error does not establish whether the server received or counted
  the request, even though the report counts it as an attempted request.
- A 429 observation is one narrow security check, not proof that an endpoint is
  secure or adequately protected against credential stuffing.

Use isolated test accounts and a controlled development environment when
comparing changes to a limiter. Allow existing counters to expire or reset them
through the backend's development setup before repeatable experiments.

## Development and tests

```powershell
python -m unittest discover -s tests -v
```

Run this from the repository root so Python can import `login_probe`. Directly
running `python tests/test_probe.py` may fail to find that package.

The tests cover response classification, real HTTP exchanges with a temporary
loopback server, request budgets, stop conditions, CLI input validation, password
sources, report formatting, interruptions, and CLI return codes. One subprocess
test exposes the known entrypoint exit-code issue and is marked
`unittest.expectedFailure`. Remove that marker when fixing the entrypoint.
The tests do not require the target backend or real credentials.

```text
login_probe/
    __main__.py      Module entrypoint
    cli.py           Argument parsing, password input, terminal reporting
    client.py        HTTP requests and response classification
    rate_limit.py    Attempt loop, stop conditions, and report data
tests/
    test_probe.py    Classifier, HTTP integration, and CLI tests
```

Future extensions may include lockout/recovery measurements, account-versus-IP
scope tests, a small synthetic multi-account credential set, CAPTCHA enforcement
checks, and structured reports for regression testing.
