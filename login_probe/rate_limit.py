"""Probe experiment: repeat failed logins until a stop condition is observed."""

from dataclasses import dataclass
import math
from time import sleep

from .client import LoginClient, Observation, Outcome

@dataclass(frozen=True)
class Attempt:
    """Class for storing data for each request attempt. 
    The attempt number, and the observation made from this attempt are stored here."""
    number: int
    observation: Observation

@dataclass(frozen=True)
class ProbeReport:
    """Class for storing the report data after probing the login endpoint several times. 
    It stores all the seperate attempts, the max amount of attemps, and the amount of delay 
    between each attempt in seconds."""
    attempts: tuple[Attempt, ...]
    max_attempts: int
    delay_seconds: float

    @property
    def last_outcome(self) -> Outcome:
        return self.attempts[-1].observation.outcome

    @property
    def failure_count(self) -> int:
        return sum(
            attempt.observation.outcome == Outcome.AUTH_FAILURE
            for attempt in self.attempts
        )
    
def run_probe(
    client: LoginClient,
    email: str,
    password: str,
    *,
    max_attempts: int = 20,
    delay_seconds: float = 0.5,
) -> ProbeReport:
    """A function for running a probe. It sends [max_attempts] requests throught the [client] 
    to the server, with a delay of [delay_seconds], using the specified [email] and [password].
    We stop if the login response was not just a failed login, but something else that would 
    indicate rate limiting, or a successful login."""
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")
    if not math.isfinite(delay_seconds) or delay_seconds < 0:
        raise ValueError("delay_seconds must be finite and at least zero")
    if not email.strip() or not password:
        raise ValueError("email and test password must not be empty")

    attempts = []
    for number in range(1, max_attempts + 1):
        observation = client.attempt(email, password)
        attempts.append(Attempt(number, observation))
        # Continue only when we understand the response as a failed login.
        # This also prevents accidentally repeating successful logins.
        if observation.outcome != Outcome.AUTH_FAILURE:
            break
        if number < max_attempts:
            sleep(delay_seconds)

    return ProbeReport(tuple(attempts), max_attempts, delay_seconds)
