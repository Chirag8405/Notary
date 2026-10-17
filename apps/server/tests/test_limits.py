"""The rate limiter on its own (#242): a sliding window per client, a fake clock, a bound."""

import pytest

from notary_server.limits import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def limiter(clock: FakeClock, *, limit: int = 3, window: float = 60.0, max_keys: int = 4096):
    return RateLimiter(limit=limit, window_seconds=window, clock=clock, max_keys=max_keys)


@pytest.mark.invariant("I6")
def test_a_client_gets_its_budget_per_window() -> None:
    clock = FakeClock()
    rate = limiter(clock)
    assert [rate.allow("a") for _ in range(3)] == [True, True, True]
    assert rate.allow("a") is False
    clock.advance(59)
    assert rate.allow("a") is False  # the first hits are still inside the window
    clock.advance(1)
    # Exactly one window later all three have left: the whole budget is back, and no more.
    assert [rate.allow("a") for _ in range(3)] == [True, True, True]
    assert rate.allow("a") is False


@pytest.mark.invariant("I6")
def test_the_window_slides_it_does_not_reset() -> None:
    clock = FakeClock()
    rate = limiter(clock)
    assert rate.allow("a")  # t = 0
    clock.advance(30)
    assert rate.allow("a")  # t = 30
    assert rate.allow("a")  # t = 30
    assert rate.allow("a") is False
    clock.advance(30)  # t = 60: only the hit of t = 0 has left
    assert rate.allow("a") is True
    assert rate.allow("a") is False


@pytest.mark.invariant("I6")
def test_a_refused_hit_is_not_recorded() -> None:
    clock = FakeClock()
    rate = limiter(clock, limit=1)
    assert rate.allow("a")
    for _ in range(50):
        assert rate.allow("a") is False  # hammering does not push the window forward
    clock.advance(60)
    assert rate.allow("a") is True


@pytest.mark.invariant("I6")
def test_retry_after_is_whole_seconds_and_at_least_one() -> None:
    clock = FakeClock()
    rate = limiter(clock, limit=2)
    assert rate.retry_after("nobody") == 1
    assert rate.allow("a")
    clock.advance(10)
    assert rate.allow("a")
    assert rate.retry_after("a") == 50  # the first hit leaves in 50 seconds
    clock.advance(49.2)
    assert rate.retry_after("a") == 1  # 0.8 s left, rounded up
    clock.advance(0.8)
    assert rate.retry_after("a") == 1  # allowed again; still never below 1


@pytest.mark.invariant("I6")
def test_clients_do_not_share_a_budget() -> None:
    clock = FakeClock()
    rate = limiter(clock, limit=1)
    assert rate.allow("a")
    assert rate.allow("a") is False
    assert rate.allow("b") is True
    assert rate.allow("b") is False


@pytest.mark.invariant("I6")
def test_the_table_of_clients_is_bounded_and_drops_the_least_recently_used() -> None:
    clock = FakeClock()
    rate = limiter(clock, limit=1, max_keys=3)
    for index in range(10):
        assert rate.allow(f"client-{index}")
        assert rate.keys() <= 3
    assert rate.keys() == 3
    # The most recent client is still tracked (its budget is spent) ...
    assert rate.allow("client-9") is False
    # ... and the first one was forgotten long ago, so it starts from a fresh budget.
    assert rate.allow("client-0") is True
    assert rate.allow("client-0") is False
    assert rate.keys() == 3


@pytest.mark.parametrize(
    ("limit", "window", "max_keys"), [(0, 60.0, 4), (1, 0.0, 4), (1, -1.0, 4), (1, 60.0, 0)]
)
def test_a_limiter_needs_positive_numbers(limit: int, window: float, max_keys: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        RateLimiter(limit=limit, window_seconds=window, clock=FakeClock(), max_keys=max_keys)
