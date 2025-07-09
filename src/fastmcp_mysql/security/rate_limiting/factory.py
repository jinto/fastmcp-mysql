"""Rate limiter factory."""

from ..config import RateLimitAlgorithm
from ..interfaces import RateLimiter
from .fixed_window import FixedWindowLimiter
from .sliding_window import SlidingWindowLimiter
from .token_bucket import TokenBucketLimiter


def create_rate_limiter(
    algorithm: RateLimitAlgorithm,
    requests_per_minute: int,
    burst_size: int | None = None,
    per_user_limits: dict[str, int] | None = None,
) -> RateLimiter:
    """
    Create a rate limiter based on algorithm.

    Args:
        algorithm: Rate limiting algorithm
        requests_per_minute: Default requests per minute
        burst_size: Burst size for token bucket
        per_user_limits: Per-user rate limits

    Returns:
        Rate limiter instance
    """
    if algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
        if burst_size is None:
            burst_size = max(5, requests_per_minute // 12)  # Default: 5 or rpm/12
        return TokenBucketLimiter(
            requests_per_minute=requests_per_minute,
            burst_size=burst_size,
            per_user_limits=per_user_limits,
        )

    elif algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
        return SlidingWindowLimiter(requests_per_minute=requests_per_minute)

    elif algorithm == RateLimitAlgorithm.FIXED_WINDOW:
        return FixedWindowLimiter(requests_per_minute=requests_per_minute)

    else:
        raise ValueError(f"Unknown rate limiting algorithm: {algorithm}")
