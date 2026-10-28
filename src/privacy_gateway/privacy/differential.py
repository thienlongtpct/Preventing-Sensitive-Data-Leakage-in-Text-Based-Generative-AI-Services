import math
import random


def noisy_counts(
    counts: dict[str, float],
    epsilon: float,
    seed: int | None = None,
    sensitivity: float = 1.0,
) -> dict[str, float]:
    """Add Laplace(sensitivity / epsilon) noise to each value of a histogram.

    `sensitivity` is the L1 change one audit event can cause across the whole
    histogram, so the release as a whole is epsilon-DP. Negative results are
    clamped to zero, which is post-processing and costs no budget. Diffprivlib is
    used when installed. With `seed`, results repeat, which is for tests only.
    """
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    if sensitivity <= 0:
        raise ValueError("sensitivity must be positive")
    if not counts:
        return {}

    try:
        from diffprivlib.mechanisms import Laplace
    except ImportError:
        return _fallback_counts(counts, epsilon, seed, sensitivity)

    mechanism = Laplace(epsilon=epsilon, sensitivity=sensitivity, random_state=seed)
    return {key: max(0.0, float(mechanism.randomise(float(value)))) for key, value in counts.items()}


def laplace_scale(sensitivity: float, epsilon: float) -> float:
    return sensitivity / epsilon


def error_bound(scale: float, confidence: float = 0.95) -> float:
    """|noise| stays below this value with the given probability, from P(|X| > t) = exp(-t / b)."""
    return scale * math.log(1.0 / (1.0 - confidence))


def _fallback_counts(
    counts: dict[str, float], epsilon: float, seed: int | None, sensitivity: float
) -> dict[str, float]:
    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    scale = laplace_scale(sensitivity, epsilon)
    return {key: max(0.0, value + _laplace(rng, scale)) for key, value in counts.items()}


def _laplace(rng: random.Random, scale: float) -> float:
    """Inverse-CDF sample from Laplace(0, scale)."""
    uniform = rng.random() - 0.5
    if uniform == 0.0:
        return 0.0
    return -scale * math.copysign(1.0, uniform) * math.log(1.0 - 2.0 * abs(uniform))


def privacy_backend() -> str:
    try:
        import diffprivlib  # noqa: F401
    except ImportError:
        return "laplace-fallback"
    return "diffprivlib"
