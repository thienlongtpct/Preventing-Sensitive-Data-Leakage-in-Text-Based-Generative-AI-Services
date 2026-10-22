import math
import random


def noisy_counts(counts: dict[str, int], epsilon: float, seed: int | None = None) -> dict[str, float]:
    """Add Laplace noise to aggregate counts.

    Each statistic uses `epsilon` on its own. This init build does not compose
    those spends into one privacy budget. Diffprivlib is used when installed.
    """
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    if not counts:
        return {}

    try:
        from diffprivlib.mechanisms import Laplace
    except ImportError:
        return _fallback_counts(counts, epsilon, seed)

    mechanism = Laplace(epsilon=epsilon, sensitivity=1.0)
    return {key: max(0.0, float(mechanism.randomise(value))) for key, value in counts.items()}


def _fallback_counts(counts: dict[str, int], epsilon: float, seed: int | None) -> dict[str, float]:
    rng = random.Random(seed)
    scale = 1.0 / epsilon
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
