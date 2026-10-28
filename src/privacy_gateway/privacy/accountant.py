import json
from datetime import datetime, timezone
from pathlib import Path

TOLERANCE = 1e-9


class BudgetExceeded(RuntimeError):
    pass


class PrivacyAccountant:
    """Track the epsilon spent on releases from one audit log.

    Uses basic sequential composition: every release adds its epsilon, and a release
    that would pass the total is refused before any statistic is computed. With a
    ledger path the spends survive restarts, and the stored total wins over the one
    passed in, so asking for a bigger budget does not reset the period.
    """

    def __init__(self, total_epsilon: float, ledger_path: Path | None = None):
        if total_epsilon <= 0:
            raise ValueError("total_epsilon must be positive")
        self.ledger_path = ledger_path
        self.total_epsilon = float(total_epsilon)
        self.spends: list[dict] = []
        if ledger_path is not None and ledger_path.exists():
            stored = json.loads(ledger_path.read_text(encoding="utf-8"))
            self.total_epsilon = float(stored["total_epsilon"])
            self.spends = list(stored.get("spends", []))

    @property
    def spent(self) -> float:
        return sum(float(item["epsilon"]) for item in self.spends)

    @property
    def remaining(self) -> float:
        return max(0.0, self.total_epsilon - self.spent)

    def check(self, epsilon: float) -> None:
        if epsilon <= 0:
            raise ValueError("epsilon must be positive")
        if self.spent + epsilon > self.total_epsilon + TOLERANCE:
            raise BudgetExceeded(
                f"Release needs epsilon {epsilon:g}, but only {self.remaining:g} "
                f"of {self.total_epsilon:g} is left."
            )

    def spend(self, epsilon: float, label: str) -> None:
        self.check(epsilon)
        self.spends.append(
            {
                "label": label,
                "epsilon": float(epsilon),
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        )
        self._save()

    def reset(self, total_epsilon: float | None = None) -> None:
        """Start a new budget period. Earlier releases still exist, so only do this on a fresh log."""
        if total_epsilon is not None:
            if total_epsilon <= 0:
                raise ValueError("total_epsilon must be positive")
            self.total_epsilon = float(total_epsilon)
        self.spends = []
        self._save()

    def summary(self) -> dict:
        return {
            "total_epsilon": self.total_epsilon,
            "spent": round(self.spent, 6),
            "remaining": round(self.remaining, 6),
            "releases": len(self.spends),
            "composition": "sequential",
        }

    def _save(self) -> None:
        if self.ledger_path is None:
            return
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"total_epsilon": self.total_epsilon, "spends": self.spends}
        self.ledger_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
