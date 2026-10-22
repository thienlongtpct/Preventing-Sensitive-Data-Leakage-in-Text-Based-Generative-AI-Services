from pathlib import Path


def project_root() -> Path:
    """Locate the repository root from an installed or source checkout."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "config" / "policy.yaml").is_file():
            return parent
    raise FileNotFoundError("Could not locate the project root (pyproject.toml and config/policy.yaml).")
