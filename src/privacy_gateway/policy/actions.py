import hashlib
import hmac

from privacy_gateway.schemas import ACTION_RANK, Finding


def stronger_action(left: str, right: str) -> str:
    return left if ACTION_RANK[left] >= ACTION_RANK[right] else right


def apply_transforms(
    text: str,
    annotated: list[tuple[Finding, str]],
    token_key: str,
) -> str:
    """Replace spans marked redact or tokenize. Spans must not overlap."""
    replacements: list[tuple[int, int, str]] = []
    for finding, action in annotated:
        if action not in {"redact", "tokenize"}:
            continue
        raw = text[finding.start : finding.end]
        if action == "redact":
            replacement = f"[REDACTED:{finding.category}]"
        else:
            digest = hmac.new(token_key.encode(), raw.encode(), hashlib.sha256).hexdigest()[:8]
            replacement = f"[TOKEN:{finding.category}:{digest}]"
        replacements.append((finding.start, finding.end, replacement))

    updated = text
    for start, end, replacement in sorted(replacements, key=lambda item: item[0], reverse=True):
        updated = updated[:start] + replacement + updated[end:]
    return updated
