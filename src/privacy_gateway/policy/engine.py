from privacy_gateway.schemas import ACTION_RANK, CATEGORY_PRIORITY, Decision, Finding


class PolicyEngine:
    """Map role and severity to allow, warn, redact, tokenize, or block.

    Each finding keeps its own action so a warning does not redact a clean span.
    The reported action is the most restrictive action among the findings.
    """

    def __init__(self, roles: dict[str, dict[str, str]], fail_closed: bool = True):
        self.roles = {name.lower(): actions for name, actions in roles.items()}
        self.fail_closed = fail_closed

    def decide(self, role: str, findings: list[Finding]) -> Decision:
        normalized = role.lower()
        if normalized not in self.roles:
            return Decision(action="block", annotated=[], unknown_role=True)
        if not findings:
            return Decision(action="allow", annotated=[])

        role_actions = self.roles[normalized]
        annotated = [(finding, role_actions[finding.severity]) for finding in findings]
        action = max((name for _, name in annotated), key=lambda name: ACTION_RANK[name])
        return Decision(action=action, annotated=annotated)


def prefer_category(left: str, right: str) -> str:
    return left if CATEGORY_PRIORITY.index(left) <= CATEGORY_PRIORITY.index(right) else right
