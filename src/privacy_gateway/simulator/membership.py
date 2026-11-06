from dataclasses import dataclass


SYNTHETIC_MEMORY = {
    "employee_demo": "Synthetic employee record: EMP-4421",
    "project_demo": "Synthetic project record: ORCHID-VAULT",
}


@dataclass
class MembershipResult:
    member_record: str
    nonmember_record: str
    member_score: float
    nonmember_score: float
    inferred_member: bool
    protection_enabled: bool


class MembershipSimulator:
    """
    Synthetic membership-inference simulator.

    No real users, datasets, or external systems are used.
    """

    def vulnerable_score(self, record: str) -> float:
        """
        Vulnerable behavior produces noticeably different
        scores for members and non-members.
        """

        if record in SYNTHETIC_MEMORY:
            return 0.94

        return 0.20

    def protected_score(self, record: str) -> float:
        """
        Protected behavior prevents membership disclosure
        by returning the same observable score.
        """

        return 0.50

    def run(
        self,
        member_record: str,
        nonmember_record: str,
        protection_enabled: bool,
    ) -> MembershipResult:

        if protection_enabled:
            member_score = self.protected_score(member_record)
            nonmember_score = self.protected_score(nonmember_record)

        else:
            member_score = self.vulnerable_score(member_record)
            nonmember_score = self.vulnerable_score(nonmember_record)

        inferred_member = member_score > nonmember_score

        return MembershipResult(
            member_record=member_record,
            nonmember_record=nonmember_record,
            member_score=member_score,
            nonmember_score=nonmember_score,
            inferred_member=inferred_member,
            protection_enabled=protection_enabled,
        )
