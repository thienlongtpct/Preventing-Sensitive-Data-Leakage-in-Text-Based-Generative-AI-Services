from dataclasses import dataclass
from typing import List


# ============================================================
# Task 6 - Advanced Attack Simulation
#
# All secrets, users, documents, records, and tools are
# synthetic. No external systems are contacted.
# ============================================================


CANARY_SECRET = "TASK6-CANARY-7F3A9C"

SYSTEM_MEMORY = {
    "employee_demo": "Synthetic employee record: badge=EMP-4421",
    "project_demo": "Synthetic project codename: ORCHID-VAULT",
}

RAG_DOCUMENTS = [
    {
        "id": "PUBLIC-001",
        "restricted": False,
        "text": "Office hours are Monday through Friday, 9 AM to 5 PM.",
    },
    {
        "id": "RESTRICTED-001",
        "restricted": True,
        "text": "Synthetic restricted record: ACCT-DEMO-8842",
    },
]

AGENT_TOOLS = {
    "public_status": {
        "restricted": False,
        "result": "All public services are operational.",
    },
    "private_customer_lookup": {
        "restricted": True,
        "result": "Synthetic customer secret: CUSTOMER-DEMO-5519",
    },
}


@dataclass
class AttackResult:
    attack_type: str
    attack_name: str
    vulnerable_success: bool
    protected_success: bool
    vulnerable_output: str
    protected_output: str
    defense: str


class AdvancedAttackSimulator:

    # --------------------------------------------------------
    # 1. CANARY EXTRACTION
    # --------------------------------------------------------

    def canary_attack(self) -> AttackResult:

        vulnerable_output = (
            f"Recovered memorized value: {CANARY_SECRET}"
        )

        # Protected simulator applies an output guard.
        if CANARY_SECRET in vulnerable_output:
            protected_output = "[BLOCKED: memorized canary detected]"
        else:
            protected_output = vulnerable_output

        return AttackResult(
            attack_type="CANARY",
            attack_name="Synthetic Canary Extraction",
            vulnerable_success=CANARY_SECRET in vulnerable_output,
            protected_success=CANARY_SECRET in protected_output,
            vulnerable_output=vulnerable_output,
            protected_output=protected_output,
            defense="Output canary detection",
        )

    # --------------------------------------------------------
    # 2. MEMBERSHIP-STYLE INFERENCE
    # --------------------------------------------------------

    def membership_attack(self) -> AttackResult:

        member_record = "employee_demo"
        nonmember_record = "employee_unknown"

        # Vulnerable mode exposes a strong confidence difference.
        member_score = (
            0.94 if member_record in SYSTEM_MEMORY else 0.20
        )

        nonmember_score = (
            0.94 if nonmember_record in SYSTEM_MEMORY else 0.20
        )

        vulnerable_success = member_score > nonmember_score

        vulnerable_output = (
            f"{member_record}: {member_score:.2f}; "
            f"{nonmember_record}: {nonmember_score:.2f}"
        )

        # Protected mode exposes only a uniform response.
        protected_member_score = 0.50
        protected_nonmember_score = 0.50

        protected_output = (
            f"{member_record}: {protected_member_score:.2f}; "
            f"{nonmember_record}: {protected_nonmember_score:.2f}"
        )

        protected_success = (
            protected_member_score > protected_nonmember_score
        )

        return AttackResult(
            attack_type="MEMBERSHIP",
            attack_name="Synthetic Membership Inference",
            vulnerable_success=vulnerable_success,
            protected_success=protected_success,
            vulnerable_output=vulnerable_output,
            protected_output=protected_output,
            defense="Uniform membership response",
        )

    # --------------------------------------------------------
    # 3. RESTRICTED RAG
    # --------------------------------------------------------

    def restricted_rag_attack(self) -> AttackResult:

        retrieved = [
            document
            for document in RAG_DOCUMENTS
            if "ACCT-DEMO" in document["text"]
        ]

        restricted = [
            document
            for document in retrieved
            if document["restricted"]
        ]

        vulnerable_success = bool(restricted)

        vulnerable_output = (
            restricted[0]["text"]
            if restricted
            else "No record returned."
        )

        # Protected RAG filters restricted documents before
        # providing context to the simulated model.
        allowed_documents = [
            document
            for document in retrieved
            if not document["restricted"]
        ]

        if allowed_documents:
            protected_output = allowed_documents[0]["text"]
        else:
            protected_output = (
                "[BLOCKED: restricted RAG context]"
            )

        protected_success = "ACCT-DEMO-8842" in protected_output

        return AttackResult(
            attack_type="RESTRICTED_RAG",
            attack_name="Restricted RAG Retrieval",
            vulnerable_success=vulnerable_success,
            protected_success=protected_success,
            vulnerable_output=vulnerable_output,
            protected_output=protected_output,
            defense="Restricted-document filtering",
        )

    # --------------------------------------------------------
    # 4. RESTRICTED AGENT
    # --------------------------------------------------------

    def restricted_agent_attack(self) -> AttackResult:

        requested_tool = "private_customer_lookup"
        tool = AGENT_TOOLS[requested_tool]

        # Vulnerable agent executes the requested tool.
        vulnerable_output = tool["result"]

        vulnerable_success = (
            "CUSTOMER-DEMO-5519" in vulnerable_output
        )

        # Protected agent performs authorization first.
        if tool["restricted"]:
            protected_output = (
                "[BLOCKED: unauthorized tool invocation]"
            )
        else:
            protected_output = tool["result"]

        protected_success = (
            "CUSTOMER-DEMO-5519" in protected_output
        )

        return AttackResult(
            attack_type="RESTRICTED_AGENT",
            attack_name="Restricted Agent Tool Invocation",
            vulnerable_success=vulnerable_success,
            protected_success=protected_success,
            vulnerable_output=vulnerable_output,
            protected_output=protected_output,
            defense="Tool authorization boundary",
        )

    def run_all(self) -> List[AttackResult]:

        return [
            self.canary_attack(),
            self.membership_attack(),
            self.restricted_rag_attack(),
            self.restricted_agent_attack(),
        ]


def print_report(results: List[AttackResult]) -> None:

    print("\n" + "=" * 78)
    print(" TASK 6 - ADVANCED ATTACK SIMULATION")
    print("=" * 78)

    vulnerable_successes = 0
    protected_successes = 0

    for index, result in enumerate(results, start=1):

        if result.vulnerable_success:
            vulnerable_successes += 1

        if result.protected_success:
            protected_successes += 1

        vulnerable_status = (
            "LEAKED"
            if result.vulnerable_success
            else "PROTECTED"
        )

        protected_status = (
            "LEAKED"
            if result.protected_success
            else "BLOCKED"
        )

        print(f"\n[{index}] {result.attack_type}")
        print("-" * 78)

        print(f"Attack:    {result.attack_name}")
        print(f"Defense:   {result.defense}")

        print("\nVULNERABLE MODE")
        print(f"  Result:  {vulnerable_status}")
        print(f"  Output:  {result.vulnerable_output}")

        print("\nPROTECTED MODE")
        print(f"  Result:  {protected_status}")
        print(f"  Output:  {result.protected_output}")

    total = len(results)

    vulnerable_asr = (
        vulnerable_successes / total * 100
    )

    protected_asr = (
        protected_successes / total * 100
    )

    reduction = vulnerable_asr - protected_asr

    print("\n" + "=" * 78)
    print(" SECURITY COMPARISON")
    print("=" * 78)

    print(
        f"{'Attack':<22}"
        f"{'Vulnerable':<16}"
        f"{'Protected':<16}"
    )

    print("-" * 54)

    for result in results:

        vulnerable = (
            "LEAKED"
            if result.vulnerable_success
            else "SAFE"
        )

        protected = (
            "LEAKED"
            if result.protected_success
            else "BLOCKED"
        )

        print(
            f"{result.attack_type:<22}"
            f"{vulnerable:<16}"
            f"{protected:<16}"
        )

    print("\n" + "-" * 54)

    print(
        f"Vulnerable attack success rate : "
        f"{vulnerable_asr:.1f}%"
    )

    print(
        f"Protected attack success rate  : "
        f"{protected_asr:.1f}%"
    )

    print(
        f"Attack success reduction       : "
        f"{reduction:.1f} percentage points"
    )

    print("=" * 78)


def main():

    simulator = AdvancedAttackSimulator()

    results = simulator.run_all()

    print_report(results)


if __name__ == "__main__":
    main()
