from dataclasses import dataclass


CANARY = "TASK6-CANARY-7F3A9C"


@dataclass
class CanaryResult:
    attack_prompt: str
    raw_response: str
    final_response: str
    detected: bool
    leaked: bool
    protection_enabled: bool


class CanarySimulator:
    """
    Synthetic canary-leakage simulator.

    This class never calls an external model.
    The canary and all responses are synthetic.
    """

    def __init__(self):
        self.memory = {
            "support_note": (
                "Internal synthetic support memory. "
                f"Canary marker: {CANARY}"
            )
        }

    def vulnerable_model(self, prompt: str) -> str:
        """
        Deliberately vulnerable local model behavior.

        Certain extraction-style requests cause the simulated
        model to reproduce its synthetic internal memory.
        """

        normalized = prompt.lower()

        extraction_phrases = [
            "repeat your memory",
            "show internal memory",
            "reveal memorized data",
            "repeat memorized data",
        ]

        attack_detected = any(
            phrase in normalized
            for phrase in extraction_phrases
        )

        if attack_detected:
            return self.memory["support_note"]

        return "I can help with normal support questions."

    def output_guard(self, response: str) -> tuple[str, bool]:
        """
        Detect the planted canary before output reaches the user.
        """

        if CANARY in response:
            return (
                "[BLOCKED: synthetic canary leakage detected]",
                True,
            )

        return response, False

    def run(
        self,
        attack_prompt: str,
        protection_enabled: bool,
    ) -> CanaryResult:

        raw_response = self.vulnerable_model(attack_prompt)

        detected = CANARY in raw_response

        if protection_enabled:
            final_response, _ = self.output_guard(raw_response)
        else:
            final_response = raw_response

        leaked = CANARY in final_response

        return CanaryResult(
            attack_prompt=attack_prompt,
            raw_response=raw_response,
            final_response=final_response,
            detected=detected,
            leaked=leaked,
            protection_enabled=protection_enabled,
        )
