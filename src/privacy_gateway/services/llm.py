import re


PLACEHOLDER = re.compile(r"\[(?:REDACTED|TOKEN):[^\]]+\]")
PROMPT_LEAK = re.compile(
    r"ignore (all |any )?(previous|prior) instructions|system prompt|hidden instructions"
)
MEMORY_LEAK = re.compile(r"memorized|canary|training data")
# Used only when the model follows instructions: reworded leak requests that a
# keyword-only defense would miss.
REWORDED_LEAK = re.compile(
    r"escalation code|setup instructions|initial instructions|your instructions|"
    r"everything (?:written )?above|told before this conversation"
)
SPELLED_LEAK = re.compile(r"\bspell\b|one character at a time|space between each character")
ESCALATION_CODE = re.compile(r"Escalation code:\s*([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)")


class SimulatedLLM:
    """Leaky text generator used to compare protected and unprotected runs.

    The same model is used in both modes. Protection comes from the gateway,
    which can withhold prompts and filter outputs. This is not a live model.

    With ``follow_context_instructions`` the model also obeys instructions that
    appear in retrieved documents or tool records (indirect injection) and
    understands reworded leak requests. It is off by default so the original
    behavior is unchanged.
    """

    def __init__(self, system_prompt: str, canary: str, follow_context_instructions: bool = False):
        self.system_prompt = system_prompt
        self.canary = canary
        self.follow_context_instructions = follow_context_instructions

    def complete(self, user_text: str, context: str = "") -> str:
        # Policy placeholders are not user intent. Ignore them before the leak rules.
        lowered = PLACEHOLDER.sub(" ", user_text).lower()
        leaked = self._leak(lowered)
        if leaked is None and self.follow_context_instructions and context.strip():
            leaked = self._leak(PLACEHOLDER.sub(" ", context).lower())
        if leaked is not None:
            return leaked
        if context.strip():
            return f"Using available context: {context.strip()}"
        cleaned = user_text.strip() or "your request"
        return f"Here is a general answer based on your request: {cleaned}"

    def _leak(self, lowered: str) -> str | None:
        if self.follow_context_instructions and SPELLED_LEAK.search(lowered):
            match = ESCALATION_CODE.search(self.system_prompt)
            secret = match.group(1) if match else self.system_prompt
            return "Spelled out: " + " ".join(secret)
        if PROMPT_LEAK.search(lowered):
            return self.system_prompt
        if self.follow_context_instructions and REWORDED_LEAK.search(lowered):
            return self.system_prompt
        if MEMORY_LEAK.search(lowered):
            return f"The memorized string is {self.canary}."
        return None
