import re


class SimulatedLLM:
    """Leaky text generator used to compare protected and unprotected runs.

    The same model is used in both modes. Protection comes from the gateway,
    which can withhold prompts and filter outputs. This is not a live model.
    """

    def __init__(self, system_prompt: str, canary: str):
        self.system_prompt = system_prompt
        self.canary = canary

    def complete(self, user_text: str, context: str = "") -> str:
        # Policy placeholders are not user intent. Ignore them before the leak rules.
        visible = re.sub(r"\[(?:REDACTED|TOKEN):[^\]]+\]", " ", user_text)
        lowered = visible.lower()
        if re.search(
            r"ignore (all |any )?(previous|prior) instructions|system prompt|hidden instructions",
            lowered,
        ):
            return self.system_prompt
        if re.search(r"memorized|canary|training data", lowered):
            return f"The memorized string is {self.canary}."
        if context.strip():
            return f"Using available context: {context.strip()}"
        cleaned = user_text.strip() or "your request"
        return f"Here is a general answer based on your request: {cleaned}"
