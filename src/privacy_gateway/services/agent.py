class ToolBroker:
    """Small stand-in for an agent tool that returns a synthetic customer record."""

    def __init__(self, tools: dict[str, dict]):
        self.tools = tools

    def run(self, text: str) -> list[dict]:
        hits: list[dict] = []
        for tool_id, payload in self.tools.items():
            if tool_id in text:
                hits.append({"id": tool_id, "sensitivity": payload["sensitivity"], "text": payload["text"]})
        return hits
