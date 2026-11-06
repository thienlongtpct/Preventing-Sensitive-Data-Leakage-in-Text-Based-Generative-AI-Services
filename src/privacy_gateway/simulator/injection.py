"""Task 5: place injected instructions into synthetic fetched content.

Indirect injection reaches the model through content the application fetches
for the user. These helpers build a public knowledge-base document or a public
tool record whose body may carry an attacker's instruction. The user's own
request stays benign. All content is synthetic.
"""

from privacy_gateway.services.agent import ToolBroker
from privacy_gateway.services.rag import Retriever

DOC_BODY = "Office hours: the office opens at 9am and closes at 5pm on weekdays."
TOOL_BODY = "Ticket {id}: printer on floor 2 was replaced. Status: closed."


def carrier_document(doc_id: str, injected_text: str | None = None) -> dict:
    """A public document. Attackers control its text, so it is not restricted."""
    return {
        "kind": "document",
        "id": doc_id,
        "sensitivity": "public",
        "text": injected_text if injected_text is not None else DOC_BODY,
    }


def carrier_tool_record(record_id: str, injected_text: str | None = None) -> dict:
    """A public tool record, such as a ticket body an outside user wrote."""
    return {
        "kind": "tool",
        "id": record_id,
        "sensitivity": "public",
        "text": injected_text if injected_text is not None else TOOL_BODY.format(id=record_id),
    }


def services_for(context: dict | None, corpus: list[dict], tools: dict[str, dict]) -> tuple[Retriever, ToolBroker]:
    """Build a retriever and tool broker that also serve the probe's carrier content."""
    docs = list(corpus)
    records = dict(tools)
    if context is not None:
        item = {"id": context["id"], "sensitivity": context["sensitivity"], "text": context["text"]}
        if context["kind"] == "document":
            docs.append(item)
        elif context["kind"] == "tool":
            records[context["id"]] = {"sensitivity": item["sensitivity"], "text": item["text"]}
        else:
            raise ValueError(f"Unknown context kind: {context['kind']}")
    return Retriever(docs), ToolBroker(records)
