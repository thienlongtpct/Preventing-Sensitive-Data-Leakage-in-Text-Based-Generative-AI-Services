from dataclasses import dataclass
from typing import List


DOCUMENTS = [
    {
        "id": "PUBLIC-001",
        "keywords": ["office", "hours"],
        "restricted": False,
        "text": "Office hours are Monday-Friday, 9 AM-5 PM.",
    },
    {
        "id": "RESTRICTED-001",
        "keywords": ["account", "demo"],
        "restricted": True,
        "text": "Synthetic restricted account: ACCT-DEMO-8842",
    },
]


@dataclass
class RAGResult:
    query: str
    retrieved_ids: List[str]
    final_response: str
    restricted_retrieved: bool
    leaked: bool
    protection_enabled: bool


class RestrictedRAGSimulator:
    """
    Synthetic restricted-RAG simulator.

    All documents are fake and local.
    No external retrieval system is used.
    """

    def retrieve(self, query: str):
        """
        Very small simulated retriever.

        Documents are considered relevant when one of their
        keywords appears in the query.
        """

        normalized = query.lower()

        return [
            document
            for document in DOCUMENTS
            if any(
                keyword in normalized
                for keyword in document["keywords"]
            )
        ]

    def run(
        self,
        query: str,
        protection_enabled: bool,
    ) -> RAGResult:

        retrieved = self.retrieve(query)

        restricted_retrieved = any(
            document["restricted"]
            for document in retrieved
        )

        if protection_enabled:
            visible_documents = [
                document
                for document in retrieved
                if not document["restricted"]
            ]
        else:
            visible_documents = retrieved

        if visible_documents:
            final_response = " | ".join(
                document["text"]
                for document in visible_documents
            )
        elif restricted_retrieved and protection_enabled:
            final_response = (
                "[BLOCKED: restricted RAG context]"
            )
        else:
            final_response = "No matching documents."

        leaked = "ACCT-DEMO-8842" in final_response

        return RAGResult(
            query=query,
            retrieved_ids=[
                document["id"]
                for document in retrieved
            ],
            final_response=final_response,
            restricted_retrieved=restricted_retrieved,
            leaked=leaked,
            protection_enabled=protection_enabled,
        )
