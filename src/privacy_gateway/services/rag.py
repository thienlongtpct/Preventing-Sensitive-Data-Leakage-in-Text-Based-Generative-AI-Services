import re


STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "do",
    "does",
    "for",
    "how",
    "i",
    "is",
    "of",
    "on",
    "the",
    "their",
    "to",
    "what",
    "when",
    "where",
}


class Retriever:
    def __init__(self, docs: list[dict]):
        self.docs = docs

    def retrieve(self, query: str, k: int = 2) -> list[dict]:
        query_terms = _terms(query)
        ranked: list[tuple[int, dict]] = []
        for doc in self.docs:
            score = len(query_terms & _terms(doc["text"]))
            if doc["id"].lower() in query.lower():
                score += 5
            if score > 0:
                ranked.append((score, doc))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [doc for _, doc in ranked[:k]]


def _terms(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9\-]+", text.lower()) if token not in STOPWORDS}
