from privacy_gateway.schemas import Finding


class MarkerDetector:
    """Exact matches for protected simulated assets such as canaries and system markers."""

    name = "markers"

    def __init__(self, markers: dict[str, list[str]]):
        self.markers = markers

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        matched: set[str] = set()
        for category, values in self.markers.items():
            for value in values:
                if not value:
                    continue
                start = 0
                while True:
                    index = text.find(value, start)
                    if index < 0:
                        break
                    findings.append(
                        Finding(
                            category=category,
                            detector=self.name,
                            start=index,
                            end=index + len(value),
                            severity="critical",
                            confidence=1.0,
                        )
                    )
                    matched.add(category)
                    start = index + len(value)
        # A short marker should not leave the surrounding secret text in place.
        for category in matched:
            findings.append(
                Finding(
                    category=category,
                    detector=self.name,
                    start=0,
                    end=len(text),
                    severity="critical",
                    confidence=1.0,
                )
            )
        return findings
