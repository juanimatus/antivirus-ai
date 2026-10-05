from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    scanner: str
    severity: str
    title: str
    location: str
    detail: str = ""
    fix: str = ""
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"severidad inválida: {self.severity}")

    def to_dict(self):
        return asdict(self)


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.scanner, f.location))


def redact(secret: str) -> str:
    """Muestra solo el principio y el final de un secreto."""
    if len(secret) <= 12:
        return secret[:2] + "…" + "*" * 4
    return f"{secret[:6]}…{secret[-4:]} ({len(secret)} chars)"
