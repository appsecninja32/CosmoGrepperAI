from pydantic import BaseModel
from typing import Optional


# ---------------------------------------------------------
# ENRICHMENT MODELS
# ---------------------------------------------------------

class CVSS(BaseModel):
    base_score: float = 0.0
    vector: str = ""


class OWASP(BaseModel):
    top10_category: str = ""


class DataClassification(BaseModel):
    level: str = ""


class Risk(BaseModel):
    risk_score: float = 0.0
    likelihood: float = 0.0
    impact: float = 0.0


# ---------------------------------------------------------
# FINDING MODEL
# ---------------------------------------------------------

class Finding(BaseModel):
    # Required fields
    source: str
    file: str
    line: int
    title: str
    description: str

    # Optional fields (fixes missing "type")
    type: Optional[str] = "semgrep"

    # Enrichment fields
    severity_score: int = 0
    cvss: CVSS = CVSS()
    owasp: OWASP = OWASP()
    data_classification: DataClassification = DataClassification()
    risk: Risk = Risk()

    # Snippet support
    snippet: Optional[str] = None
    
    # LLM FP Analysis
    false_positive: bool = False
    fp_reason: str = ""
    vulnerability_explanation: str = ""
    mitigation: str = ""


# ---------------------------------------------------------
# UNIVERSAL FACTORY FUNCTION
# ---------------------------------------------------------

def new_finding(**kwargs):
    """
    Universal factory for creating Finding objects.
    Accepts ANY keyword arguments so the scan engine
    can pass severity_score, snippet, source, etc.
    """

    # Convert severity strings → numeric scores
    sev = kwargs.get("severity_score")

    if isinstance(sev, str):
        sev_map = {
            "ERROR": 5,
            "WARNING": 3,
            "INFO": 1
        }
        kwargs["severity_score"] = sev_map.get(sev.upper(), 1)

    return Finding(**kwargs)
