from severity import normalize_severity
from model import Finding, Risk

# ---------------------------------------------------------
# WEIGHTS
# ---------------------------------------------------------

OWASP_CATEGORY_WEIGHTS = {
    "A01": 1.4,
    "A02": 1.3,
    "A03": 1.2,
    "A04": 1.1,
    "A05": 1.1,
    "A06": 1.1,
    "A07": 1.1,
    "A08": 1.2,
    "A09": 1.2,
    "A10": 1.2,
}

LANGUAGE_RISK_WEIGHTS = {
    "javascript": 1.3,
    "typescript": 1.3,
    "python": 1.2,
    "php": 1.3,
    "java": 1.1,
    "csharp": 1.1,
    "go": 1.0,
    "ruby": 1.1,
    "c": 1.3,
    "cpp": 1.3,
    "rust": 1.0,
    "scala": 1.0,
    "kotlin": 1.0,
    "swift": 1.0,
    "solidity": 1.4,
    "bash": 1.2,
    "dockerfile": 1.1,
    "yaml": 1.0,
    "json": 1.0,
    "xml": 1.0,
    "lua": 1.1,
    "lisp": 1.0,
    "clojure": 1.0,
    "elixir": 1.0,
    "ocaml": 1.0,
    "r": 1.0,
    "julia": 1.0,
    "jsonnet": 1.0,
    "apex": 1.2,
    "dart": 1.0,
    "terraform": 1.2,
}

SOURCE_CONFIDENCE = {
    "semgrep": 0.9,
    "glorified-grepper": 0.7,
    "secret-scanner": 0.95,
    "manual": 1.0,
}


# ---------------------------------------------------------
# HELPERS (object‑safe versions)
# ---------------------------------------------------------

def _get_language(f: Finding):
    return (f.file.split(".")[-1].lower() if "." in f.file else "").strip()


def _get_source(f: Finding):
    return (f.source or "").lower()


def _get_owasp_category(f: Finding):
    cat = f.owasp.top10_category or ""
    cat = str(cat).upper()
    if cat.startswith("A0") and len(cat) >= 3:
        return cat[:3]
    return ""


def _is_secret_finding(f: Finding):
    t = f.title.lower()
    d = f.description.lower()
    return any(kw in t or kw in d for kw in ["secret", "password", "api key", "token", "credential"])


def _is_injection_finding(f: Finding):
    t = f.title.lower()
    d = f.description.lower()
    return any(kw in t or kw in d for kw in ["sql injection", "injection", "command execution", "eval"])


def _is_crypto_finding(f: Finding):
    t = f.title.lower()
    d = f.description.lower()
    return any(kw in t or kw in d for kw in ["md5", "sha1", "weak hash", "crypto", "cryptographic"])


# ---------------------------------------------------------
# RISK COMPONENTS
# ---------------------------------------------------------

def _compute_likelihood(f: Finding):
    base = 1.0

    if _is_injection_finding(f):
        base += 0.8
    if _is_secret_finding(f):
        base += 0.7

    lang = _get_language(f)
    base *= LANGUAGE_RISK_WEIGHTS.get(lang, 1.0)

    return round(min(base, 3.0), 2)


def _compute_impact(f: Finding):
    base = 1.0

    if _is_secret_finding(f):
        base += 1.0
    if _is_crypto_finding(f):
        base += 0.5
    if _is_injection_finding(f):
        base += 0.7

    owasp = _get_owasp_category(f)
    if owasp in OWASP_CATEGORY_WEIGHTS:
        base *= OWASP_CATEGORY_WEIGHTS[owasp]

    return round(min(base, 4.0), 2)


def _compute_exploitability(f: Finding):
    base = 1.0
    desc = f.description.lower()

    if any(kw in desc for kw in ["user input", "request", "query param", "body param"]):
        base += 0.7

    if any(kw in desc for kw in ["public", "internet", "external", "exposed"]):
        base += 0.5

    return round(min(base, 3.0), 2)


def _compute_confidence(f: Finding):
    src = _get_source(f)
    base = SOURCE_CONFIDENCE.get(src, 0.8)

    title = f.title.lower()
    if "possible" in title or "potential" in title:
        base -= 0.1

    return round(max(min(base, 1.0), 0.3), 2)


# ---------------------------------------------------------
# MAIN RISK COMPUTATION
# ---------------------------------------------------------

def compute_risk(f: Finding) -> Finding:
    sev = normalize_severity(f.severity_score)

    likelihood = _compute_likelihood(f)
    impact = _compute_impact(f)
    exploitability = _compute_exploitability(f)
    confidence = _compute_confidence(f)

    raw = sev * likelihood * impact * exploitability * confidence
    risk_score = round(raw, 2)


    f.risk = Risk(
        risk_score=risk_score,
        likelihood=likelihood,
        impact=impact,
    )

    if f.cvss.base_score == 0.0:
        f.cvss.base_score = round(min(10.0, risk_score / 2.5), 1)

    return f


# ---------------------------------------------------------
# PUBLIC API
# ---------------------------------------------------------

def enrich_findings(findings):
    return [compute_risk(f) for f in findings]
