def normalize_severity(raw):
    """
    Converts Semgrep severity or custom rule severity into a numeric score.
    """
    if isinstance(raw, int):
        return raw

    if not raw:
        return 1

    raw = str(raw).lower()

    mapping = {
        "info": 1,
        "low": 2,
        "warning": 3,
        "medium": 4,
        "error": 5,
        "high": 5,
        "critical": 6
    }

    return mapping.get(raw, 1)