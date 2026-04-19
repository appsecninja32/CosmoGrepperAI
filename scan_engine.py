import subprocess
import json
from pathlib import Path
import os
import model   # SAFE import, avoids circular import


# ---------------------------------------------------------
# SEMGREP SCAN
# ---------------------------------------------------------

def run_semgrep_json(path, ruleset):
    """
    Executes semgrep with JSON output.
    Returns: Dict with 'results' list and optional 'error' string.
    """
    # Resolve absolute rules directory if not a public registry (p/...)
    if ruleset.startswith("p/"):
        config_val = ruleset
    else:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        config_val = os.path.join(BASE_DIR, "rules", ruleset)

    # Use list-based arguments for better path safety especially on Windows
    # We still use shell=True on Windows because semgrep is often a script/shim
    cmd = ["semgrep", "scan", "--json", "--config", config_val, str(path)]

    # Ensure UTF-8 for Semgrep subprocess on Windows
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        # Use shell=True for Windows compatibility with shims
        # Use shell=False for Unix/Mac for better signal handling and security
        is_windows = (os.name == "nt")
        result = subprocess.run(
            cmd,
            shell=is_windows,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=env
        )
    except Exception as e:
        return {"results": [], "error": f"Internal process error: {str(e)}"}

    # If the stdout is empty and there's stderr, it's likely a configuration or engine crash
    if not result.stdout.strip() and result.stderr.strip():
        return {
            "results": [],
            "error": f"Semgrep Error: {result.stderr.strip()}",
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    # Parse JSON
    try:
        data = json.loads(result.stdout)
        # If semgrep had warnings/errors in the JSON return that too
        if "errors" in data and data["errors"] and not data.get("results"):
             return {
                 "results": [],
                 "error": f"Semgrep Engine reported internal errors: {json.dumps(data['errors'][0])}"
             }
        return data
    except Exception:
        # If parsing fails, fall back to capturing stderr
        err_msg = "Failed to parse Semgrep output"
        if result.stderr.strip():
            err_msg = f"Semgrep failed: {result.stderr.strip()}"
        
        return {
            "results": [],
            "error": err_msg,
            "stdout": result.stdout,
            "stderr": result.stderr
        }


# ---------------------------------------------------------
# CONVERT SEMGREP RESULTS TO FINDINGS
# ---------------------------------------------------------

def convert_semgrep_to_findings(json_data):
    findings = []

    for item in json_data.get("results", []):
        file_path = item.get("path", "")
        line = item.get("start", {}).get("line", 0)
        message = item.get("extra", {}).get("message", "")
        rule_id = item.get("check_id", "")

        metadata = item.get("extra", {}).get("metadata", {})
        owasp_data = metadata.get("owasp", [])
        owasp_str = owasp_data[0] if isinstance(owasp_data, list) and owasp_data else str(owasp_data) if owasp_data else ""
        cvss_data = metadata.get("cvss", [])
        cvss_str = cvss_data[0] if isinstance(cvss_data, list) and cvss_data else str(cvss_data) if cvss_data else ""

        finding = model.new_finding(
            title=rule_id,
            description=message,
            file=file_path,
            line=line,
            severity_score=item.get("extra", {}).get("severity", 1),
            snippet=extract_code_snippet(file_path, line),
            source="semgrep"
        )
        if owasp_str:
             finding.owasp.top10_category = owasp_str
        if cvss_str:
             try:
                 finding.cvss.base_score = float(cvss_str)
             except:
                 pass

        # --- Mitigation Advice Pipeline ---
        # 1. Try Semgrep metadata fields first
        rem = metadata.get("remediation") or metadata.get("fix") or metadata.get("fix_recommendation")
        if rem:
            finding.mitigation = str(rem)
        else:
            # 2. Generate rule-based mitigation from the rule ID and description
            finding.mitigation = _generate_mitigation(rule_id, message)

        findings.append(finding)

    return findings


def _generate_mitigation(rule_id: str, description: str) -> str:
    """Generate actionable mitigation advice based on rule ID keywords and description."""
    rid = rule_id.lower()
    desc = description.lower()

    # SQL Injection
    if "sql" in rid or "sqli" in rid or "sql-injection" in rid or "sql injection" in desc:
        return ("Use parameterized queries or prepared statements instead of string concatenation.\n"
                "Example (Python):\n"
                "  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                "Never interpolate user input directly into SQL strings.")

    # Command Injection / OS Command Exec
    if "command" in rid or "exec" in rid or "os-command" in rid or "subprocess" in rid or "command injection" in desc:
        return ("Avoid passing user-controlled input to shell commands.\n"
                "Use safe APIs like subprocess.run() with shell=False and a list of arguments.\n"
                "Example:\n"
                "  subprocess.run(['ls', '-la', safe_path], shell=False)\n"
                "Validate and sanitize all inputs before use in system calls.")

    # XSS
    if "xss" in rid or "cross-site" in rid or "cross_site_scripting" in rid or "xss" in desc:
        return ("Escape all user-supplied data before rendering in HTML.\n"
                "Use context-aware output encoding (HTML, JS, URL, CSS).\n"
                "Implement Content-Security-Policy (CSP) headers.\n"
                "Use framework auto-escaping (e.g., Jinja2 autoescape=True).")

    # Path Traversal
    if "path-traversal" in rid or "directory-traversal" in rid or "lfi" in rid or "path traversal" in desc:
        return ("Validate and canonicalize file paths before access.\n"
                "Use os.path.realpath() and verify the resolved path is within the allowed directory.\n"
                "Reject inputs containing '../' or '..\\' sequences.\n"
                "Use an allowlist of permitted file paths when possible.")

    # SSRF
    if "ssrf" in rid or "server-side-request" in rid or "ssrf" in desc:
        return ("Validate and restrict outbound URLs to an allowlist of trusted domains.\n"
                "Block requests to internal/private IP ranges (127.0.0.1, 10.x, 172.16-31.x, 192.168.x).\n"
                "Use a URL parser to extract and validate the hostname before making requests.\n"
                "Disable HTTP redirects or validate each redirect destination.")

    # Deserialization
    if "deserial" in rid or "pickle" in rid or "yaml.load" in rid or "deserialization" in desc:
        return ("Never deserialize untrusted data with unsafe methods.\n"
                "Use yaml.safe_load() instead of yaml.load().\n"
                "Avoid pickle for untrusted input; use JSON instead.\n"
                "Implement integrity checks (HMAC) on serialized data.")

    # Hardcoded Secrets / Credentials
    if "secret" in rid or "password" in rid or "credential" in rid or "hardcoded" in rid or "api-key" in rid:
        return ("Remove hardcoded secrets from source code immediately.\n"
                "Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).\n"
                "Add secret patterns to .gitignore and scan for leaked secrets with tools like detect-secrets.\n"
                "Rotate any credentials that were committed to version control.")

    # Insecure Crypto / Hashing
    if "crypto" in rid or "hash" in rid or "md5" in rid or "sha1" in rid or "weak-cipher" in rid:
        return ("Replace weak hashing algorithms (MD5, SHA1) with SHA-256 or stronger.\n"
                "For passwords, use bcrypt, scrypt, or Argon2 with proper salt.\n"
                "Use TLS 1.2+ for data in transit and AES-256 for data at rest.\n"
                "Never implement custom cryptographic algorithms.")

    # CORS
    if "cors" in rid or "cross-origin" in rid or "access-control" in rid:
        return ("Restrict Access-Control-Allow-Origin to specific trusted domains.\n"
                "Never use wildcard (*) with credentials.\n"
                "Validate the Origin header on the server side.\n"
                "Implement proper CORS preflight handling.")

    # Open Redirect
    if "redirect" in rid or "open-redirect" in rid:
        return ("Validate redirect URLs against an allowlist of trusted domains.\n"
                "Use relative URLs for redirects when possible.\n"
                "Never pass user-controlled input directly to redirect functions.\n"
                "Warn users before redirecting to external sites.")

    # CSRF
    if "csrf" in rid or "cross-site-request" in rid:
        return ("Implement anti-CSRF tokens in all state-changing forms.\n"
                "Use SameSite cookie attribute (Strict or Lax).\n"
                "Verify the Origin/Referer header on the server.\n"
                "Use framework-provided CSRF protection (e.g., Django {% csrf_token %}).")

    # Insecure HTTP
    if "http" in rid and ("insecure" in rid or "cleartext" in rid) or "https" in desc:
        return ("Enforce HTTPS for all communications.\n"
                "Use HSTS (HTTP Strict Transport Security) headers.\n"
                "Redirect all HTTP requests to HTTPS.\n"
                "Ensure TLS certificates are valid and up to date.")

    # XML / XXE
    if "xml" in rid or "xxe" in rid:
        return ("Disable external entity processing in XML parsers.\n"
                "Use defusedxml library in Python for safe XML parsing.\n"
                "Validate and sanitize XML input before processing.\n"
                "Prefer JSON over XML when possible.")

    # Authentication / Authorization
    if "auth" in rid or "jwt" in rid or "token" in rid or "session" in rid:
        return ("Implement proper authentication with strong password policies.\n"
                "Use secure session management with httpOnly and secure cookie flags.\n"
                "Validate and verify JWT tokens with proper signature checking.\n"
                "Implement rate limiting on authentication endpoints.")

    # Generic fallback based on description
    return ("Review the flagged code and apply the principle of least privilege.\n"
            "Validate and sanitize all user inputs at the application boundary.\n"
            "Follow secure coding guidelines for your language/framework.\n"
            "Consult OWASP guidance for this vulnerability category: https://owasp.org/www-project-top-ten/")


try:
    from detect_secrets import SecretsCollection
    from detect_secrets.settings import transient_settings
    HAS_DETECT_SECRETS = True
except ImportError:
    HAS_DETECT_SECRETS = False

def scan_directory_for_secrets(path):
    findings = []
    
    if not HAS_DETECT_SECRETS:
        print("[!] Warning: 'detect-secrets' is not installed or virtual environment is not active. Secret scanning skipped.")
        print("[!] Please run: pip install detect-secrets")
        return findings
    
    plugins_setup = [
        {"name": "AWSKeyDetector"},
        {"name": "ArtifactoryDetector"},
        {"name": "AzureStorageKeyDetector"},
        {"name": "BasicAuthDetector"},
        {"name": "CloudantDetector"},
        {"name": "GitHubTokenDetector"},
        {"name": "IbmCloudIamDetector"},
        {"name": "IbmCosHmacDetector"},
        {"name": "JwtTokenDetector"},
        {"name": "KeywordDetector", "keyword_exclude": ""},
        {"name": "MailchimpDetector"},
        {"name": "NpmDetector"},
        {"name": "PrivateKeyDetector"},
        {"name": "SendGridDetector"},
        {"name": "SlackDetector"},
        {"name": "SoftlayerDetector"},
        {"name": "SquareOAuthDetector"},
        {"name": "StripeDetector"},
        {"name": "TwilioKeyDetector"}
    ]

    secrets = SecretsCollection()
    try:
        with transient_settings({"plugins_used": plugins_setup}):
            # Uses os.walk internally
            secrets.scan_files(str(path))
            
        data = secrets.json()
        
        for file_path, file_secrets in data.items():
            for secret in file_secrets:
                line_num = secret.get("line_number", 1)
                secret_type = secret.get("type", "Unknown Secret")
                
                findings.append(
                    model.new_finding(
                        title=f"Secret: {secret_type}",
                        description=f"A potential {secret_type} was dynamically detected locally.",
                        file=file_path,
                        line=line_num,
                        severity_score=5,
                        snippet=extract_code_snippet(file_path, line_num),
                        source="detect-secrets"
                    )
                )
    except Exception as e:
        print("[DetectSecrets Error]", e)

    return findings


# ---------------------------------------------------------
# CODE SNIPPET EXTRACTION
# ---------------------------------------------------------

def extract_code_snippet(file_path, line_number, context=3):
    if not Path(file_path).exists():
        return ""

    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()

        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)

        return "".join(lines[start:end])
    except:
        return ""


# ---------------------------------------------------------
# STOP SEMGREP
# ---------------------------------------------------------

def stop_semgrep():
    """Attempts to kill semgrep and its child processes cross-platform."""
    try:
        if os.name == "nt":
            # Use /T to kill the process tree on Windows
            subprocess.run(
                ["taskkill", "/F", "/T", "/IM", "semgrep.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        else:
            # Use pkill with full process matching on Unix/Mac
            subprocess.run(
                ["pkill", "-f", "semgrep"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        return True
    except:
        return False