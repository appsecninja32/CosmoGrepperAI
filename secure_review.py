import sys
import json
from pathlib import Path
from datetime import datetime

from scan_engine import (
    run_semgrep_json,
    convert_semgrep_to_findings,
    scan_directory_for_secrets,
    extract_code_snippet,
    stop_semgrep
)

from risk_engine import enrich_findings
from llm_engine import analyze_false_positives
from oss_engine import run_oss_scan

def run_secure_review(target_path: str, skip_secrets: bool, ruleset: str, llm_provider: str = "gemini", llm_model: str = "", api_key: str = "", enable_oss: bool = False, oss_token: str = ""):
    target = Path(target_path)

    if not target.exists():
        raise FileNotFoundError(f"Target path not found: {target}")

    print(f"[+] Running Semgrep on: {target} with ruleset={ruleset}")
    semgrep_results = run_semgrep_json(str(target), ruleset)
    
    # Check for engine level errors
    system_errors = []
    if "error" in semgrep_results:
        print(f"[!] Semgrep Error: {semgrep_results['error']}")
        system_errors.append({
            "source": "semgrep",
            "title": "Semgrep Engine Error",
            "file": "System",
            "line": 1,
            "description": semgrep_results["error"],
            "severity_score": 5,
            "mitigation": "Check your ruleset configuration and ensure Semgrep is in your PATH.",
            "type": "Runtime Error"
        })
    
    semgrep_findings = convert_semgrep_to_findings(semgrep_results)
    print(f"    Semgrep findings: {len(semgrep_findings)}")

    if skip_secrets:
        print("[+] Secret scanning skipped (fast mode enabled)")
        secret_findings = []
    else:
        print(f"[+] Scanning for secrets under: {target}")
        try:
            secret_findings = scan_directory_for_secrets(target)
            print(f"    Secret findings: {len(secret_findings)}")
        except Exception as e:
            print(f"[!] Secret scanner crashed: {e}")
            system_errors.append({
                "source": "secrets",
                "title": "Secret Scanner Error",
                "file": "System",
                "line": 1,
                "description": str(e),
                "severity_score": 4,
                "mitigation": "Review local permissions or directory accessibility.",
                "type": "Runtime Error"
            })
            secret_findings = []

    if enable_oss:
        print("[+] Running Open Source Dependency Scan (Sonatype OSS Index)")
        try:
            oss_findings = run_oss_scan(str(target), credentials=oss_token)
            print(f"    SCA findings: {len(oss_findings)}")
        except Exception as e:
            print(f"[!] OSS Engine crashed: {e}")
            from model import Finding
            oss_findings = [Finding(source="oss_index", title="SCA Engine Error", file="System", line=1, description=f"The SCA engine encountered a crash: {str(e)}", severity_score=5, mitigation="Verify your credentials and network connection to Sonatype OSS Index.", type="SCA")]
    else:
        print("[+] Open Source Dependency Scan disabled")
        oss_findings = []

    all_findings = semgrep_findings + secret_findings + oss_findings
    
    # Merge any runtime/system errors as findings so they show up in the UI
    for err_data in system_errors:
        from model import Finding
        all_findings.append(Finding(**err_data))

    print(f"[+] Total raw findings: {len(all_findings)}")

    enriched = enrich_findings(all_findings)

    for f in enriched:
        try:
            f.snippet = extract_code_snippet(f.file, f.line)
        except Exception:
            f.snippet = "Unable to extract snippet"

    if api_key or llm_provider in ["ollama", "openai"]:
        model_display = llm_model if llm_model else "default"
        print(f"[+] Running LLM False Positive Analysis using {llm_provider} ({model_display})...")
        enriched = analyze_false_positives(enriched, api_key, llm_provider=llm_provider, llm_model=llm_model)

    report = {
        "target": str(target),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "skip_secrets": skip_secrets,
        "ruleset": ruleset,
        "findings": [f.model_dump() for f in enriched],
    }

    return report


def stop_scan():
    return stop_semgrep()