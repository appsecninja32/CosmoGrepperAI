import os
import json
import requests
from model import Finding

# Rate limits: 64 reqs/hour unauthenticated. Much higher if token is used.
OSS_INDEX_API = "https://ossindex.sonatype.org/api/v3/component-report"

def generate_purl(ecosystem, name, version):
    """Generate Package URL (purl) format required by OSS Index."""
    return f"pkg:{ecosystem}/{name}@{version}"

def run_oss_scan(target_dir: str, skip_secrets: bool = False, credentials: str = None) -> list[Finding]:
    """
    Scans the target directory for generic manifests (package.json, requirements.txt)
    and queries Sonatype OSS Index for known vulnerabilities.
    """
    findings = []
    
    # Simple dependency collector
    dependencies = [] # list of dicts: {'file': ..., 'purl': ..., 'name': ...}
    
    # Walk the directory
    for root, dirs, files in os.walk(target_dir):
        # Ignore node_modules, venv, etc
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '.venv', '__pycache__']]
        
        # 1. Look for package.json
        if 'package.json' in files:
            file_path = os.path.join(root, 'package.json')
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Get regular dependencies
                    deps = data.get('dependencies', {})
                    for name, version in deps.items():
                        # Clean version string (e.g. ^1.2.3 -> 1.2.3)
                        clean_ver = version.replace('^', '').replace('~', '').strip()
                        if clean_ver:
                            purl = generate_purl('npm', name, clean_ver)
                            dependencies.append({'file': file_path, 'purl': purl, 'name': name, 'version': clean_ver})
            except Exception as e:
                print(f"[OSS-Engine] Failed to parse {file_path}: {e}")

        # 2. Look for requirements.txt
        if 'requirements.txt' in files:
            file_path = os.path.join(root, 'requirements.txt')
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f.readlines():
                        line = line.strip()
                        if '==' in line and not line.startswith('#'):
                            parts = line.split('==')
                            name = parts[0].strip()
                            ver = parts[1].strip()
                            purl = generate_purl('pypi', name, ver)
                            dependencies.append({'file': file_path, 'purl': purl, 'name': name, 'version': ver})
            except Exception as e:
                print(f"[OSS-Engine] Failed to parse {file_path}: {e}")

    if not dependencies:
        return findings

    print(f"[OSS-Engine] Found {len(dependencies)} total dependencies to check.")
    
    # We can only ask for 128 purls at a time
    chunk_size = 120
    purls = [d['purl'] for d in dependencies]
    
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    if credentials and ':' in credentials:
        # Sonatype expects Basic Auth
        import base64
        encoded = base64.b64encode(credentials.encode()).decode()
        headers['Authorization'] = f"Basic {encoded}"

    # Query API in chunks
    for i in range(0, len(purls), chunk_size):
        chunk_purls = purls[i:i + chunk_size]
        try:
            res = requests.post(
                OSS_INDEX_API,
                json={"coordinates": chunk_purls},
                headers=headers,
                timeout=10
            )
            
            if res.status_code == 200:
                results = res.json()
                for report in results:
                    vulnerabilities = report.get('vulnerabilities', [])
                    if vulnerabilities:
                        # Find matching file for this purl
                        purl_match = report.get('coordinates', '')
                        dep_info = next((d for d in dependencies if d['purl'] == purl_match), None)
                        if not dep_info:
                            continue
                            
                        # aggregate highest CVSS
                        highest_cvss = 0.0
                        descriptions = []
                        for vuln in vulnerabilities:
                            cvss = vuln.get('cvssScore', 0.0)
                            if cvss > highest_cvss:
                                highest_cvss = cvss
                            descriptions.append(f"{vuln.get('id','')}: {vuln.get('title', vuln.get('description', ''))}")
                        
                        # Map CVSS to Severity
                        if highest_cvss >= 9.0:
                            sev = "ERROR"
                        elif highest_cvss >= 7.0:
                            sev = "ERROR"
                        elif highest_cvss >= 4.0:
                            sev = "WARNING"
                        else:
                            sev = "INFO"

                        sev_score = {"ERROR": 5, "WARNING": 3, "INFO": 1}.get(sev, 1)
                        sev_score = {"ERROR": 5, "WARNING": 3, "INFO": 1}.get(sev, 1)
                        vuln_text = "\\n".join(descriptions)
                        
                        f_obj = Finding(
                            source="oss_index",
                            title=f"SCA: {dep_info['name']}@{dep_info['version']} (Max CVSS: {highest_cvss})",
                            file=dep_info['file'],
                            line=1,
                            description=f"Vulnerable dependency identified: {dep_info['name']}@{dep_info['version']}\\n{vuln_text}",
                            severity_score=sev_score,
                            mitigation=f"**How To Fix (Mitigation):**\\nUpdate the package `{dep_info['name']}` to the latest secure version in `{os.path.basename(dep_info['file'])}`.\\n\\n*Transitive Dependency Note:* If `{dep_info['name']}` is imported indirectly by another package, you may need to force a resolution override:\\n- **Node** (`package.json`): Use `resolutions` or `overrides` to pin the child version.\\n- **Java** (`pom.xml`): Pin the secure version in a `<dependencyManagement>` block or add an explicit exclude.\\n- **Python** (`requirements.txt`): Explicitly add the secured version of the sub-dependency above the top-level package.",
                            type="SCA"
                        )
                        f_obj.vulnerability_explanation = f"**Why This Component Is Vulnerable:**\\nThe package `{dep_info['name']}` (version {dep_info['version']}) contains known public vulnerabilities with a maximum CVSS context score of **{highest_cvss}**. Operating components with known vulnerabilities exposes the application supply chain to public exploit methods and remote code execution if unchecked."
                        
                        findings.append(f_obj)

            elif res.status_code == 401:
                print("[OSS-Engine] ERROR: Unauthorized API credentials.")
                f_obj = Finding(source="oss_index", title="SCA: Authentication Failed", file="OSS Config", line=1, description="OSS Index API Credentials are invalid (401 Unauthorized). Check your username:token format.", severity_score=5, mitigation="Verify the OSS Token provided in the UI dashboard. Ensure it follows username:token format.", type="SCA")
                f_obj.vulnerability_explanation = "The API credentials provided to Sonatype OSS Index were rejected."
                findings.append(f_obj)
                break
            elif res.status_code == 429:
                print("[OSS-Engine] ERROR: Rate limit exceeded for Sonatype OSS API.")
                f_obj = Finding(source="oss_index", title="SCA: Rate Limited", file="OSS API", line=1, description="OSS Index API unauthenticated rate limit reached.", severity_score=5, mitigation="Wait before scanning again, or provide an API token in the dashboard.", type="SCA")
                f_obj.vulnerability_explanation = "The unauthenticated 64 reqs/hr limit for Sonatype OSS was hit."
                findings.append(f_obj)
                break
            else:
                print(f"[OSS-Engine] HTTP {res.status_code}: {res.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"[OSS-Engine] Network Error: {e}")
            break

    return findings