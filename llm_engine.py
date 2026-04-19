import json
import requests
import re

try:
    from google import genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

def analyze_false_positives(findings, api_key: str, llm_provider: str = "gemini", llm_model: str = ""):
    if not findings:
        return findings

    # Only abort if using gemini and missing API key
    if llm_provider == "gemini" and not api_key:
        return findings

    if llm_provider == "gemini" and not HAS_GENAI:
        print("[!] Warning: google-genai is not installed. LLM analysis skipped. Run 'pip install google-genai' to enable.")
        return findings

    gemini_model_name = llm_model if llm_model else "gemini-2.0-flash"
    ollama_model_name = llm_model if llm_model else "llama3"

    client = None
    if llm_provider == "gemini":
        client = genai.Client(api_key=api_key)
    else:
        # Default Ollama URL if none provided in the API key field
        ollama_url = api_key if "http" in api_key else "http://localhost:11434"
        ollama_endpoint = f"{ollama_url}/api/generate"
    
    for f in findings:
        # Only run on Medium, High, Critical to save time
        if f.severity_score < 3:
            continue
        
        if not f.snippet or f.snippet == "Unable to extract snippet" or f.snippet == "No source code available":
            continue
            
        prompt = f"""You are an elite Application Security engineer performing a code review.
Analyze the following security finding detected by Semgrep and provide a comprehensive developer-focused assessment.

FINDING DETAILS:
- Rule: {f.title}
- Description: {f.description}
- File: {f.file}
- Line: {f.line}

SOURCE CODE:
```
{f.snippet}
```

You MUST return a valid JSON object with EXACTLY these fields:

{{
  "false_positive": boolean,
  "justification": "1-2 sentence explanation of why this is or is not a false positive",
  "vulnerability_explanation": "A dense, elite developer-friendly explanation of WHY this code is vulnerable. Explain the exact attack vector, what makes this specific code pattern dangerous, and the potential blast radius.",
  "mitigation": "Provide the EXACT corrected code block that fixes this vulnerability. If it requires an architectural change, write out the new code structure. If this is an SCA/Dependency finding, outline exactly how to update the transitive tree in Maven, NPM, or PIP. No vague advice."
}}

IMPORTANT RULES:
- vulnerability_explanation should reference the ACTUAL variable names and function calls from the code
- mitigation MUST include working replacement code, not just advice
- If the code uses subprocess with shell=True, show the exact fix with shell=False
- If the code has SQL injection, show parameterized query replacement
- Be specific and actionable - a junior developer should be able to copy-paste your fix
"""
        
        def _parse_llm_json(raw_text):
            t = raw_text.strip()
            if t.startswith("```"):
                t = re.sub(r"^```(?:json)?", "", t)
                t = re.sub(r"```$", "", t)
            return json.loads(t.strip())
            
        try:
            if llm_provider == "gemini":
                response = client.models.generate_content(
                    model=gemini_model_name,
                    contents=prompt,
                    config={"response_mime_type": "application/json"}
                )
                data = _parse_llm_json(response.text)
            elif llm_provider == "ollama":
                payload = {
                    "model": ollama_model_name,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                }
                res = requests.post(ollama_endpoint, json=payload, timeout=60)
                if res.status_code == 200:
                    data = _parse_llm_json(res.json().get("response", "{}"))
                else:
                    print(f"Ollama error: {res.status_code}")
                    continue
            else:
                # OpenAI / LM Studio logic
                openai_url = api_key if "http" in api_key else "https://api.openai.com/v1"
                openai_endpoint = f"{openai_url}/chat/completions"
                headers = {"Authorization": f"Bearer {api_key if 'http' not in api_key else 'dummy'}", "Content-Type": "application/json"}
                
                payload = {
                    "model": ollama_model_name if llm_model else "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.0,
                    "response_format": {"type": "json_object"}
                }
                res = requests.post(openai_endpoint, json=payload, headers=headers, timeout=60)
                if res.status_code == 200:
                    content_str = res.json()["choices"][0]["message"]["content"]
                    data = _parse_llm_json(content_str)
                else:
                    print(f"OpenAI Compatible Error: {res.status_code} - {res.text}")
                    continue

            if isinstance(data, dict):
                f.false_positive = data.get("false_positive", False)
                f.fp_reason = data.get("justification", "No justification provided by AI.")
                f.vulnerability_explanation = data.get("vulnerability_explanation", "")
                f.mitigation = data.get("mitigation", f.mitigation)  # Keep existing if LLM returns empty
                print(f"      [LLM] Evaluated {f.title} -> FP: {f.false_positive} | Has explanation: {bool(f.vulnerability_explanation)} | Has mitigation: {bool(f.mitigation)}")
        except Exception as e:
            print(f"      [LLM ERROR] Engine failed on {f.title}: {e}")
            pass
            
    return findings

def auto_detect_ruleset(path: str, api_key: str, llm_provider: str, llm_model: str) -> str:
    """Uses LLM to recommend the best ruleset based on file extensions."""
    import os
    from collections import Counter
    
    if not os.path.exists(path):
        return "p/security-audit"
        
    exts = []
    # Fast scan of top levels
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '.venv']]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext: exts.append(ext)
            
    if not exts:
        return "p/security-audit"
        
    counts = Counter(exts)
    top_exts = dict(counts.most_common(10))
    prompt = f"""You are a static analysis expert configuring Semgrep. 
Look at the most common file extensions in this project:
{json.dumps(top_exts)}

Which of the following Semgrep rulesets is the BEST match to scan this repository natively?
Options:
- p/java (For Java/Kotlin)
- p/python (For Python)
- p/javascript (For JS/TS/Node)
- p/golang (For Go)
- p/default (Generic mixed bag)
- p/security-audit (Aggressive core security, good for C/C++ or mixed unknown)

Respond ONLY with the exact string of the chosen ruleset option (e.g. "p/python"), nothing else.
"""
    try:
        if llm_provider == "gemini" and HAS_GENAI and api_key:
            client = genai.Client(api_key=api_key)
            model_name = llm_model if llm_model else "gemini-2.5-flash"
            response = client.models.generate_content(model=model_name, contents=prompt)
            rec = response.text.strip().replace("`", "").replace('"', '')
            if rec.startswith("p/"): return rec
            
        elif llm_provider in ["ollama", "openai"]:
            url = api_key if "http" in api_key else "http://localhost:11434"
            ep = f"{url}/api/generate" if llm_provider == "ollama" else f"{url}/v1/chat/completions"
            model_name = llm_model if llm_model else ("llama3" if llm_provider == "ollama" else "gpt-3.5-turbo")
            
            if llm_provider == "ollama":
                payload = {"model": model_name, "prompt": prompt, "stream": False}
                res = requests.post(ep, json=payload, timeout=10)
                if res.status_code == 200:
                    rec = res.json().get("response", "").strip().replace("`", "")
                    if rec.startswith("p/"): return rec
            else:
                payload = {"model": model_name, "messages": [{"role": "user", "content": prompt}]}
                headers = {"Content-Type": "application/json"}
                if "api.openai" in url:
                    headers["Authorization"] = f"Bearer {api_key}"
                res = requests.post(ep, json=payload, headers=headers, timeout=10)
                if res.status_code == 200:
                    rec = res.json()["choices"][0]["message"]["content"].strip().replace("`", "")
                    if rec.startswith("p/"): return rec
    except Exception as e:
        print(f"[Auto-Detect Error] {e}")
        
    return "p/security-audit"