import sys
import subprocess
import os

# Ensure UTF-8 encoding for subprocesses (fixes Semgrep on Windows)
os.environ["PYTHONIOENCODING"] = "utf-8"

# --- Auto-Dependencies Bootstrap ---
def _ensure_dependencies():
    try:
        import fastapi
        import uvicorn
        import google.genai
        import detect_secrets
    except ImportError:
        print("\n[*] Detected missing dependencies. Auto-installing from requirements.txt...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("[*] Required components successfully installed! Rebooting application...\n")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            print(f"[!] Critical error auto-installing dependencies: {e}")
            print("Please run: pip install -r requirements.txt manually.")
            sys.exit(1)

_ensure_dependencies()
# -----------------------------------

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn
import json
from pathlib import Path

from secure_review import run_secure_review, stop_scan
from export_pdf import export_pdf

app = FastAPI()

# Serve official logo and other images
app.mount("/images", StaticFiles(directory="images"), name="images")
# Serve CSS and other static assets
app.mount("/static", StaticFiles(directory="static"), name="static")

# Allow browser access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CosmoGrepper Dashboard</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
        <div class="header">
            <div class="logo-container">
                <img src="/images/cosmoGepperAI.png" class="logo-img" alt="CosmoGrepperAI">
            </div>
            
            <div style="display:flex; align-items:center; gap:1.2rem; color: var(--text-muted); font-size: 0.9rem;">
                <a href="https://buymeacoffee.com/appsecninja32" target="_blank" style="text-decoration: none; color: var(--primary); font-weight: 500; display: flex; align-items: center; gap: 5px;">
                    ☕ Buy me a coffee
                </a>
                <span id="themeLabel">Dark</span>
                <div id="themeToggle" class="theme-toggle">
                    <div id="themeKnob" class="theme-knob"></div>
                </div>
            </div>
        </div>

        <!-- Language Support Modal -->
        <div id="languageModal" class="modal-overlay" onclick="if(event.target==this) hideLanguageModal()">
            <div class="modal-content">
                <span class="modal-close" onclick="hideLanguageModal()">&times; Close</span>
                <h2 style="margin-top:0; color: var(--primary);">📖 Language Support</h2>
                <p style="color: var(--text-muted); font-size: 0.95rem;">CosmoGrepperAI provides specialized scanning for the following ecosystems:</p>
                <div style="display:grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-top: 1.5rem;">
                    <div class="stat-card" style="padding:1rem; border-radius:12px;">
                        <div class="stat-title">Python</div>
                        <div style="font-size:0.85rem; color:var(--text-muted);">SCA (PIP) + Semgrep Security Audit</div>
                    </div>
                    <div class="stat-card" style="padding:1rem; border-radius:12px;">
                        <div class="stat-title">Java / Kotlin</div>
                        <div style="font-size:0.85rem; color:var(--text-muted);">SCA (Maven/POM) + Semgrep Rulesets</div>
                    </div>
                    <div class="stat-card" style="padding:1rem; border-radius:12px;">
                        <div class="stat-title">JavaScript / TS</div>
                        <div style="font-size:0.85rem; color:var(--text-muted);">SCA (NPM) + Generic JS Security</div>
                    </div>
                    <div class="stat-card" style="padding:1rem; border-radius:12px;">
                        <div class="stat-title">Go / Golang</div>
                        <div style="font-size:0.85rem; color:var(--text-muted);">Native Semgrep + Dynamic exec checks</div>
                    </div>
                    <div class="stat-card" style="padding:1rem; border-radius:12px;">
                        <div class="stat-title">C# / .NET</div>
                        <div style="font-size:0.85rem; color:var(--text-muted);">Semgrep Core + Weak Crypto detection</div>
                    </div>
                    <div class="stat-card" style="padding:1rem; border-radius:12px;">
                        <div class="stat-title">Infrastructure / PHP</div>
                        <div style="font-size:0.85rem; color:var(--text-muted);">Secrets + OWASP Top 10 + Config Audit</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="container">
            <!-- Product Description -->
            <div style="margin-bottom: 1.5rem; padding: 1.2rem 1.5rem; background: rgba(59, 130, 246, 0.06); border: 1px solid rgba(59, 130, 246, 0.15); border-radius: 12px; color: var(--text-muted); font-size: 0.9rem; line-height: 1.6;">
                <strong style="color: var(--text);">COSMO GREPPER AI</strong> uses Semgrep as its scanning core while adding context‑aware intelligence on top. Semgrep supplies the fast, rule‑driven pattern matching, and COSMO GREPPER AI expands those results with LLM reasoning, correlation, and clearer remediation so findings become more meaningful than raw pattern hits.
            </div>

            <!-- Control Panel -->
            <div class="glass-panel" style="margin-bottom: 2rem;">
                <div class="controls-section">
                    <div class="input-group">
                        <label class="input-label" for="path">Target Directory</label>
                        <div style="display:flex; gap:5px; width:100%;">
                            <input type="text" id="path" placeholder="C:\\Projects\\TargetApp..." style="flex: 1; min-width:0;" />
                            <button type="button" class="btn" style="background: rgba(255,255,255,0.1); border: 1px solid var(--glass-border); color: var(--text); padding: 0 1rem; flex-shrink: 0;" onclick="openBrowse()">Browse</button>
                        </div>
                    </div>
                    
                    <div class="input-group">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <label class="input-label" for="ruleset">Active Ruleset</label>
                            <a href="#" onclick="showLanguageModal()" style="font-size: 0.75rem; color: var(--primary); text-decoration: none; font-weight: 500;">📖 Language Support</a>
                        </div>
                        <div style="display:flex; gap:5px; width:100%;">
                            <select id="ruleset" style="flex:1; min-width:0;">
                                <optgroup label="Remote Registries (Powerful)">
                                    <option value="p/default">p/default (All Community Rules - High Noise)</option>
                                    <option value="p/security-audit" selected>p/security-audit (Aggressive Security)</option>
                                    <option value="p/secrets">p/secrets (Dedicated Secrets)</option>
                                    <option value="p/cwe-top-25">p/cwe-top-25 (Top 25 Weaknesses)</option>
                                    <option value="p/owasp-top-ten">p/owasp-top-ten (OWASP Top 10 Models)</option>
                                    <option value="p/javascript">p/javascript (JS/TS Specific)</option>
                                    <option value="p/python">p/python (Python Specific)</option>
                                    <option value="p/java">p/java (Java/Kotlin Specific)</option>
                                    <option value="p/golang">p/golang (Go Specific)</option>
                                </optgroup>
                                <optgroup label="Local Rules">
                                    <option value="expanded_security.yaml">Local: Offline Aggressive Pack</option>
                                    <option value="owasp">Local: OWASP rules dir</option>
                                    <option value="javascript">Local: JS rules dir</option>
                                    <option value="python">Local: Python rules dir</option>
                                </optgroup>
                            </select>
                            <button type="button" id="autoDetectBtn" class="btn" style="background: rgba(59, 130, 246, 0.1); border: 1px solid var(--primary); color: var(--primary); padding: 0 0.8rem; font-size: 0.85rem;" onclick="autoDetectRuleset()">✨ Auto-Detect</button>
                        </div>
                        <span class="input-hint" style="margin-top: 0.3rem; display: block; opacity: 0.9;">✨ Uses AI to analyze project architecture and recommend the most effective ruleset for your stack.</span>
                    </div>

                    <div class="input-group">
                        <label class="input-label" for="llmProvider">LLM Provider</label>
                        <select id="llmProvider">
                            <option value="gemini">Google Gemini (Cloud)</option>
                            <option value="ollama">Ollama (Local /api/generate)</option>
                            <option value="openai">OpenAI (LM Studio / vLLM / Cloud)</option>
                        </select>
                    </div>
                    
                    <div class="input-group">
                        <label class="input-label" for="llmModel">Model Name</label>
                        <div style="display:flex; gap:5px; width:100%;">
                            <select id="llmModel" style="flex:1; min-width:0;" onchange="handleModelChange(this)">
                                <optgroup label="Google Gemini">
                                    <option value="gemini-2.5-flash">gemini-2.5-flash</option>
                                    <option value="gemini-2.0-flash">gemini-2.0-flash</option>
                                    <option value="gemini-1.5-pro">gemini-1.5-pro</option>
                                </optgroup>
                                <optgroup label="Ollama / Local">
                                    <option value="llama3">llama3</option>
                                    <option value="mistral:7b">mistral:7b</option>
                                    <option value="codellama">codellama</option>
                                </optgroup>
                                <optgroup label="OpenAI">
                                    <option value="gpt-4o">gpt-4o</option>
                                    <option value="gpt-3.5-turbo">gpt-3.5-turbo</option>
                                </optgroup>
                                <option value="__custom__">✏️ Custom model name...</option>
                            </select>
                             <button type="button" class="btn" id="testLlmBtn" style="background: rgba(59, 130, 246, 0.2); border: 1px solid var(--primary); color: var(--primary); padding: 0 1rem; flex-shrink:0;" onclick="testLlmConnection(this)">🔌 Test</button>
                        </div>
                        <input type="text" id="llmModelCustom" placeholder="Enter custom model name" style="display:none;" />
                        <span class="input-hint">🔌 Test auto-discovers models from local Ollama/OpenAI endpoints</span>
                    </div>
                    
                    <div class="input-group">
                        <label class="input-label" for="apiKey">LLM Key / URL Endpoint</label>
                        <input type="password" id="apiKey" placeholder="API Key or http://localhost:1234/v1" />
                        <span class="input-hint">Gemini API key, Ollama URL, or OpenAI-compatible endpoint</span>
                    </div>

                    <div class="input-group" style="grid-column: 1 / -1; display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem;">
                        <div class="input-group">
                            <label class="input-label" style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
                                <input type="checkbox" id="enableOss" checked style="width: 1.2rem; height: 1.2rem;">
                                Enable OSS Dependency Scan
                            </label>
                            <span class="input-hint">Checks package.json/requirements.txt via Sonatype OSS Index</span>
                        </div>
                        <div class="input-group">
                            <label class="input-label" for="ossToken">OSS Index Credentials (Optional)</label>
                            <input type="text" id="ossToken" placeholder="username:token (Increases rate limit)" style="font-family: monospace;" />
                        </div>
                    </div>

                        <div class="actions-group" style="display:flex; gap:12px; grid-column: 1 / -1; margin-top: 1rem; border-top: 1px solid var(--glass-border); padding-top: 1.5rem;">
                            <button id="scanBtn" class="btn btn-primary" onclick="runScan()" style="padding: 0.8rem 2.5rem;">
                                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-top:2px"><path d="M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z"></path><path d="M21 21l-4.35-4.35"></path></svg>
                                Initialize Scan
                            </button>
                            
                            <button id="stopBtn" class="btn btn-danger" onclick="stopScan()" style="padding: 0.8rem 2.5rem;">
                                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-top:2px"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="9" y1="9" x2="15" y2="15"></line><line x1="15" y1="9" x2="9" y2="15"></line></svg>
                                Abort
                            </button>
                        </div>
                </div>
                <div class="options-row" style="display:flex; justify-content:space-between; align-items:center; width:100%;">
                    <div>
                        <input type="checkbox" id="skipSecrets" />
                        <label for="skipSecrets" style="margin-right: 15px;">Skip custom secret scanning</label>
                    </div>
                </div>
            </div>

            <div id="errorBanner" class="glass-panel" style="display:none; border-color: var(--danger); background: rgba(239, 68, 68, 0.1); margin-bottom: 2rem; padding: 1rem 1.5rem; position: relative;">
                <div style="display:flex; align-items:center; gap: 12px;">
                    <div style="background: var(--danger); width: 8px; height: 35px; border-radius: 4px;"></div>
                    <div>
                        <div style="font-weight: 700; color: var(--danger); font-size: 1.1rem;">⚠️ SCANNER INTERRUPTED</div>
                        <div id="errorText" style="color: var(--text); font-size: 0.95rem;">An issue was detected during the analysis process.</div>
                    </div>
                </div>
                <button onclick="this.parentElement.style.display='none'" style="position:absolute; top:10px; right:15px; background:none; border:none; color:var(--text-muted); cursor:pointer; font-size:1.2rem;">&times;</button>
            </div>

            <div id="spinner" class="scanning-overlay">
                <div class="radar-spinner"></div>
                <div style="font-weight: 500; font-size: 1.1rem; color: var(--primary);">Scanning Target Assets...</div>
                <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 5px;">Analyzing semantics, evaluating models, correlating findings</div>
            </div>

            <!-- Dashboard Content (hidden until scan) -->
            <div id="dashboardContent" style="display: none;">
                
                <div class="stats-grid">
                    <div class="glass-panel stat-card">
                        <div class="stat-title">Total Findings</div>
                        <div class="stat-value" id="valTotal">0</div>
                    </div>
                    <div class="glass-panel stat-card">
                        <div class="stat-title">Critical / High</div>
                        <div class="stat-value" id="valCrit" style="color: var(--danger);">0</div>
                    </div>
                    <div class="glass-panel stat-card">
                        <div class="stat-title">Secrets Intercepted</div>
                        <div class="stat-value" id="valSecrets" style="color: var(--primary);">0</div>
                    </div>
                    <div class="glass-panel stat-card" style="align-items: center;">
                        <div class="stat-title" style="align-self: flex-start;">Severity Distribution</div>
                        <div class="chart-wrapper">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                </div>

                <div class="filter-container">
                    <input type="text" id="searchBox" placeholder="Search by file, title, or description..." onkeyup="applyFilters()" />
                    <div class="filter-chips">
                        <div class="chip active" onclick="setFilter('all', this)">All Severities</div>
                        <div class="chip" onclick="setFilter(5, this)">Critical</div>
                        <div class="chip" onclick="setFilter(4, this)">High</div>
                        <div class="chip" onclick="setFilter(3, this)">Medium</div>
                        <div class="chip" onclick="setFilter('sca', this)">SCA / OSS</div>
                    </div>
                    <div class="options-row" style="margin-left: auto;">
                        <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
                            <input type="checkbox" id="hideFp" onchange="applyFilters()" checked> 
                            Hide LLM False Positives
                        </label>
                    </div>
                    <button type="button" class="btn" style="background: rgba(234, 179, 8, 0.2); border: 1px solid var(--warning); color: var(--warning); padding: 0.5rem 1rem;" onclick="exportPdf()">
                        📄 Export PDF
                    </button>
                </div>

                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Risk Level</th>
                                <th>Detection Rule</th>
                                <th>Target File</th>
                                <th>Line</th>
                            </tr>
                        </thead>
                        <tbody id="resultsBody">
                            <!-- populated by JS -->
                        </tbody>
                    </table>
                </div>
            </div>
            
        </div>

        <script>
            let findingsCache = [];
            let severityChart = null;
            let scanInProgress = false;
            let severityFilter = "all";

            /* Model Dropdown Handler */
            function handleModelChange(sel) {
                const customInput = document.getElementById('llmModelCustom');
                if (sel.value === '__custom__') {
                    customInput.style.display = 'block';
                    customInput.focus();
                } else {
                    customInput.style.display = 'none';
                    customInput.value = '';
                }
            }
            function getSelectedModel() {
                const sel = document.getElementById('llmModel');
                if (sel.value === '__custom__') {
                    return document.getElementById('llmModelCustom').value;
                }
                return sel.value;
            }

            /* Theme Management */
            const savedTheme = localStorage.getItem("theme") || "dark";
            if (savedTheme === "light") {
                document.body.classList.add("light");
                document.getElementById("themeLabel").innerText = "Light";
            }
            
            document.getElementById("themeToggle").onclick = () => {
                const isLight = document.body.classList.toggle("light");
                localStorage.setItem("theme", isLight ? "light" : "dark");
                document.getElementById("themeLabel").innerText = isLight ? "Light" : "Dark";
            };

            async function openBrowse() {
                try {
                     const res = await fetch('/browse?t=' + Date.now());
                     if (!res.ok) {
                         return alert(`WARNING: The server threw a ${res.status} error! You are likely running an OLD cached server process! Please close your terminal and run 'python app.py' again!`);
                     }
                     
                     const data = await res.json();
                     if (data.path) {
                         document.getElementById('path').value = data.path;
                     } else {
                         alert("Failed to fetch path. Check your taskbar to make sure the Folder Select window hasn't popped up BEHIND your browser!");
                     }
                } catch(e) {
                     alert("Fatal Javascript Error: Please fully restart your app.py terminal server. An old cached version is blocking the new APIs from working!");
                }
            }

            function showLanguageModal() { document.getElementById('languageModal').style.display = 'flex'; }
            function hideLanguageModal() { document.getElementById('languageModal').style.display = 'none'; }

            async function autoDetectRuleset() {
                const path = document.getElementById('path').value;
                if (!path) return alert("Please specify a directory first.");

                const btn = document.getElementById('autoDetectBtn');
                const oldText = btn.innerText;
                btn.innerText = "⏳ Detecting...";
                btn.disabled = true;

                try {
                    const params = new URLSearchParams({
                        path: path,
                        provider: document.getElementById('llmProvider').value,
                        model: getSelectedModel(),
                        api_key: document.getElementById('apiKey').value
                    });
                    const res = await fetch('/analyze_path?' + params);
                    const data = await res.json();
                    if (data.recommended_ruleset) {
                        document.getElementById('ruleset').value = data.recommended_ruleset;
                        alert("✨ AI Analysis complete! Recommended ruleset: " + data.recommended_ruleset);
                    }
                } catch(e) {
                    alert("AI Auto-detection failed. Ensure your LLM is configured correctly.");
                } finally {
                    btn.innerText = oldText;
                    btn.disabled = false;
                }
            }

            async function exportPdf() {
                const path = document.getElementById('path').value;
                if (!path) return alert("Please specify a target path to scan before exporting.");
                
                const params = new URLSearchParams({
                    path: path,
                    skip_secrets: document.getElementById('skipSecrets').checked,
                    ruleset: document.getElementById('ruleset').value,
                    llm_provider: document.getElementById('llmProvider').value,
                    llm_model: getSelectedModel(),
                    api_key: document.getElementById('apiKey') ? document.getElementById('apiKey').value : "",
                    enable_oss: document.getElementById('enableOss').checked,
                    oss_token: document.getElementById('ossToken').value
                });
                
                window.open('/pdf?' + params.toString(), '_blank');
            }

             async function testLlmConnection(btn) {
                if (!btn) btn = document.getElementById('testLlmBtn');
                const originalHtml = btn.innerHTML;
                
                const provider = document.getElementById('llmProvider').value;
                const apiKeyUrl = document.getElementById('apiKey').value;
                
                if (provider === "gemini") {
                    return alert("Test connection only scans local Ollama/OpenAI architectures for models dynamically. Try a manual scan to test Gemini keys!");
                }
                
                try {
                    btn.disabled = true;
                    btn.innerHTML = "⏳ Testing...";
                    
                    const res = await fetch(`/llm/test?provider=${provider}&endpoint=${encodeURIComponent(apiKeyUrl)}&t=${Date.now()}`);
                    if (!res.ok) {
                         return alert(`WARNING: Handshake failed (HTTP ${res.status})!`);
                    }
                    
                    const data = await res.json();
                    
                    if (data.status === "ok") {
                        if (data.models && data.models.length > 0) {
                            const sel = document.getElementById('llmModel');
                            // Add discovered models as a new optgroup
                            let existingDiscovered = sel.querySelector('optgroup[label="Discovered Models"]');
                            if (existingDiscovered) existingDiscovered.remove();
                            const grp = document.createElement('optgroup');
                            grp.label = 'Discovered Models';
                            data.models.forEach(m => {
                                const opt = document.createElement('option');
                                opt.value = m;
                                opt.textContent = m;
                                grp.appendChild(opt);
                            });
                            sel.insertBefore(grp, sel.firstChild);
                            sel.value = data.models[0]; // auto-select first discovered model
                            handleModelChange(sel);
                            alert(`Success! Found ${data.models.length} local models.`);
                        } else {
                            alert("Connected, but no downloaded models were found.");
                        }
                    } else {
                        alert("Connection failed:\\n" + data.status);
                    }
                } catch(e) {
                    alert("FATAL ERROR: Connection failed.");
                } finally {
                    btn.disabled = false;
                    btn.innerHTML = originalHtml;
                }
            }

            /* Scan Execution */
             async function runScan() {
                if (scanInProgress) return;
                const path = document.getElementById('path').value;
                if (!path) {
                    showErrorBanner("Please specify a target path to scan before initializing.");
                    return;
                }

                scanInProgress = true;
                document.getElementById('errorBanner').style.display = "none";
                document.getElementById('spinner').style.display = "block";
                document.getElementById('dashboardContent').style.display = "none";
                document.getElementById('stopBtn').style.display = "inline-flex";
                document.getElementById('scanBtn').style.display = "none";

                try {
                    const params = new URLSearchParams({
                        path: path,
                        skip_secrets: document.getElementById('skipSecrets').checked,
                        ruleset: document.getElementById('ruleset').value,
                        llm_provider: document.getElementById('llmProvider').value,
                        llm_model: getSelectedModel(),
                        api_key: document.getElementById('apiKey') ? document.getElementById('apiKey').value : "",
                        enable_oss: document.getElementById('enableOss').checked,
                        oss_token: document.getElementById('ossToken').value
                    });
                    
                    const res = await fetch('/scan?' + params);
                    const data = await res.json();
                    
                    if (data.findings) {
                        findingsCache = data.findings;
                        document.getElementById('dashboardContent').style.display = "block";
                        
                        // Check for high-level runtime errors from backends
                        const systemErrors = data.findings.filter(f => f.type === "Runtime Error" || f.source === "oss_index" && f.title.includes("Failed"));
                        if (systemErrors.length > 0) {
                             showErrorBanner(systemErrors[0].description);
                        } else if (data.findings.length === 0) {
                             showSuccessBanner("Scan completed successfully, but zero vulnerabilities were identified in the target path.");
                        }
                        
                        applyFilters();
                    } else if (data.detail) {
                        throw new Error(data.detail);
                    }
                } catch (err) {
                    console.error(err);
                    showErrorBanner("FATAL ERROR during scan: " + err.message);
                } finally {
                    scanInProgress = false;
                    document.getElementById('spinner').style.display = "none";
                    document.getElementById('stopBtn').style.display = "none";
                    document.getElementById('scanBtn').style.display = "inline-flex";
                }
            }

            async function stopScan() {
                await fetch('/stop');
                alert("Abort signal sent.");
            }

            /* Filtering Logic */
            window.setFilter = function(val, el) {
                severityFilter = val;
                document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
                el.classList.add('active');
                applyFilters();
            };

            window.applyFilters = function() {
                const query = document.getElementById("searchBox").value.toLowerCase();
                const hideFp = document.getElementById("hideFp").checked;
                const filtered = findingsCache.filter(f => {
                    let matchSev = false;
                    if (severityFilter === "all") matchSev = true;
                    else if (severityFilter === "sca") matchSev = (f.type === "SCA");
                    else matchSev = (f.severity_score === severityFilter);

                    const matchText = f.title.toLowerCase().includes(query) || 
                                      f.file.toLowerCase().includes(query) || 
                                      (f.description && f.description.toLowerCase().includes(query));
                    const matchFp = !hideFp || !f.false_positive;
                    return matchSev && matchText && matchFp;
                });
                renderDashboard(filtered);
            };

            /* Render Dashboard */
            function renderDashboard(findings) {
                // Sort by risk score descending
                findings.sort((a, b) => (b.risk ? b.risk.risk_score : 0) - (a.risk ? a.risk.risk_score : 0));
                
                // Update stats
                let counts = [0,0,0,0,0,0];
                let secrets = 0;
                findings.forEach(f => {
                    counts[f.severity_score] = (counts[f.severity_score] || 0) + 1;
                    if (f.source === "secret-llm" || f.title.toLowerCase().includes("secret") || f.title.toLowerCase().includes("key")) {
                        secrets++;
                    }
                });

                document.getElementById('valTotal').innerText = findings.length;
                document.getElementById('valCrit').innerText = counts[5] + counts[4];
                document.getElementById('valSecrets').innerText = secrets;

                // Update chart
                const chartColors = [
                    'rgba(100, 116, 139, 0.8)', // 0 (None)
                    'rgba(100, 116, 139, 0.8)', // 1
                    'rgba(59, 130, 246, 0.8)',  // 2
                    'rgba(234, 179, 8, 0.8)',   // 3
                    'rgba(249, 115, 22, 0.8)',  // 4
                    'rgba(239, 68, 68, 0.8)'    // 5
                ];

                if (severityChart) severityChart.destroy();
                
                const ctx = document.getElementById('severityChart').getContext('2d');
                Chart.defaults.color = 'rgba(148, 163, 184, 0.8)';
                severityChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ["Info", "Low", "Medium", "High", "Critical"],
                        datasets: [{
                            data: [counts[1], counts[2], counts[3], counts[4], counts[5]],
                            backgroundColor: chartColors.slice(1),
                            borderWidth: 0,
                            hoverOffset: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '75%',
                        plugins: {
                            legend: { display: false }
                        }
                    }
                });

                // Update table
                const tbody = document.getElementById('resultsBody');
                let html = "";
                
                const sevLabels = {
                    5: "Critical",
                    4: "High",
                    3: "Medium",
                    2: "Low",
                    1: "Info",
                    0: "None"
                };

                findings.forEach((f, i) => {
                    const rowId = `desc-${i}`;
                    const sevClass = `sev-${f.severity_score}`;
                    const label = sevLabels[f.severity_score];
                    
                    const isFp = f.false_positive;
                    const fpStyle = isFp ? "opacity: 0.6; filter: grayscale(1);" : "";
                    const fpBadge = isFp ? `<span class="badge" style="background:#475569; margin-left:8px;">False Positive</span>` : "";
                    const fpReasonHtml = isFp ? `<div style="margin-top:1rem; padding:1rem; background:rgba(239, 68, 68, 0.1); border-left:4px solid var(--danger); border-radius:4px;"><b style="color:var(--danger)">LLM FP Verdict:</b> ${f.fp_reason}</div>` : "";
                    
                    // Vulnerability explanation (why it's dangerous)
                    const vulnExplainHtml = f.vulnerability_explanation && f.vulnerability_explanation.trim() !== "" 
                        ? `<div style="margin-top:1rem; padding:1rem; background:rgba(249, 115, 22, 0.1); border-left:4px solid #f97316; border-radius:4px;">
                            <b style="color:#f97316; font-size: 0.95rem;">⚠ Why This Code Is Vulnerable:</b>
                            <div style="margin-top:0.5rem; line-height:1.6; color: var(--text);">${f.vulnerability_explanation.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\\n/g, "<br>")}</div>
                          </div>` 
                        : "";
                    
                    // Mitigation advice (how to fix it)
                    const mitigationHtml = f.mitigation && f.mitigation.trim() !== "" 
                        ? `<div style="margin-top:1rem; padding:1rem; background:rgba(16, 185, 129, 0.1); border-left:4px solid var(--success); border-radius:4px;">
                            <b style="color:var(--success); font-size: 0.95rem;">✅ How To Fix (Mitigation):</b>
                            <pre style="margin-top:0.5rem; white-space: pre-wrap; word-wrap: break-word;"><code>${f.mitigation.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</code></pre>
                          </div>` 
                        : "";
                    
                    html += `
                        <tr class="main-row" onclick="toggleRow('${rowId}')" style="${fpStyle}">
                            <td><span class="badge ${sevClass}">${label}</span>${fpBadge}</td>
                            <td style="font-weight: 500;">${f.title}</td>
                            <td style="font-family: monospace; font-size: 0.85rem; color: var(--text-muted);">${f.file}</td>
                            <td>${f.line}</td>
                        </tr>
                        <tr id="${rowId}" class="details-row">
                            <td colspan="4" style="padding: 0;">
                                <div class="details-content">
                                    <div style="margin-bottom: 1.2rem; color: var(--text-muted); line-height: 1.5;">
                                        ${f.description}
                                    </div>
                                    
                                    <div class="info-grid">
                                        <div class="info-item">
                                            <span class="info-label">OWASP Category</span>
                                            <span class="info-val">${f.owasp ? f.owasp.top10_category : 'N/A'}</span>
                                        </div>
                                        <div class="info-item">
                                            <span class="info-label">CVSS Base Score</span>
                                            <span class="info-val">${f.cvss ? f.cvss.base_score : 'N/A'}</span>
                                        </div>
                                        <div class="info-item">
                                            <span class="info-label">Risk Score</span>
                                            <span class="info-val" style="color:var(--danger); font-weight:700;">${f.risk ? f.risk.risk_score.toFixed(2) : '0.0'}</span>
                                        </div>
                                    </div>

                                    <div class="info-label" style="margin-bottom: 0.5rem;">Evidence (Snippet)</div>
                                    <pre><code>${(f.snippet || "No source code available").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</code></pre>
                                    ${fpReasonHtml}
                                    ${vulnExplainHtml}
                                    ${mitigationHtml}
                                </div>
                            </td>
                        </tr>
                    `;
                });
                
                if(findings.length === 0) {
                    html = `<tr><td colspan="4" style="text-align:center; padding: 2rem; color: var(--text-muted);">No vulnerabilities found matching current filters.</td></tr>`;
                }
                
                tbody.innerHTML = html;
            }

            window.toggleRow = function(id) {
                const el = document.getElementById(id);
                if(el.style.display === "table-row") {
                    el.style.display = "none";
                } else {
                    document.querySelectorAll('.details-row').forEach(r => r.style.display = 'none');
                    el.style.display = "table-row";
                }
            };

            /* Banner Helpers */
            function showErrorBanner(msg) {
                const banner = document.getElementById('errorBanner');
                const text = document.getElementById('errorText');
                if (!banner || !text) return;
                
                const indicator = banner.querySelector('div[style*="background: var(--danger)"]');
                const title = banner.querySelector('div[style*="color: var(--danger)"]');

                text.innerText = msg;
                banner.style.display = "block";
                banner.style.borderColor = "var(--danger)";
                banner.style.background = "rgba(239, 68, 68, 0.1)";
                if (indicator) indicator.style.background = "var(--danger)";
                if (title) {
                    title.innerText = "⚠️ SCANNER INTERRUPTED";
                    title.style.color = "var(--danger)";
                }
            }

            function showSuccessBanner(msg) {
                const banner = document.getElementById('errorBanner');
                const text = document.getElementById('errorText');
                if (!banner || !text) return;

                const indicator = banner.querySelector('div[style*="background: var(--danger)"]');
                const title = banner.querySelector('div[style*="color: var(--danger)"]');

                text.innerText = msg;
                banner.style.display = "block";
                banner.style.borderColor = "var(--success)";
                banner.style.background = "rgba(16, 185, 129, 0.1)";
                if (indicator) indicator.style.background = "var(--success)";
                if (title) {
                    title.innerText = "✅ SCAN COMPLETED (CLEAN)";
                    title.style.color = "var(--success)";
                }
            }
        </script>
    </body>
    </html>
    """
@app.get("/scan")
def scan(path: str, skip_secrets: bool = False, ruleset: str = "owasp", llm_provider: str = "gemini", llm_model: str = "", api_key: str = "", enable_oss: bool = False, oss_token: str = ""):
    report = run_secure_review(path, skip_secrets=skip_secrets, ruleset=ruleset, llm_provider=llm_provider, llm_model=llm_model, api_key=api_key, enable_oss=enable_oss, oss_token=oss_token)
    return JSONResponse(report)


@app.get("/browse")
def browse():
    import subprocess, os, platform
    from pathlib import Path
    
    # Cross-platform home directory
    home_docs = str(Path.home() / "Documents")
    
    system = platform.system()
    try:
        if system == "Windows":
            # Use modern CommonOpenFileDialog-style via PowerShell
            ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.FolderBrowserDialog
$f.Description = 'Select Target Directory to Scan'
$f.ShowNewFolderButton = $false
$f.SelectedPath = '{home_docs}'
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.StartPosition = 'CenterScreen'
$owner.WindowState = 'Minimized'
$owner.Show()
$owner.BringToFront()
if($f.ShowDialog($owner) -eq 'OK'){{ $f.SelectedPath }}
$owner.Close()
"""
            cmd = ["powershell", "-Command", ps_script]
            folder_path = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=120).strip()
            return {"path": folder_path}
            
        elif system == "Darwin": # macOS
            # Use AppleScript to pick a folder
            as_script = f'tell application "System Events" to activate\nPOSIX path of (choose folder with prompt "Select Target Directory to Scan" default location "{home_docs}")'
            cmd = ["osascript", "-e", as_script]
            folder_path = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=120).strip()
            return {"path": folder_path}
            
        else: # Linux or other
            return {"path": "", "error": "Native browsing not supported on this OS. Please enter path manually."}
            
    except Exception as e:
        print(f"[Browse Error] {e}")
        return {"path": ""}

@app.get("/analyze_path")
def analyze_path(path: str, provider: str = "gemini", model: str = "", api_key: str = ""):
    from llm_engine import auto_detect_ruleset
    rec = auto_detect_ruleset(path, api_key, provider, model)
    return {"recommended_ruleset": rec}

@app.get("/llm/test")
def test_llm(provider: str, endpoint: str):
    models = []
    status = "error"
    try:
        import requests
        if provider == "ollama":
            url = endpoint if "http" in endpoint else "http://localhost:11434"
            url = url.rstrip('/') + '/api/tags'
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                models = [m.get("name") for m in res.json().get("models", [])]
                status = "ok"
            else:
                status = f"HTTP {res.status_code}"
        elif provider == "openai":
            url = endpoint if "http" in endpoint else "http://localhost:1234/v1"
            url = url.rstrip('/') + '/models'
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                models = [m.get("id") for m in res.json().get("data", [])]
                status = "ok"
            else:
                status = f"HTTP {res.status_code}"
        else:
            status = "gemini does not support dynamic listing"
    except Exception as e:
        status = str(e)
    
    return {"status": status, "models": models}


@app.get("/stop")
def stop():
    stopped = stop_scan()
    return {"stopped": stopped}


@app.get("/pdf")
def pdf(path: str, skip_secrets: bool = False, ruleset: str = "owasp", llm_provider: str = "gemini", llm_model: str = "", api_key: str = "", enable_oss: bool = False, oss_token: str = ""):
    report = run_secure_review(path, skip_secrets=skip_secrets, ruleset=ruleset, llm_provider=llm_provider, llm_model=llm_model, api_key=api_key, enable_oss=enable_oss, oss_token=oss_token)

    temp_json = "temp_report.json"
    temp_pdf = "report.pdf"

    Path(temp_json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    export_pdf(temp_json, temp_pdf)

    return FileResponse(
        temp_pdf,
        media_type="application/pdf",
        filename="report.pdf"
    )
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)