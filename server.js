/**
 * ═══════════════════════════════════════════════════════════════
 *  BlueShell Terminal Server
 *  Threat Intelligence & Blue Team Operations Platform
 * ═══════════════════════════════════════════════════════════════
 *
 *  SETUP INSTRUCTIONS:
 *  -------------------
 *  1. Install dependencies:
 *       npm install
 *
 *  2. (Optional) Install node-pty for a better terminal experience:
 *       npm install node-pty
 *     Note: node-pty requires build tools (Python, C++ compiler).
 *     On Windows: npm install --global windows-build-tools
 *     The server works fine without it using child_process fallback.
 *
 *  3. Start the server:
 *       npm start
 *       # or: node server.js
 *
 *  4. Open in browser:
 *       http://localhost:3000
 *
 *  ENVIRONMENT VARIABLES:
 *  ----------------------
 *  PORT          - Server port (default: 3000)
 *  SHELL         - Shell executable override
 *  TERM_COLS     - Default terminal columns (default: 120)
 *  TERM_ROWS     - Default terminal rows (default: 30)
 */

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const os = require('os');

// ── Attempt to load optional dependencies ──────────────────────

let pty = null;
try {
    pty = require('node-pty');
    console.log('[+] node-pty loaded - using PTY for terminal sessions');
} catch (e) {
    console.log('[*] node-pty not available - using child_process fallback');
    console.log('    Install with: npm install node-pty (optional, requires build tools)');
}

let WebSocketServer;
try {
    ({ WebSocketServer } = require('ws'));
} catch (e) {
    console.error('[!] FATAL: ws package not installed. Run: npm install ws');
    process.exit(1);
}

// ── Configuration ──────────────────────────────────────────────

const PORT = parseInt(process.env.PORT, 10) || 3000;
const DEFAULT_COLS = parseInt(process.env.TERM_COLS, 10) || 120;
const DEFAULT_ROWS = parseInt(process.env.TERM_ROWS, 10) || 30;
const STATIC_ROOT = __dirname;

const DEFAULT_SHELL = os.platform() === 'win32' ? 'cmd.exe' : (process.env.SHELL || '/bin/bash');
const SHELL = process.env.SHELL_OVERRIDE || DEFAULT_SHELL;

// ── MIME Types ─────────────────────────────────────────────────

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css':  'text/css; charset=utf-8',
    '.js':   'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif':  'image/gif',
    '.svg':  'image/svg+xml',
    '.ico':  'image/x-icon',
    '.woff': 'font/woff',
    '.woff2':'font/woff2',
    '.ttf':  'font/ttf',
    '.otf':  'font/otf',
    '.map':  'application/json',
    '.txt':  'text/plain; charset=utf-8',
    '.md':   'text/plain; charset=utf-8',
    '.xml':  'application/xml',
    '.pdf':  'application/pdf',
    '.yml':  'text/yaml; charset=utf-8',
    '.yaml': 'text/yaml; charset=utf-8',
};

function getMimeType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return MIME_TYPES[ext] || 'application/octet-stream';
}

// ── Session Tracking ───────────────────────────────────────────

const sessions = new Map();
let sessionIdCounter = 0;

function getSessionCount() {
    return sessions.size;
}

// ── Static File Server ─────────────────────────────────────────

function serveStatic(req, res) {
    // Only allow GET and HEAD
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { 'Content-Type': 'text/plain' });
        res.end('Method Not Allowed');
        return;
    }

    let urlPath = req.url.split('?')[0].split('#')[0];
    urlPath = decodeURIComponent(urlPath);

    // Default to index.html
    if (urlPath === '/') {
        urlPath = '/index.html';
    }

    // Security: prevent directory traversal
    const safePath = path.normalize(urlPath).replace(/^(\.\.[\/\\])+/, '');
    const filePath = path.join(STATIC_ROOT, safePath);

    // Ensure resolved path is within static root
    if (!filePath.startsWith(STATIC_ROOT)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
    }

    fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
            // Try with .html extension
            const htmlPath = filePath + '.html';
            fs.stat(htmlPath, (err2, stats2) => {
                if (err2 || !stats2.isFile()) {
                    res.writeHead(404, { 'Content-Type': 'text/plain' });
                    res.end('404 Not Found');
                    return;
                }
                streamFile(htmlPath, stats2, res);
            });
            return;
        }
        streamFile(filePath, stats, res);
    });
}

function streamFile(filePath, stats, res) {
    const mimeType = getMimeType(filePath);
    res.writeHead(200, {
        'Content-Type': mimeType,
        'Content-Length': stats.size,
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
    });
    fs.createReadStream(filePath).pipe(res);
}

// ── HTTP Server ────────────────────────────────────────────────

const server = http.createServer(serveStatic);

// ── WebSocket Server ───────────────────────────────────────────

const wss = new WebSocketServer({ server, path: '/terminal' });

wss.on('connection', (ws, req) => {
    const sessionId = ++sessionIdCounter;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`[+] Terminal session #${sessionId} opened from ${clientIp} (${getSessionCount() + 1} active)`);

    let shellProcess = null;
    let alive = true;

    // ── Create shell process ──

    function createShell(cols, rows) {
        cols = cols || DEFAULT_COLS;
        rows = rows || DEFAULT_ROWS;

        if (pty) {
            // ── node-pty mode (full PTY support) ──
            try {
                const shell = pty.spawn(SHELL, [], {
                    name: 'xterm-256color',
                    cols: cols,
                    rows: rows,
                    cwd: os.homedir(),
                    env: Object.assign({}, process.env, {
                        TERM: 'xterm-256color',
                        COLORTERM: 'truecolor',
                    }),
                });

                shell.onData((data) => {
                    if (alive && ws.readyState === ws.OPEN) {
                        ws.send(JSON.stringify({ type: 'output', data: data }));
                    }
                });

                shell.onExit(({ exitCode, signal }) => {
                    console.log(`[*] Session #${sessionId} shell exited (code=${exitCode}, signal=${signal})`);
                    if (alive && ws.readyState === ws.OPEN) {
                        ws.send(JSON.stringify({ type: 'exit', code: exitCode }));
                        ws.close();
                    }
                    cleanup();
                });

                return shell;
            } catch (err) {
                console.error(`[!] PTY spawn failed for session #${sessionId}:`, err.message);
                console.log('[*] Falling back to child_process...');
                return createChildProcessShell(cols, rows);
            }
        } else {
            return createChildProcessShell(cols, rows);
        }
    }

    function createChildProcessShell(cols, rows) {
        // ── child_process fallback ──
        const isWindows = os.platform() === 'win32';
        const shellCmd = isWindows ? 'cmd.exe' : (process.env.SHELL || '/bin/bash');
        const shellArgs = isWindows ? [] : ['--login'];

        const shell = spawn(shellCmd, shellArgs, {
            cwd: os.homedir(),
            env: Object.assign({}, process.env, {
                TERM: 'xterm-256color',
                COLUMNS: String(cols),
                LINES: String(rows),
            }),
            stdio: ['pipe', 'pipe', 'pipe'],
            windowsHide: true,
        });

        shell._isPty = false;

        shell.stdout.on('data', (data) => {
            if (alive && ws.readyState === ws.OPEN) {
                ws.send(JSON.stringify({ type: 'output', data: data.toString('utf-8') }));
            }
        });

        shell.stderr.on('data', (data) => {
            if (alive && ws.readyState === ws.OPEN) {
                ws.send(JSON.stringify({ type: 'output', data: data.toString('utf-8') }));
            }
        });

        shell.on('exit', (code, signal) => {
            console.log(`[*] Session #${sessionId} shell exited (code=${code}, signal=${signal})`);
            if (alive && ws.readyState === ws.OPEN) {
                ws.send(JSON.stringify({ type: 'exit', code: code }));
                ws.close();
            }
            cleanup();
        });

        shell.on('error', (err) => {
            console.error(`[!] Session #${sessionId} shell error:`, err.message);
            if (alive && ws.readyState === ws.OPEN) {
                ws.send(JSON.stringify({ type: 'error', message: err.message }));
                ws.close();
            }
            cleanup();
        });

        return shell;
    }

    // ── Initialize shell ──

    shellProcess = createShell(DEFAULT_COLS, DEFAULT_ROWS);

    sessions.set(sessionId, { ws, shell: shellProcess, createdAt: Date.now() });

    // Send session info to client
    ws.send(JSON.stringify({
        type: 'connected',
        sessionId: sessionId,
        shell: SHELL,
        hasPty: pty !== null,
        platform: os.platform(),
    }));

    // ── Handle incoming messages ──

    ws.on('message', (rawMsg) => {
        if (!alive) return;

        let msg;
        try {
            msg = JSON.parse(rawMsg.toString());
        } catch (e) {
            // Treat raw text as input
            msg = { type: 'input', data: rawMsg.toString() };
        }

        switch (msg.type) {
            case 'input':
                if (shellProcess) {
                    // Update last activity for timeout tracking
                    const session = sessions.get(sessionId);
                    if (session) session.lastActivity = Date.now();

                    if (pty && shellProcess.write) {
                        shellProcess.write(msg.data);
                    } else if (shellProcess.stdin && shellProcess.stdin.writable) {
                        shellProcess.stdin.write(msg.data);
                    }
                }
                break;

            case 'resize':
                if (shellProcess && pty && typeof shellProcess.resize === 'function') {
                    try {
                        const cols = Math.max(1, Math.min(500, parseInt(msg.cols, 10) || DEFAULT_COLS));
                        const rows = Math.max(1, Math.min(200, parseInt(msg.rows, 10) || DEFAULT_ROWS));
                        shellProcess.resize(cols, rows);
                    } catch (e) {
                        // Resize not supported in child_process fallback
                    }
                }
                break;

            case 'ping':
                if (ws.readyState === ws.OPEN) {
                    ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
                }
                break;

            default:
                break;
        }
    });

    // ── Handle disconnect ──

    ws.on('close', () => {
        console.log(`[-] Terminal session #${sessionId} closed (${getSessionCount() - 1} active)`);
        cleanup();
    });

    ws.on('error', (err) => {
        console.error(`[!] WebSocket error on session #${sessionId}:`, err.message);
        cleanup();
    });

    // ── Cleanup ──

    function cleanup() {
        if (!alive) return;
        alive = false;
        sessions.delete(sessionId);

        if (shellProcess) {
            try {
                if (pty && typeof shellProcess.kill === 'function') {
                    shellProcess.kill();
                } else if (shellProcess.kill) {
                    shellProcess.kill('SIGTERM');
                    // Force kill after 3 seconds if still running
                    setTimeout(() => {
                        try { shellProcess.kill('SIGKILL'); } catch (e) { /* already dead */ }
                    }, 3000);
                }
            } catch (e) {
                // Process already terminated
            }
            shellProcess = null;
        }
    }
});

// ── Health Check Endpoint ──────────────────────────────────────

const originalHandler = server.listeners('request')[0];
server.removeAllListeners('request');
server.on('request', (req, res) => {
    // CORS headers for local development
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    if (req.url === '/api/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: 'ok',
            uptime: process.uptime(),
            sessions: getSessionCount(),
            hasPty: pty !== null,
            platform: os.platform(),
            shell: SHELL,
            timestamp: Date.now(),
        }));
        return;
    }

    // ── AI Detection Generator API ──────────────────────────
    if (req.url === '/api/generate-detection' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            try {
                const { ruleName, context, platformFocus, mode } = JSON.parse(body);
                if (!ruleName) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'ruleName is required' }));
                    return;
                }

                // ── SIEM-Only Prompt Template ──────────────────────
                const SIEM_PROMPT_TEMPLATE = `You are a senior SOC analyst and detection engineer.

Your task is to generate a complete, production-ready SIEM detection rule.

Rule Name: {{RULE_NAME}}

Context (use this knowledge while generating rule):
{{CONTEXT_DATA}}
- Windows Event ID 4624 = Successful login
- Logon Type 10 = Remote Interactive (RDP)
- Event ID 4625 = Failed login
- Event ID 4672 = Privileged login
- Event ID 5140 = SMB share access
- MITRE ATT&CK T1021 = Remote Services (Lateral Movement)
- MITRE ATT&CK T1059 = Command Execution (PowerShell etc.)

Instructions:
- Generate practical SOC-level detection (NOT generic)
- Use real-world attack patterns
- Correlate multiple logs if applicable
- Prefer detection engineering mindset

{{PLATFORM_FOCUS}}

IMPORTANT: Return valid JSON only with these keys:
{
  "ruleName": "string",
  "description": "string",
  "mitre": [{"id": "string", "name": "string", "tactic": "string"}],
  "severity": "string",
  "severityReason": "string",
  "logSources": [{"source": "string", "eventId": "string", "purpose": "string"}],
  "detectionLogic": ["string (step-by-step)"],
  "splunkSPL": "string",
  "sentinelKQL": "string",
  "thresholds": {"events": number, "window": "string", "note": "string"},
  "falsePositives": ["string"],
  "investigationSteps": ["string"],
  "responseActions": ["string"],
  "tuning": ["string"]
}
Return ONLY valid JSON. No markdown, no explanation, no code fences.`;

                // Platform-specific context injection
                function getPlatformContext(platform) {
                    switch (platform) {
                        case 'CrowdStrike':
                            return `Focus more on: CrowdStrike Falcon
- Generate CrowdStrike-specific IOA (Indicator of Attack) behavioral rules
- Include CrowdStrike IOC (hash, IP, domain) blocklist entries
- Include CrowdStrike Falcon prevention policy recommendations
- Use CrowdStrike RTR (Real Time Response) commands for containment
- Reference CrowdStrike Event Search queries (Falcon LQL)
- Map to CrowdStrike Falcon detection categories
- Include Falcon SOAR (Fusion workflows) automation steps`;
                        case 'Splunk':
                            return `Focus more on: Splunk Enterprise Security
- Prioritize SPL (Search Processing Language) queries
- Include Splunk ES Notable Event creation
- Include Splunk Adaptive Response actions
- Reference Splunk CIM (Common Information Model) field names
- Include Risk-Based Alerting (RBA) risk score assignments
- Map to Splunk ES MITRE ATT&CK framework app`;
                        case 'Microsoft Sentinel':
                            return `Focus more on: Microsoft Sentinel
- Prioritize KQL (Kusto Query Language) analytics rules
- Include Sentinel Analytic Rule YAML format
- Include Logic App / Automation Rules for SOAR
- Reference Microsoft Defender XDR tables (DeviceProcessEvents, etc.)
- Include Sentinel Workbook visualizations
- Map to Sentinel MITRE ATT&CK blade`;
                        case 'Elastic SIEM':
                            return `Focus more on: Elastic Security
- Prioritize EQL (Event Query Language) and KQL queries
- Include Elastic Detection Rule TOML format
- Include Elastic Agent Fleet integration
- Reference ECS (Elastic Common Schema) field names
- Include Machine Learning anomaly detection jobs`;
                        case 'Palo Alto Cortex XDR':
                            return `Focus more on: Palo Alto Cortex XDR
- Prioritize XQL (XDR Query Language) queries
- Include BIOC (Behavioral IOC) rule definitions
- Include Cortex XSOAR playbook automation
- Reference Cortex XDR Analytics alert categories
- Map to Cortex XDR MITRE ATT&CK module`;
                        case 'QRadar':
                            return `Focus more on: IBM QRadar
- Prioritize AQL (Ariel Query Language) queries
- Include QRadar Custom Rule Engine (CRE) definitions
- Include QRadar SOAR playbook steps
- Reference QRadar DSM event properties
- Map to QRadar offense categorization`;
                        case 'Wazuh':
                            return `Focus more on: Wazuh
- Prioritize Wazuh XML rule format
- Include Wazuh Active Response scripts
- Include Wazuh FIM (File Integrity Monitoring) rules
- Reference Wazuh Syscheck and SCA modules
- Map to Wazuh MITRE ATT&CK module`;
                        default:
                            return '';
                    }
                }

                const platformCtx = getPlatformContext(platformFocus);

                // ── Master Prompt Template ──────────────────────────
                // {{RULE_NAME}} and {{CONTEXT_DATA}} get replaced at runtime
                const MASTER_PROMPT_TEMPLATE = `You are a senior SOC analyst, detection engineer, and security automation expert.

Your task is to generate a complete security detection and response solution.

Rule Name: {{RULE_NAME}}

Context:
{{CONTEXT_DATA}}

Instructions:
- Think like a real SOC (Detection + Response + Endpoint + Correlation)
- Cover SIEM, EDR, SOAR, and XDR aspects
- Use MITRE ATT&CK framework
- Avoid generic answers
- Be technical and concise
- Include real-world attack patterns (NOT generic)
- Correlate multiple logs where possible
- Include endpoint behavior (process, command-line, parent-child)
- Include automation and response actions

{{PLATFORM_FOCUS}}

Output format:

========================
1. Rule Name

2. Description
- Clear explanation of attack and detection goal

========================
3. MITRE ATT&CK Mapping
- Technique ID
- Tactic

========================
4. Severity
- Low / Medium / High / Critical (with reason)

========================
5. SIEM Detection
- Log Sources (Event IDs, firewall, cloud logs, etc.)
- Detection Logic (step-by-step correlation)
- Queries:
   - Splunk SPL
   - KQL (Microsoft Sentinel)

========================
6. EDR Detection
- Process behavior
- Command-line patterns
- Parent-child process relationships
- File/registry/network indicators
- IOA (behavior-based detection)
- IOC (IP, domain, hash)

========================
7. XDR Correlation
- Multi-source correlation (Endpoint + Network + Identity)
- Attack chain mapping (initial access → execution → lateral movement)
- Timeline-based detection

========================
8. SOAR Playbook (Automation)
- Trigger condition
- Automated actions:
   - Isolate host
   - Disable user account
   - Block IP/domain
   - Kill process
- Approval steps (if needed)

========================
9. Detection Conditions
- Threshold (number of events)
- Time window

========================
10. False Positives
- Realistic scenarios

========================
11. Investigation Steps
- What SOC analyst should check step-by-step

========================
12. Response Actions (Manual + Automated)

========================
13. Tuning Recommendations

IMPORTANT: Return the output as valid JSON with these keys:
{
  "ruleName": "string",
  "description": "string",
  "mitre": [{"id": "string", "name": "string", "tactic": "string"}],
  "severity": "string",
  "severityReason": "string",
  "logSources": [{"source": "string", "eventId": "string", "purpose": "string"}],
  "splunkSPL": "string",
  "sentinelKQL": "string",
  "edrProcess": "string",
  "edrParentChild": "string",
  "edrCmdIndicators": ["string"],
  "ioa": ["string"],
  "falsePositives": ["string"],
  "soarTrigger": "string",
  "soarActions": ["string"],
  "thresholds": {"events": number, "window": "string", "note": "string"},
  "investigationSteps": ["string"],
  "tuning": ["string"],
  "xdrCorrelation": "string",
  "responseManual": ["string"],
  "responseAutomated": ["string"]
}
Return ONLY valid JSON. No markdown, no explanation, no code fences.`;

                // ── Build Context Data ──────────────────────────────
                // Combine smart context + base context
                const baseContext = `- Windows Event ID 4624 = Successful login
- Logon Type 10 = Remote Interactive (RDP)
- Event ID 4625 = Failed login
- Event ID 4672 = Privileged login
- Event ID 5140 = SMB share access
- PowerShell Event ID 4104 = Script execution
- MITRE ATT&CK T1021 = Remote Services (Lateral Movement)
- MITRE ATT&CK T1059 = Command Execution`;

                const fullContext = (context || '') + '\n' + baseContext;

                // ── Select Template Based on Mode ───────────────────
                // mode: "siem" = SIEM-only rule | "full" (default) = Full SIEM+EDR+SOAR+XDR
                const selectedTemplate = (mode === 'siem')
                    ? SIEM_PROMPT_TEMPLATE
                    : MASTER_PROMPT_TEMPLATE;

                // ── Replace Template Placeholders ───────────────────
                const DETECTION_PROMPT = selectedTemplate
                    .replace('{{RULE_NAME}}', ruleName)
                    .replace('{{CONTEXT_DATA}}', fullContext.trim())
                    .replace('{{PLATFORM_FOCUS}}', platformCtx);

                // Check for ANTHROPIC_API_KEY
                const apiKey = process.env.ANTHROPIC_API_KEY;

                if (apiKey) {
                    // Call Claude API
                    const https = require('https');
                    const postData = JSON.stringify({
                        model: 'claude-sonnet-4-20250514',
                        max_tokens: 4000,
                        temperature: 0.2,
                        messages: [{ role: 'user', content: DETECTION_PROMPT }]
                    });

                    const apiReq = https.request({
                        hostname: 'api.anthropic.com',
                        path: '/v1/messages',
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'x-api-key': apiKey,
                            'anthropic-version': '2023-06-01',
                            'Content-Length': Buffer.byteLength(postData)
                        }
                    }, (apiRes) => {
                        let data = '';
                        apiRes.on('data', chunk => { data += chunk; });
                        apiRes.on('end', () => {
                            try {
                                const parsed = JSON.parse(data);
                                const content = parsed.content?.[0]?.text || '{}';
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ source: 'claude-api', data: JSON.parse(content) }));
                            } catch (e) {
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ source: 'claude-api-raw', data: data }));
                            }
                        });
                    });

                    apiReq.on('error', (e) => {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ source: 'local', message: 'API unavailable, use local generation', prompt: DETECTION_PROMPT }));
                    });

                    apiReq.write(postData);
                    apiReq.end();
                } else {
                    // No API key — return prompt for local generation
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        source: 'local',
                        message: 'No ANTHROPIC_API_KEY set. Using local generation engine. Set env var to enable Claude API.',
                        prompt: DETECTION_PROMPT
                    }));
                }
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid JSON body' }));
            }
        });
        return;
    }

    if (req.url === '/api/info') {
        const { execSync } = require('child_process');
        let nodeVer = process.version;
        let npmVer = 'N/A';
        let claudeVer = 'N/A';
        try { npmVer = execSync('npm --version', { timeout: 3000 }).toString().trim(); } catch (e) {}
        try { claudeVer = execSync('claude --version', { timeout: 3000 }).toString().trim(); } catch (e) {}
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            os: `${os.type()} ${os.release()}`,
            arch: os.arch(),
            hostname: os.hostname(),
            shell: SHELL,
            hasPty: pty !== null,
            node: nodeVer,
            npm: npmVer,
            claude: claudeVer,
            memory: `${Math.round(os.freemem() / 1024 / 1024)}MB free / ${Math.round(os.totalmem() / 1024 / 1024)}MB total`,
            cpus: os.cpus().length,
            uptime: Math.round(os.uptime()) + 's',
        }));
        return;
    }

    originalHandler(req, res);
});

// ── Session Timeout (30 min idle) ────────────────────────────────

setInterval(() => {
    const now = Date.now();
    const TIMEOUT = 30 * 60 * 1000; // 30 minutes
    for (const [id, session] of sessions) {
        if (now - (session.lastActivity || session.createdAt) > TIMEOUT) {
            console.log(`[*] Session #${id} timed out (idle > 30 min)`);
            try {
                if (session.ws.readyState === session.ws.OPEN) {
                    session.ws.send(JSON.stringify({ type: 'error', message: 'Session timed out (30 min idle)' }));
                    session.ws.close(1000, 'Session timeout');
                }
            } catch (e) {}
        }
    }
}, 60000); // Check every minute

// ── Start Server ───────────────────────────────────────────────

server.listen(PORT, () => {
    console.log('');
    console.log('  ╔══════════════════════════════════════════════╗');
    console.log('  ║   BlueShell Terminal Server                  ║');
    console.log('  ║   Threat Intelligence & Blue Team Ops        ║');
    console.log('  ╠══════════════════════════════════════════════╣');
    console.log(`  ║   URL:      http://localhost:${PORT}             ║`);
    console.log(`  ║   Shell:    ${SHELL.padEnd(33)}║`);
    console.log(`  ║   PTY:      ${(pty ? 'YES (node-pty)' : 'NO (child_process fallback)').padEnd(33)}║`);
    console.log(`  ║   Platform: ${os.platform().padEnd(33)}║`);
    console.log('  ╚══════════════════════════════════════════════╝');
    console.log('');
});

// ── Graceful Shutdown ──────────────────────────────────────────

function shutdown(signal) {
    console.log(`\n[*] Received ${signal}. Shutting down gracefully...`);

    // Close all terminal sessions
    for (const [id, session] of sessions) {
        console.log(`[*] Closing session #${id}...`);
        try {
            if (session.ws.readyState === session.ws.OPEN) {
                session.ws.send(JSON.stringify({ type: 'shutdown', message: 'Server shutting down' }));
                session.ws.close(1001, 'Server shutting down');
            }
        } catch (e) { /* ignore */ }

        try {
            if (session.shell) {
                if (pty && typeof session.shell.kill === 'function') {
                    session.shell.kill();
                } else if (session.shell.kill) {
                    session.shell.kill('SIGTERM');
                }
            }
        } catch (e) { /* ignore */ }
    }
    sessions.clear();

    // Close WebSocket server
    wss.close(() => {
        console.log('[*] WebSocket server closed');
        // Close HTTP server
        server.close(() => {
            console.log('[*] HTTP server closed');
            console.log('[+] Shutdown complete.');
            process.exit(0);
        });
    });

    // Force exit after 5 seconds
    setTimeout(() => {
        console.log('[!] Forced shutdown after timeout');
        process.exit(1);
    }, 5000);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// Handle Windows Ctrl+C
if (os.platform() === 'win32') {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin });
    rl.on('SIGINT', () => shutdown('SIGINT'));
}

process.on('uncaughtException', (err) => {
    console.error('[!] Uncaught exception:', err);
});

process.on('unhandledRejection', (reason) => {
    console.error('[!] Unhandled rejection:', reason);
});
