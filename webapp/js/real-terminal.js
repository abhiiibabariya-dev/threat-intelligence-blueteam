/**
 * ═══════════════════════════════════════════════════════════════
 *  BlueShell Real Terminal - Frontend WebSocket Terminal Client
 *  Threat Intelligence & Blue Team Operations Platform
 * ═══════════════════════════════════════════════════════════════
 *
 *  This module upgrades the existing simulated terminal to a real
 *  shell terminal when the BlueShell server (server.js) is running.
 *
 *  BACKWARDS COMPATIBLE: If the server is not running, the original
 *  simulated terminal continues to work exactly as before.
 *
 *  Load this script AFTER app.js in index.html:
 *    <script src="js/real-terminal.js"></script>
 */

(function () {
    'use strict';

    // ── State ──────────────────────────────────────────────────

    let ws = null;
    let isRealTerminal = false;
    let isConnecting = false;
    let reconnectTimer = null;
    let reconnectAttempts = 0;
    let sessionInfo = null;
    let commandHistory = [];
    let historyIndex = -1;
    let currentInputBuffer = '';
    let serverAvailable = null; // null = unknown, true/false

    const MAX_RECONNECT_ATTEMPTS = 10;
    const RECONNECT_BASE_DELAY = 1000;
    const RECONNECT_MAX_DELAY = 15000;
    const HEALTH_CHECK_INTERVAL = 30000;
    const MAX_SCROLLBACK = 5000; // max terminal lines before trimming
    const WS_URL = `ws://${window.location.hostname || 'localhost'}:${window.location.port || '3000'}/terminal`;
    const HEALTH_URL = `http://${window.location.hostname || 'localhost'}:${window.location.port || '3000'}/api/health`;

    // ── Save original functions ────────────────────────────────

    const _originalToggleTerminal = window.toggleTerminal;
    const _originalExecuteCommand = window.executeCommand;

    // ── ANSI Parser ────────────────────────────────────────────
    //
    // Handles common ANSI escape sequences and converts them to
    // styled HTML spans. Supports SGR (Select Graphic Rendition)
    // codes for colors, bold, underline, etc.

    const ANSI_COLORS = {
        // Standard foreground
        30: '#000000', 31: '#ff3333', 32: '#00ff41', 33: '#ffcc00',
        34: '#00aaff', 35: '#a855f7', 36: '#00d4ff', 37: '#c9d1d9',
        // Bright foreground
        90: '#666666', 91: '#ff6b6b', 92: '#69ff69', 93: '#ffee88',
        94: '#66bbff', 95: '#cc88ff', 96: '#66eeff', 97: '#ffffff',
        // Standard background
        40: '#000000', 41: '#cc0000', 42: '#00aa00', 43: '#ccaa00',
        44: '#0055aa', 45: '#880088', 46: '#00aaaa', 47: '#aaaaaa',
        // Bright background
        100: '#555555', 101: '#ff5555', 102: '#55ff55', 103: '#ffff55',
        104: '#5555ff', 105: '#ff55ff', 106: '#55ffff', 107: '#ffffff',
    };

    function parseAnsi(text) {
        // Escape HTML entities first
        let html = text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');

        // Track current style state
        let currentStyles = {};
        let result = '';
        let openSpans = 0;

        // Split on ANSI escape sequences: ESC[ ... m
        const parts = html.split(/(\x1b\[[0-9;]*m)/);

        for (const part of parts) {
            const match = part.match(/^\x1b\[([0-9;]*)m$/);
            if (match) {
                // Close any existing span
                if (openSpans > 0) {
                    result += '</span>';
                    openSpans--;
                }

                const codes = (match[1] || '0').split(';').map(Number);
                for (const code of codes) {
                    if (code === 0) {
                        // Reset
                        currentStyles = {};
                    } else if (code === 1) {
                        currentStyles.bold = true;
                    } else if (code === 2) {
                        currentStyles.dim = true;
                    } else if (code === 3) {
                        currentStyles.italic = true;
                    } else if (code === 4) {
                        currentStyles.underline = true;
                    } else if (code === 7) {
                        currentStyles.inverse = true;
                    } else if (code === 9) {
                        currentStyles.strikethrough = true;
                    } else if (code === 22) {
                        delete currentStyles.bold;
                        delete currentStyles.dim;
                    } else if (code === 23) {
                        delete currentStyles.italic;
                    } else if (code === 24) {
                        delete currentStyles.underline;
                    } else if (code === 27) {
                        delete currentStyles.inverse;
                    } else if (code === 29) {
                        delete currentStyles.strikethrough;
                    } else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97)) {
                        currentStyles.color = ANSI_COLORS[code];
                    } else if (code === 39) {
                        delete currentStyles.color;
                    } else if ((code >= 40 && code <= 47) || (code >= 100 && code <= 107)) {
                        currentStyles.background = ANSI_COLORS[code];
                    } else if (code === 49) {
                        delete currentStyles.background;
                    }
                }

                // Open new span with accumulated styles
                const styleStr = buildStyleString(currentStyles);
                if (styleStr) {
                    result += `<span style="${styleStr}">`;
                    openSpans++;
                }
            } else if (part) {
                // Strip other escape sequences (cursor movement, etc.)
                const cleaned = part.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '')
                                    .replace(/\x1b\][^\x07]*\x07/g, '')   // OSC sequences
                                    .replace(/\x1b\[[\?]?[0-9;]*[hl]/g, '') // Mode set/reset
                                    .replace(/\x1b[()][0-9A-Za-z]/g, '')  // Character set
                                    .replace(/\x1b/g, '');                // Stray ESC
                result += cleaned;
            }
        }

        // Close remaining spans
        while (openSpans > 0) {
            result += '</span>';
            openSpans--;
        }

        return result;
    }

    function buildStyleString(styles) {
        const parts = [];
        if (styles.color) parts.push(`color:${styles.color}`);
        if (styles.background) parts.push(`background-color:${styles.background}`);
        if (styles.bold) parts.push('font-weight:bold');
        if (styles.dim) parts.push('opacity:0.6');
        if (styles.italic) parts.push('font-style:italic');
        if (styles.underline) parts.push('text-decoration:underline');
        if (styles.strikethrough) parts.push('text-decoration:line-through');
        if (styles.inverse) {
            // Swap color and background
            const fg = styles.background || '#0a0e17';
            const bg = styles.color || '#c9d1d9';
            parts.push(`color:${fg};background-color:${bg}`);
        }
        return parts.join(';');
    }

    // ── Terminal DOM Helpers ────────────────────────────────────

    function getTerminalBody() {
        return document.getElementById('terminal-body');
    }

    function getTerminalInput() {
        return document.getElementById('terminal-input');
    }

    function getTerminalInputLine() {
        const input = getTerminalInput();
        return input ? input.closest('.terminal-input-line') : null;
    }

    function appendToTerminal(html) {
        const body = getTerminalBody();
        if (!body) return;
        body.insertAdjacentHTML('beforeend', html);

        // Trim scrollback if too long
        while (body.children.length > MAX_SCROLLBACK) {
            body.removeChild(body.firstChild);
        }

        body.scrollTop = body.scrollHeight;
    }

    function clearTerminal() {
        const body = getTerminalBody();
        if (body) body.innerHTML = '';
    }

    function appendOutputLine(text) {
        const parsed = parseAnsi(text);
        appendToTerminal(`<div class="terminal-line"><span class="output">${parsed}</span></div>`);
    }

    function appendSystemLine(text, cssClass) {
        cssClass = cssClass || 'output';
        appendToTerminal(
            `<div class="terminal-line"><span class="${cssClass}">${escapeHtmlSafe(text)}</span></div>`
        );
    }

    function escapeHtmlSafe(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ── Real Terminal Mode Switching ───────────────────────────

    function updateStatusIndicator(status) {
        const dot = document.getElementById('terminal-status-dot');
        const text = document.getElementById('terminal-status-text');
        if (dot) {
            dot.className = 'terminal-status-dot ' + status;
        }
        if (text) {
            const labels = { connected: 'LIVE SHELL', disconnected: 'SIMULATED', connecting: 'CONNECTING...' };
            text.textContent = labels[status] || status.toUpperCase();
        }
    }

    function switchToRealMode() {
        if (isRealTerminal) return;
        isRealTerminal = true;

        const body = getTerminalBody();
        const inputLine = getTerminalInputLine();
        const input = getTerminalInput();

        if (body) {
            body.innerHTML = '';
        }

        // In real terminal mode, hide the input line - we capture keys directly
        if (inputLine) {
            inputLine.style.display = 'none';
        }

        // Make terminal body focusable for key capture
        if (body) {
            body.setAttribute('tabindex', '0');
            body.style.cursor = 'text';
            body.addEventListener('click', focusTerminalBody);
        }

        // Update terminal header to show real mode
        const header = document.querySelector('.terminal-header span');
        if (header) {
            header.textContent = `blueshell@soc:~$ [LIVE SHELL${sessionInfo ? ' #' + sessionInfo.sessionId : ''}]`;
        }

        updateStatusIndicator('connected');
        attachRealKeyHandler();
    }

    function switchToSimulatedMode() {
        if (!isRealTerminal) return;
        isRealTerminal = false;

        const body = getTerminalBody();
        const inputLine = getTerminalInputLine();

        if (body) {
            body.removeAttribute('tabindex');
            body.style.cursor = '';
            body.removeEventListener('click', focusTerminalBody);
        }

        // Show input line again
        if (inputLine) {
            inputLine.style.display = '';
        }

        // Restore terminal header
        const header = document.querySelector('.terminal-header span');
        if (header) {
            header.textContent = 'blueshell@soc:~$';
        }

        updateStatusIndicator('disconnected');
        detachRealKeyHandler();

        // Add a message about fallback
        appendSystemLine('[BlueShell] Switched to simulated terminal mode', 'typed');
    }

    function focusTerminalBody() {
        const body = getTerminalBody();
        if (body) body.focus();
    }

    // ── Key Handler for Real Terminal ──────────────────────────

    let _keyHandler = null;

    function attachRealKeyHandler() {
        detachRealKeyHandler();

        _keyHandler = function (e) {
            if (!isRealTerminal || !ws || ws.readyState !== WebSocket.OPEN) return;

            // Don't capture if terminal is hidden
            const terminal = document.getElementById('terminal');
            if (!terminal || terminal.classList.contains('hidden')) return;

            // Allow browser shortcuts (Ctrl+C copies when there is a selection,
            // but send SIGINT when there is no selection)
            if (e.ctrlKey && e.key === 'c') {
                const selection = window.getSelection();
                if (selection && selection.toString().length > 0) {
                    return; // Allow copy
                }
                // Send SIGINT (Ctrl+C = \x03)
                sendToTerminal('\x03');
                e.preventDefault();
                return;
            }

            // Ctrl key combos
            if (e.ctrlKey) {
                const ctrlMap = {
                    'a': '\x01', 'b': '\x02', 'd': '\x04', 'e': '\x05',
                    'f': '\x06', 'k': '\x0b', 'l': '\x0c', 'n': '\x0e',
                    'p': '\x10', 'r': '\x12', 'u': '\x15', 'w': '\x17',
                    'z': '\x1a',
                };
                if (ctrlMap[e.key.toLowerCase()]) {
                    sendToTerminal(ctrlMap[e.key.toLowerCase()]);
                    e.preventDefault();
                    return;
                }
                // Let other Ctrl combos pass through to browser
                return;
            }

            // Alt key - let browser handle
            if (e.altKey) return;

            e.preventDefault();

            // Special keys
            switch (e.key) {
                case 'Enter':
                    sendToTerminal('\r');
                    break;
                case 'Backspace':
                    sendToTerminal('\x7f');
                    break;
                case 'Tab':
                    sendToTerminal('\t');
                    break;
                case 'Escape':
                    sendToTerminal('\x1b');
                    break;
                case 'ArrowUp':
                    sendToTerminal('\x1b[A');
                    break;
                case 'ArrowDown':
                    sendToTerminal('\x1b[B');
                    break;
                case 'ArrowRight':
                    sendToTerminal('\x1b[C');
                    break;
                case 'ArrowLeft':
                    sendToTerminal('\x1b[D');
                    break;
                case 'Home':
                    sendToTerminal('\x1b[H');
                    break;
                case 'End':
                    sendToTerminal('\x1b[F');
                    break;
                case 'Insert':
                    sendToTerminal('\x1b[2~');
                    break;
                case 'Delete':
                    sendToTerminal('\x1b[3~');
                    break;
                case 'PageUp':
                    sendToTerminal('\x1b[5~');
                    break;
                case 'PageDown':
                    sendToTerminal('\x1b[6~');
                    break;
                case 'F1':  sendToTerminal('\x1bOP');  break;
                case 'F2':  sendToTerminal('\x1bOQ');  break;
                case 'F3':  sendToTerminal('\x1bOR');  break;
                case 'F4':  sendToTerminal('\x1bOS');  break;
                case 'F5':  sendToTerminal('\x1b[15~'); break;
                case 'F6':  sendToTerminal('\x1b[17~'); break;
                case 'F7':  sendToTerminal('\x1b[18~'); break;
                case 'F8':  sendToTerminal('\x1b[19~'); break;
                case 'F9':  sendToTerminal('\x1b[20~'); break;
                case 'F10': sendToTerminal('\x1b[21~'); break;
                case 'F11': sendToTerminal('\x1b[23~'); break;
                case 'F12': sendToTerminal('\x1b[24~'); break;
                case 'Shift':
                case 'Control':
                case 'Alt':
                case 'Meta':
                case 'CapsLock':
                case 'NumLock':
                case 'ScrollLock':
                    // Modifier keys alone - ignore
                    break;
                default:
                    // Printable character
                    if (e.key.length === 1) {
                        sendToTerminal(e.key);
                    }
                    break;
            }
        };

        document.addEventListener('keydown', _keyHandler, true);
    }

    function detachRealKeyHandler() {
        if (_keyHandler) {
            document.removeEventListener('keydown', _keyHandler, true);
            _keyHandler = null;
        }
    }

    // ── WebSocket Connection ───────────────────────────────────

    function connectWebSocket() {
        if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
            return; // Already connected or connecting
        }
        if (isConnecting) return;
        isConnecting = true;

        updateStatusIndicator('connecting');

        try {
            ws = new WebSocket(WS_URL);
        } catch (e) {
            isConnecting = false;
            handleConnectionFailure();
            return;
        }

        ws.onopen = function () {
            isConnecting = false;
            reconnectAttempts = 0;
            console.log('[BlueShell] WebSocket connected');

            switchToRealMode();

            // Send initial resize based on terminal dimensions
            sendResize();
        };

        ws.onmessage = function (event) {
            let msg;
            try {
                msg = JSON.parse(event.data);
            } catch (e) {
                handleTerminalOutput(event.data);
                return;
            }

            switch (msg.type) {
                case 'connected':
                    sessionInfo = msg;
                    const mode = msg.hasPty ? 'PTY' : 'pipe';
                    appendOutputLine(`\x1b[32m[BlueShell]\x1b[0m Connected to ${msg.shell} (${mode}) on ${msg.platform} — Session #${msg.sessionId}`);
                    appendOutputLine('');

                    // Update header with session info
                    const header = document.querySelector('.terminal-header span');
                    if (header) {
                        header.textContent = `blueshell@soc:~$ [LIVE SHELL #${msg.sessionId}]`;
                    }
                    break;

                case 'output':
                    handleTerminalOutput(msg.data);
                    break;

                case 'exit':
                    appendOutputLine(`\x1b[33m[BlueShell]\x1b[0m Shell exited with code ${msg.code}`);
                    break;

                case 'error':
                    appendOutputLine(`\x1b[31m[BlueShell Error]\x1b[0m ${msg.message}`);
                    break;

                case 'shutdown':
                    appendOutputLine(`\x1b[33m[BlueShell]\x1b[0m Server shutting down...`);
                    switchToSimulatedMode();
                    break;

                case 'pong':
                    // Keepalive response
                    break;
            }
        };

        ws.onclose = function (event) {
            isConnecting = false;
            console.log('[BlueShell] WebSocket closed:', event.code, event.reason);

            if (isRealTerminal) {
                appendOutputLine(`\x1b[33m[BlueShell]\x1b[0m Connection lost. Attempting to reconnect...`);
            }

            ws = null;
            sessionInfo = null;
            scheduleReconnect();
        };

        ws.onerror = function (error) {
            isConnecting = false;
            console.log('[BlueShell] WebSocket error');
            // onclose will fire after this
        };
    }

    function disconnectWebSocket() {
        clearReconnectTimer();
        reconnectAttempts = MAX_RECONNECT_ATTEMPTS; // prevent auto-reconnect

        if (ws) {
            ws.close(1000, 'User disconnect');
            ws = null;
        }
        sessionInfo = null;
    }

    // ── Send Data ──────────────────────────────────────────────

    function sendToTerminal(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'input', data: data }));
        }
    }

    function sendResize() {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;

        const body = getTerminalBody();
        if (!body) return;

        // Estimate cols/rows from terminal body dimensions
        const charWidth = 7.8;  // approximate monospace char width at default font size
        const charHeight = 18;  // approximate line height
        const cols = Math.floor(body.clientWidth / charWidth) || 120;
        const rows = Math.floor(body.clientHeight / charHeight) || 30;

        ws.send(JSON.stringify({ type: 'resize', cols: cols, rows: rows }));
    }

    // ── Handle Terminal Output ─────────────────────────────────

    function handleTerminalOutput(data) {
        if (!data) return;

        const body = getTerminalBody();
        if (!body) return;

        // Split by newlines, handling \r\n and \r
        const lines = data.split(/\r?\n|\r/);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            // Get or create the last line element for appending
            let lastLine = body.lastElementChild;

            if (i === 0 && lastLine && lastLine.classList.contains('terminal-line-live')) {
                // Append to existing live line (continuation of partial output)
                const parsed = parseAnsi(line);
                lastLine.insertAdjacentHTML('beforeend', parsed);
            } else {
                // Create a new line
                const div = document.createElement('div');
                div.className = 'terminal-line terminal-line-live';
                div.innerHTML = parseAnsi(line);
                body.appendChild(div);
            }
        }

        // Trim scrollback
        while (body.children.length > MAX_SCROLLBACK) {
            body.removeChild(body.firstChild);
        }

        body.scrollTop = body.scrollHeight;
    }

    // ── Reconnection Logic ─────────────────────────────────────

    function scheduleReconnect() {
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            console.log('[BlueShell] Max reconnect attempts reached. Falling back to simulated terminal.');
            switchToSimulatedMode();
            serverAvailable = false;
            return;
        }

        const delay = Math.min(
            RECONNECT_BASE_DELAY * Math.pow(1.5, reconnectAttempts),
            RECONNECT_MAX_DELAY
        );
        reconnectAttempts++;

        console.log(`[BlueShell] Reconnecting in ${Math.round(delay / 1000)}s (attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
        clearReconnectTimer();
        reconnectTimer = setTimeout(() => {
            connectWebSocket();
        }, delay);
    }

    function clearReconnectTimer() {
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
    }

    function handleConnectionFailure() {
        serverAvailable = false;
        console.log('[BlueShell] Server not available. Using simulated terminal.');
    }

    // ── Health Check ───────────────────────────────────────────

    function checkServerHealth() {
        return fetch(HEALTH_URL, { method: 'GET', cache: 'no-cache' })
            .then(function (res) {
                if (res.ok) {
                    serverAvailable = true;
                    return res.json();
                }
                throw new Error('Server returned ' + res.status);
            })
            .catch(function () {
                serverAvailable = false;
                return null;
            });
    }

    // ── Override toggleTerminal ────────────────────────────────

    window.toggleTerminal = function () {
        const terminal = document.getElementById('terminal');
        const wasHidden = terminal.classList.contains('hidden');

        // Call original toggle
        if (typeof _originalToggleTerminal === 'function') {
            _originalToggleTerminal();
        }

        // If we just opened the terminal
        if (wasHidden) {
            if (serverAvailable === null) {
                // First time opening - check if server is available
                checkServerHealth().then(function (health) {
                    if (health) {
                        connectWebSocket();
                    } else {
                        // Server not running, use simulated mode
                        console.log('[BlueShell] Server not detected. Using simulated terminal.');
                        appendSystemLine('[BlueShell] Real terminal server not detected.', 'typed');
                        appendSystemLine('[BlueShell] To enable real shell, run:', 'typed');
                        appendSystemLine('  cd ' + (window.location.pathname.includes('webapp') ? '..' : '.'), 'output');
                        appendSystemLine('  npm install && npm start', 'output');
                        appendSystemLine('[BlueShell] Then refresh this page. Simulated terminal is active.', 'typed');
                        appendSystemLine('', 'output');
                        const input = getTerminalInput();
                        if (input) input.focus();
                    }
                });
            } else if (serverAvailable) {
                if (!ws || ws.readyState !== WebSocket.OPEN) {
                    reconnectAttempts = 0;
                    connectWebSocket();
                }
                if (isRealTerminal) {
                    focusTerminalBody();
                }
            } else {
                // Simulated mode
                const input = getTerminalInput();
                if (input) input.focus();
            }
        } else {
            // Terminal was closed - no need to disconnect, keep session alive
        }
    };

    // ── Override executeCommand (simulated mode only) ──────────

    window.executeCommand = function () {
        if (isRealTerminal) {
            // In real mode, input goes through key handler, not this function
            return;
        }
        // Call original
        if (typeof _originalExecuteCommand === 'function') {
            _originalExecuteCommand();
        }
    };

    // ── Keepalive Ping ─────────────────────────────────────────

    setInterval(function () {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
        }
    }, 25000);

    // ── Periodic health check for reconnection ─────────────────

    setInterval(function () {
        if (serverAvailable === false && !isRealTerminal) {
            // Periodically check if server came back online
            checkServerHealth().then(function (health) {
                if (health) {
                    console.log('[BlueShell] Server is back online.');
                    serverAvailable = true;
                    // Don't auto-connect - wait for user to toggle terminal
                }
            });
        }
    }, HEALTH_CHECK_INTERVAL);

    // ── Handle window resize ───────────────────────────────────

    let resizeDebounce = null;
    window.addEventListener('resize', function () {
        if (!isRealTerminal) return;
        clearTimeout(resizeDebounce);
        resizeDebounce = setTimeout(function () {
            sendResize();
        }, 200);
    });

    // ── Add paste support for real terminal ────────────────────

    document.addEventListener('paste', function (e) {
        if (!isRealTerminal) return;

        const terminal = document.getElementById('terminal');
        if (!terminal || terminal.classList.contains('hidden')) return;

        const text = (e.clipboardData || window.clipboardData).getData('text');
        if (text) {
            sendToTerminal(text);
            e.preventDefault();
        }
    });

    // ── Public API (for debugging / advanced use) ──────────────

    window.BlueShellTerminal = {
        connect: function () {
            reconnectAttempts = 0;
            serverAvailable = true;
            connectWebSocket();
        },
        disconnect: function () {
            disconnectWebSocket();
            switchToSimulatedMode();
        },
        isConnected: function () {
            return ws && ws.readyState === WebSocket.OPEN;
        },
        isRealMode: function () {
            return isRealTerminal;
        },
        getSession: function () {
            return sessionInfo;
        },
        sendInput: function (data) {
            sendToTerminal(data);
        },
        checkServer: function () {
            return checkServerHealth();
        },
    };

    // ── Initialize ─────────────────────────────────────────────

    console.log('[BlueShell] Real terminal module loaded. Server detection will occur on first terminal open.');

})();
