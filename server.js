/**
 * CrowdStrike POC Kit - Server with Real Terminal
 * Run: node server.js
 * Open: http://localhost:3000/crowdstrike-poc.html
 *
 * Features:
 * - Serves static HTML files
 * - WebSocket-based real terminal (actual shell commands)
 * - Works with claude CLI, npm, git, and all system commands
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const { spawn } = require('child_process');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;

// MIME types
const MIME = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// HTTP Server
const server = http.createServer((req, res) => {
  let filePath = path.join(ROOT, req.url === '/' ? 'crowdstrike-poc.html' : req.url);
  const ext = path.extname(filePath);
  const contentType = MIME[ext] || 'application/octet-stream';

  // Security: prevent path traversal
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404);
        res.end('File not found');
      } else {
        res.writeHead(500);
        res.end('Server error');
      }
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

// WebSocket Terminal Server
const wss = new WebSocketServer({ server, path: '/terminal' });

wss.on('connection', (ws) => {
  console.log('[Terminal] Client connected');

  // Spawn a real shell
  const shell = process.env.SHELL || '/data/data/com.termux/files/usr/bin/bash';
  const proc = spawn(shell, ['-i'], {
    cwd: ROOT,
    env: {
      ...process.env,
      TERM: 'xterm-256color',
      COLUMNS: '120',
      LINES: '40',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  // Send shell output to WebSocket
  proc.stdout.on('data', (data) => {
    try { ws.send(JSON.stringify({ type: 'output', data: data.toString() })); } catch (e) {}
  });

  proc.stderr.on('data', (data) => {
    try { ws.send(JSON.stringify({ type: 'output', data: data.toString() })); } catch (e) {}
  });

  proc.on('close', (code) => {
    try { ws.send(JSON.stringify({ type: 'exit', code })); } catch (e) {}
    ws.close();
  });

  proc.on('error', (err) => {
    try { ws.send(JSON.stringify({ type: 'error', data: err.message })); } catch (e) {}
  });

  // Receive commands from WebSocket
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());
      if (data.type === 'input') {
        proc.stdin.write(data.data);
      } else if (data.type === 'resize') {
        // Best effort resize
        try { proc.kill('SIGWINCH'); } catch (e) {}
      }
    } catch (e) {
      // Raw input fallback
      proc.stdin.write(msg.toString());
    }
  });

  ws.on('close', () => {
    console.log('[Terminal] Client disconnected');
    try { proc.kill(); } catch (e) {}
  });

  // Welcome message
  ws.send(JSON.stringify({
    type: 'output',
    data: '\x1b[36m╔══════════════════════════════════════════════════════════════╗\r\n║     REAL TERMINAL - Connected to System Shell              ║\r\n║     All commands work: claude, npm, git, python, etc.      ║\r\n╚══════════════════════════════════════════════════════════════╝\x1b[0m\r\n\r\n'
  }));
});

server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║     CrowdStrike Falcon POC Kit Server                       ║
║     http://localhost:${PORT}/crowdstrike-poc.html              ║
║                                                              ║
║     Features:                                                ║
║     - Full POC Kit with all tools                            ║
║     - Real Terminal (WebSocket)                              ║
║     - Claude CLI support                                     ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
