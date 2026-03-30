// ═══════════════════════════════════════════════════════════════════
// CROWDSTRIKE FALCON POC MODULE — BlueShell Platform
// Complete Proof-of-Concept Deployment & Success Guide
// ═══════════════════════════════════════════════════════════════════

function csCopyToClipboard(btn) {
    const block = btn.closest('.cs-code-block');
    const code = block.querySelector('code').innerText;
    navigator.clipboard.writeText(code).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'COPIED!';
        btn.style.color = '#0f0';
        setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
    });
}

function csToggleCollapse(header) {
    const body = header.nextElementSibling;
    const arrow = header.querySelector('.cs-collapse-arrow');
    if (body.style.display === 'none') {
        body.style.display = 'block';
        arrow.textContent = '▼';
    } else {
        body.style.display = 'none';
        arrow.textContent = '►';
    }
}

function csSwitchTab(tabId) {
    document.querySelectorAll('.cs-tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.cs-tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector(`.cs-tab-btn[data-tab="${tabId}"]`).classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

function csCode(code, lang) {
    return `<div class="cs-code-block"><div class="cs-code-header"><span>${lang || 'command'}</span><button onclick="csCopyToClipboard(this)">&#128203; Copy</button></div><pre><code>${code.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code></pre></div>`;
}

function csCollapsible(title, content, open) {
    const display = open ? 'block' : 'none';
    const arrow = open ? '▼' : '►';
    return `<div class="cs-collapsible"><div class="cs-collapse-header" onclick="csToggleCollapse(this)"><span class="cs-collapse-arrow">${arrow}</span> ${title}</div><div class="cs-collapse-body" style="display:${display}">${content}</div></div>`;
}

function csCheck(text) {
    return `<label class="cs-check"><input type="checkbox"><span>${text}</span></label>`;
}

// ─── TAB BUILDERS ────────────────────────────────────────────────

function buildTab1_DeploymentGuide() {
    return `
<h2 class="cs-section-title">CROWDSTRIKE FALCON POC DEPLOYMENT GUIDE</h2>

${csCollapsible('1. PRE-POC PLANNING', `
<h3>1.1 Define POC Scope</h3>
<p>Before touching a single endpoint, align with the client stakeholder on exactly what success looks like.</p>

<h4>Scope Checklist</h4>
${csCheck('Identify POC sponsor (CISO, VP Security, IT Director)')}
${csCheck('Define number of endpoints (recommend 50-200 for meaningful POC)')}
${csCheck('Identify OS mix: Windows servers, Windows workstations, Linux servers, macOS endpoints')}
${csCheck('Confirm network segments to include (corporate, DMZ, cloud workloads)')}
${csCheck('Identify existing AV/EDR to run side-by-side or replace')}
${csCheck('Agree on POC duration (14 days minimum, 30 days recommended)')}
${csCheck('Identify technical POC lead on client side')}
${csCheck('Schedule kickoff meeting with all stakeholders')}

<h4>Success Criteria Template</h4>
<table class="cs-table">
<tr><th>Criteria</th><th>Target</th><th>Measurement</th></tr>
<tr><td>Sensor deployment success rate</td><td>>98%</td><td>Falcon console host count vs target</td></tr>
<tr><td>Mean time to detect (MTTD)</td><td>&lt;1 minute</td><td>Timestamp comparison: execution vs detection</td></tr>
<tr><td>False positive rate</td><td>&lt;5% of total detections</td><td>Manual review of all detections</td></tr>
<tr><td>Detection coverage (MITRE)</td><td>>80% of tested techniques</td><td>Atomic Red Team test results</td></tr>
<tr><td>System performance impact</td><td>&lt;3% CPU average</td><td>Performance monitoring before/after</td></tr>
<tr><td>User complaints</td><td>0 workflow disruptions</td><td>Help desk ticket tracking</td></tr>
<tr><td>Visibility into lateral movement</td><td>100% of simulated attempts</td><td>Purple team exercise results</td></tr>
</table>

<h4>14-Day POC Timeline</h4>
<table class="cs-table">
<tr><th>Day</th><th>Activity</th><th>Owner</th></tr>
<tr><td>Day 1</td><td>Kickoff call, Falcon console access, CID creation</td><td>CrowdStrike SE + Client IT</td></tr>
<tr><td>Day 2-3</td><td>Sensor deployment to Phase 1 endpoints (25%)</td><td>Client IT</td></tr>
<tr><td>Day 4-5</td><td>Verify sensors reporting, deploy to Phase 2 (75%)</td><td>Client IT</td></tr>
<tr><td>Day 6</td><td>Complete deployment to 100%, configure prevention policies</td><td>CrowdStrike SE</td></tr>
<tr><td>Day 7</td><td>Custom IOA rules, exclusions tuning</td><td>CrowdStrike SE</td></tr>
<tr><td>Day 8-9</td><td>Detection testing with safe simulations</td><td>Joint</td></tr>
<tr><td>Day 10</td><td>Threat hunting exercises using Falcon LogScale</td><td>CrowdStrike SE</td></tr>
<tr><td>Day 11</td><td>Real Time Response demonstration</td><td>CrowdStrike SE</td></tr>
<tr><td>Day 12</td><td>Integration discussion (SIEM, SOAR, ticketing)</td><td>Joint</td></tr>
<tr><td>Day 13</td><td>Executive readout preparation</td><td>CrowdStrike SE</td></tr>
<tr><td>Day 14</td><td>Executive presentation, POC results review, next steps</td><td>All stakeholders</td></tr>
</table>

<h4>30-Day POC Timeline</h4>
<table class="cs-table">
<tr><th>Week</th><th>Focus</th><th>Key Deliverables</th></tr>
<tr><td>Week 1</td><td>Deploy & Baseline</td><td>100% sensor deployment, baseline alerts documented, prevention in DETECT ONLY</td></tr>
<tr><td>Week 2</td><td>Tune & Customize</td><td>Custom IOA rules live, exclusions tuned, false positives &lt;5%, switch critical policies to PREVENT</td></tr>
<tr><td>Week 3</td><td>Detect & Hunt</td><td>Atomic Red Team testing complete, threat hunting queries running, RTR demo</td></tr>
<tr><td>Week 4</td><td>Report & Close</td><td>Executive summary delivered, ROI calculated, PO discussion initiated</td></tr>
</table>
`, true)}

${csCollapsible('2. FALCON CONSOLE SETUP', `
<h3>2.1 CID (Customer ID) Configuration</h3>
<p>The CID is your unique tenant identifier. Every sensor installation requires it.</p>

<h4>Finding Your CID</h4>
<ol>
<li>Log in to <strong>falcon.crowdstrike.com</strong> (US-1), <strong>falcon.us-2.crowdstrike.com</strong> (US-2), or <strong>falcon.eu-1.crowdstrike.com</strong> (EU-1)</li>
<li>Navigate to <strong>Host setup and management > Deploy > Sensor downloads</strong></li>
<li>Your CID with checksum is displayed at the top of the page</li>
<li>Format: <code>XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX-XX</code> (32 hex chars + 2 char checksum)</li>
</ol>

<h4>Falcon Console Initial Configuration</h4>
${csCheck('Log in to Falcon console and verify tenant access')}
${csCheck('Navigate to Support > CID and record your Customer ID')}
${csCheck('Create user accounts for client POC team (User Management)')}
${csCheck('Assign roles: Falcon Administrator, Falcon Analyst, Falcon Investigator')}
${csCheck('Enable Multi-Factor Authentication for all accounts')}
${csCheck('Configure notification policies (email alerts for critical/high)')}

<h3>2.2 API Client Setup</h3>
<p>API clients are needed for integrations (SIEM, SOAR, automation).</p>

<h4>Create an API Client</h4>
<ol>
<li>Go to <strong>Support and resources > API clients and keys</strong></li>
<li>Click <strong>Add new API client</strong></li>
<li>Name it descriptively: <code>POC-SIEM-Integration</code></li>
<li>Assign scopes based on need:</li>
</ol>
<table class="cs-table">
<tr><th>Scope</th><th>Permission</th><th>Use Case</th></tr>
<tr><td>Detections</td><td>Read</td><td>Pull detections into SIEM</td></tr>
<tr><td>Hosts</td><td>Read + Write</td><td>Host management, containment</td></tr>
<tr><td>Incidents</td><td>Read + Write</td><td>Incident management</td></tr>
<tr><td>Real Time Response</td><td>Read + Write</td><td>Automated response scripts</td></tr>
<tr><td>IOCs</td><td>Read + Write</td><td>Push/pull indicators</td></tr>
<tr><td>Custom IOA Rules</td><td>Read + Write</td><td>Manage detection rules via API</td></tr>
<tr><td>Prevention Policies</td><td>Read + Write</td><td>Policy management</td></tr>
<tr><td>Sensor Update Policies</td><td>Read</td><td>Monitor sensor versions</td></tr>
</table>

${csCode(`# Authenticate to CrowdStrike API (OAuth2)
curl -X POST "https://api.crowdstrike.com/oauth2/token" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"

# Response contains access_token valid for 30 minutes
# Use in subsequent requests:
curl -X GET "https://api.crowdstrike.com/detects/queries/detects/v1?limit=10" \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"`, 'bash')}
`, true)}

${csCollapsible('3. SENSOR DEPLOYMENT', `
<h3>3.1 Download Sensors</h3>
<ol>
<li>Go to <strong>Host setup and management > Deploy > Sensor downloads</strong></li>
<li>Download the appropriate installer for each platform</li>
<li>Note: Sensors are version-specific. Use latest N-1 for stability.</li>
</ol>

<h3>3.2 Windows Deployment</h3>
<h4>Interactive Install (Single Machine Testing)</h4>
${csCode(`# MSI installer — silent install with CID
msiexec /i CsAgentMSI.msi CID=YOUR_CID_WITH_CHECKSUM /quiet /norestart /log C:\\cs_install.log

# EXE installer alternative
CsAgentInstall.exe /install /quiet /norestart CID=YOUR_CID_WITH_CHECKSUM

# With proxy configuration
msiexec /i CsAgentMSI.msi CID=YOUR_CID_WITH_CHECKSUM PROXYDISABLE=0 APP_PROXYNAME=proxy.corp.com APP_PROXYPORT=8080 /quiet /norestart`, 'powershell')}

<h4>Group Policy (GPO) Mass Deployment</h4>
${csCode(`# 1. Copy MSI to network share accessible by all target machines
#    \\\\fileserver\\Software\\CrowdStrike\\CsAgentMSI.msi

# 2. Create GPO: Computer Configuration > Policies > Software Settings > Software installation
#    - Add new package, point to the network share MSI
#    - Set to "Assigned" for mandatory install

# 3. Alternative: Use GPO Startup Script
# Create deploy_cs.bat:
@echo off
sc query csagent >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    msiexec /i "\\\\fileserver\\Software\\CrowdStrike\\CsAgentMSI.msi" CID=YOUR_CID /quiet /norestart /log C:\\cs_install.log
)`, 'batch')}

<h4>SCCM/MECM Deployment</h4>
${csCode(`# Create Application in SCCM
# Detection Method: Registry
#   HKLM\\SYSTEM\\CrowdStrike\\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\\{16e0423f-7058-48c9-a204-725362b67639}\\Default
#   Value: CU  (exists)

# Install command:
msiexec /i CsAgentMSI.msi CID=YOUR_CID /quiet /norestart

# Uninstall command:
msiexec /x CsAgentMSI.msi MAINTENANCE_TOKEN=YOUR_TOKEN /quiet /norestart

# Detection script (PowerShell):
$service = Get-Service -Name CSFalconService -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") { Write-Output "Installed" }`, 'powershell')}

<h4>Intune Deployment</h4>
${csCode(`# 1. Upload CsAgentMSI.msi as a Line-of-Business app in Intune
# 2. Set command line arguments:
#    Install: msiexec /i CsAgentMSI.msi CID=YOUR_CID /quiet /norestart
#    Uninstall: msiexec /x CsAgentMSI.msi MAINTENANCE_TOKEN=TOKEN /quiet
# 3. Detection rule: Registry key exists
#    HKLM\\SYSTEM\\CurrentControlSet\\Services\\CSAgent
# 4. Assign to target device groups`, 'powershell')}

<h3>3.3 Linux Deployment</h3>
<h4>Debian/Ubuntu (DEB)</h4>
${csCode(`# Install the sensor
sudo dpkg -i falcon-sensor_7.x.x_amd64.deb

# Set the CID
sudo /opt/CrowdStrike/falconctl -s --cid=YOUR_CID_WITH_CHECKSUM

# Start the sensor
sudo systemctl start falcon-sensor

# Enable on boot
sudo systemctl enable falcon-sensor

# Verify running
sudo systemctl status falcon-sensor
ps aux | grep falcon

# With proxy
sudo /opt/CrowdStrike/falconctl -s --cid=YOUR_CID --apd=false --aph=proxy.corp.com --app=8080`, 'bash')}

<h4>RHEL/CentOS/Amazon Linux (RPM)</h4>
${csCode(`# Install the sensor
sudo rpm -ivh falcon-sensor-7.x.x.el8.x86_64.rpm
# or with yum:
sudo yum install -y falcon-sensor-7.x.x.el8.x86_64.rpm

# Set the CID
sudo /opt/CrowdStrike/falconctl -s --cid=YOUR_CID_WITH_CHECKSUM

# Start the sensor
sudo systemctl start falcon-sensor
sudo systemctl enable falcon-sensor

# Verify
sudo /opt/CrowdStrike/falconctl -g --cid
sudo systemctl status falcon-sensor`, 'bash')}

<h4>Ansible Playbook for Mass Linux Deployment</h4>
${csCode(`---
- name: Deploy CrowdStrike Falcon Sensor
  hosts: all
  become: yes
  vars:
    cs_cid: "YOUR_CID_WITH_CHECKSUM"
    cs_deb_package: "falcon-sensor_7.x.x_amd64.deb"
    cs_rpm_package: "falcon-sensor-7.x.x.el8.x86_64.rpm"

  tasks:
    - name: Copy sensor package (Debian)
      copy:
        src: "files/{{ cs_deb_package }}"
        dest: "/tmp/{{ cs_deb_package }}"
      when: ansible_os_family == "Debian"

    - name: Install sensor (Debian)
      apt:
        deb: "/tmp/{{ cs_deb_package }}"
      when: ansible_os_family == "Debian"

    - name: Copy sensor package (RedHat)
      copy:
        src: "files/{{ cs_rpm_package }}"
        dest: "/tmp/{{ cs_rpm_package }}"
      when: ansible_os_family == "RedHat"

    - name: Install sensor (RedHat)
      yum:
        name: "/tmp/{{ cs_rpm_package }}"
        state: present
      when: ansible_os_family == "RedHat"

    - name: Set CID
      command: /opt/CrowdStrike/falconctl -s --cid={{ cs_cid }}

    - name: Start and enable falcon-sensor
      systemd:
        name: falcon-sensor
        state: started
        enabled: yes

    - name: Verify sensor is running
      command: systemctl is-active falcon-sensor
      register: sensor_status
      failed_when: sensor_status.stdout != "active"`, 'yaml')}

<h3>3.4 macOS Deployment</h3>
${csCode(`# Install the sensor package
sudo installer -pkg FalconSensorMacOS.pkg -target /

# License the sensor with your CID
sudo /Applications/Falcon.app/Contents/Resources/falconctl license YOUR_CID_WITH_CHECKSUM

# Verify installation
sudo /Applications/Falcon.app/Contents/Resources/falconctl stats

# IMPORTANT: macOS requires the following approvals:
# 1. System Extension approval (MDM or manual in System Preferences > Security)
# 2. Full Disk Access for Falcon (System Preferences > Privacy & Security)
# 3. Network Extension approval (for network filtering)

# For MDM-managed Macs, pre-approve via configuration profiles:
# - System Extension: Team ID = X9E956P446, Bundle ID = com.crowdstrike.falcon.Agent
# - PPPC (Privacy Preferences): com.crowdstrike.falcon.Agent - Full Disk Access
# - Content Filter: com.crowdstrike.falcon.Agent`, 'bash')}

<h4>Jamf Pro Deployment</h4>
${csCode(`# 1. Upload FalconSensorMacOS.pkg to Jamf Pro
# 2. Create a Policy:
#    - Trigger: Enrollment Complete + Recurring Check-in
#    - Package: FalconSensorMacOS.pkg
#    - Scripts: Post-install script to set CID:
#!/bin/bash
/Applications/Falcon.app/Contents/Resources/falconctl license YOUR_CID
# 3. Create Configuration Profiles for:
#    - System Extension (allow Team ID X9E956P446)
#    - PPPC/TCC (Full Disk Access for com.crowdstrike.falcon.Agent)
#    - Content Filter / Network Extension
# 4. Scope to target Smart Group`, 'bash')}
`, true)}

${csCollapsible('4. VERIFY SENSOR DEPLOYMENT', `
<h3>Verification Commands by Platform</h3>

<h4>Windows Verification</h4>
${csCode(`# Check service status
sc query csagent

# Expected output:
#   SERVICE_NAME: csagent
#   STATE: 4  RUNNING

# Check Falcon service
Get-Service CSFalconService | Format-Table Name, Status, StartType

# Check sensor version
reg query "HKLM\\SOFTWARE\\CrowdStrike\\Sensor" /v "VersionInfo"

# Check CID
reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\CSAgent\\Sim" /v CU

# Check connectivity
netstat -an | findstr ":443"
# Look for ESTABLISHED connections to CrowdStrike cloud

# Test sensor comms (PowerShell)
Test-NetConnection ts01-b.cloudsink.net -Port 443`, 'powershell')}

<h4>Linux Verification</h4>
${csCode(`# Check service status
sudo systemctl status falcon-sensor

# Check running processes
ps aux | grep falcon

# Check sensor version
sudo /opt/CrowdStrike/falconctl -g --version

# Check CID
sudo /opt/CrowdStrike/falconctl -g --cid

# Check RFM (Reduced Functionality Mode) — should be false
sudo /opt/CrowdStrike/falconctl -g --rfm-state

# Check connectivity
sudo ss -tnp | grep falcon`, 'bash')}

<h4>macOS Verification</h4>
${csCode(`# Check sensor stats
sudo /Applications/Falcon.app/Contents/Resources/falconctl stats

# Check system extension loaded
systemextensionsctl list | grep crowdstrike

# Check Full Disk Access granted
# Must verify in System Preferences > Privacy > Full Disk Access`, 'bash')}

<h4>Falcon Console Verification</h4>
${csCheck('Navigate to Host setup and management > Host management')}
${csCheck('Verify all deployed hosts appear with green "Online" status')}
${csCheck('Check "Last Seen" timestamp is within last few minutes')}
${csCheck('Verify correct OS, hostname, and sensor version')}
${csCheck('Confirm hosts are in correct Host Group')}
${csCheck('Check for any hosts in Reduced Functionality Mode (RFM)')}
`, true)}

${csCollapsible('5. HOST GROUP CONFIGURATION', `
<h3>Creating Host Groups</h3>
<p>Host Groups determine which policies apply to which endpoints. This is critical for staged rollout.</p>

<h4>Recommended Group Structure for POC</h4>
<table class="cs-table">
<tr><th>Group Name</th><th>Type</th><th>Criteria</th><th>Policy Mode</th></tr>
<tr><td>POC-Canary</td><td>Static</td><td>5-10 IT-owned machines</td><td>PREVENT (aggressive)</td></tr>
<tr><td>POC-Workstations</td><td>Dynamic</td><td>OS = Windows 10/11, OU contains "Workstations"</td><td>DETECT then PREVENT</td></tr>
<tr><td>POC-Servers-Windows</td><td>Dynamic</td><td>OS = Windows Server *</td><td>DETECT only initially</td></tr>
<tr><td>POC-Servers-Linux</td><td>Dynamic</td><td>OS = Linux</td><td>DETECT only initially</td></tr>
<tr><td>POC-macOS</td><td>Dynamic</td><td>OS = macOS</td><td>DETECT then PREVENT</td></tr>
<tr><td>POC-Exclusions-Test</td><td>Static</td><td>Machines with known FP-causing apps</td><td>Custom with exclusions</td></tr>
</table>

<h4>Dynamic Group Rules (API)</h4>
${csCode(`# Create a dynamic host group via API
curl -X POST "https://api.crowdstrike.com/devices/entities/host-groups/v1" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "resources": [{
      "name": "POC-Windows-Workstations",
      "group_type": "dynamic",
      "description": "All Windows workstations in POC scope",
      "assignment_rule": "platform_name:Windows+os_version:*10*,platform_name:Windows+os_version:*11*"
    }]
  }'`, 'bash')}
`, true)}

${csCollapsible('6. PREVENTION POLICY CONFIGURATION (Summary)', `
<p><strong>Note:</strong> Full prevention policy details are in Tab 5. This is the quick-start configuration for POC.</p>

<h3>POC Policy Strategy: Phased Approach</h3>

<h4>Phase 1 (Week 1): DETECT ONLY</h4>
<ul>
<li>Set all prevention toggles to <strong>DETECT</strong> (not prevent)</li>
<li>Cloud ML: <strong>Moderate</strong> detect / <strong>Disabled</strong> prevent</li>
<li>Sensor ML: <strong>Moderate</strong> detect / <strong>Disabled</strong> prevent</li>
<li>All behavioral IOAs: <strong>Detect</strong> mode</li>
<li>Purpose: Establish baseline, find false positives, tune exclusions</li>
</ul>

<h4>Phase 2 (Week 2): SELECTIVE PREVENT</h4>
<ul>
<li>Enable prevention for high-confidence categories:</li>
<li>Ransomware: <strong>PREVENT</strong></li>
<li>Exploitation: <strong>PREVENT</strong></li>
<li>Known malware (Cloud ML Aggressive): <strong>PREVENT</strong></li>
<li>Keep moderate/cautious items in detect</li>
</ul>

<h4>Phase 3 (Week 3+): FULL PREVENT</h4>
<ul>
<li>Enable aggressive prevention across all categories</li>
<li>Cloud ML: <strong>Aggressive</strong> detect + <strong>Aggressive</strong> prevent</li>
<li>Sensor ML: <strong>Aggressive</strong> detect + <strong>Moderate</strong> prevent</li>
<li>All behavioral IOAs: <strong>Prevent</strong> mode</li>
</ul>
`, true)}

${csCollapsible('7. SENSOR UPDATE POLICY', `
<h3>Sensor Version Management</h3>
<p>Controls which sensor version endpoints receive.</p>

<h4>Recommended Settings for POC</h4>
<table class="cs-table">
<tr><th>Setting</th><th>Recommendation</th><th>Reason</th></tr>
<tr><td>Build</td><td>N-1 (one version behind latest)</td><td>Stability — latest patches, proven in production</td></tr>
<tr><td>Uninstall Protection</td><td>ENABLED</td><td>Prevents unauthorized removal</td></tr>
<tr><td>Auto-update</td><td>ENABLED within maintenance window</td><td>Keep sensors current</td></tr>
<tr><td>Maintenance Window</td><td>Weekends 02:00-06:00 local</td><td>Minimize user impact</td></tr>
</table>

${csCode(`# Check sensor version via API
curl -X GET "https://api.crowdstrike.com/sensors/queries/installers/v1?filter=platform:'windows'" \\
  -H "Authorization: Bearer $TOKEN"

# Get sensor installer details
curl -X GET "https://api.crowdstrike.com/sensors/entities/installers/v1?ids=INSTALLER_ID" \\
  -H "Authorization: Bearer $TOKEN"`, 'bash')}
`, true)}

${csCollapsible('8. USB DEVICE CONTROL POLICY', `
<h3>USB Device Control</h3>
<p>Controls which USB storage devices can be used on managed endpoints.</p>

<h4>POC Configuration</h4>
<table class="cs-table">
<tr><th>Setting</th><th>Value</th><th>Notes</th></tr>
<tr><td>USB Device Control</td><td>Enabled (Monitor mode)</td><td>Start in monitor to see what devices are in use</td></tr>
<tr><td>Default Action</td><td>Allow (with logging)</td><td>Don't block during initial POC phase</td></tr>
<tr><td>Class: Mass Storage</td><td>Monitor</td><td>Log all USB storage connections</td></tr>
<tr><td>Class: Portable Devices (MTP)</td><td>Monitor</td><td>Log phone connections</td></tr>
<tr><td>Approved Device List</td><td>Corporate-issued USB devices only</td><td>By Vendor ID / Product ID</td></tr>
</table>

<h4>Device Control Classes</h4>
<ul>
<li><strong>Mass Storage (0x08)</strong> — USB flash drives, external HDDs</li>
<li><strong>Portable Devices</strong> — MTP devices (smartphones)</li>
<li><strong>Printers (0x07)</strong> — USB printers</li>
<li><strong>Wireless Controllers (0xE0)</strong> — Bluetooth adapters</li>
<li><strong>Imaging (0x06)</strong> — Scanners, cameras</li>
</ul>
`, true)}

${csCollapsible('9. FIREWALL MANAGEMENT POLICY', `
<h3>Falcon Firewall Management</h3>
<p>Host-based firewall managed through the Falcon console.</p>

<h4>Key Concepts</h4>
<ul>
<li><strong>Rule Groups</strong>: Collections of firewall rules applied to host groups</li>
<li><strong>Rule Precedence</strong>: Rules evaluated top-to-bottom, first match wins</li>
<li><strong>Default Action</strong>: Allow or Block for traffic not matching any rule</li>
<li><strong>Platforms</strong>: Windows only (uses Windows Filtering Platform)</li>
</ul>

<h4>POC Firewall Configuration</h4>
${csCode(`# Example rule group for POC:
# Rule 1: Allow outbound HTTPS (443) — all destinations
# Rule 2: Allow outbound DNS (53) — corporate DNS servers only
# Rule 3: Allow inbound RDP (3389) — from IT subnet only
# Rule 4: Block inbound SMB (445) — from non-corporate IPs
# Rule 5: Block all inbound from known malicious IPs (IOC-fed list)
# Default: Allow all (monitor mode during POC)`, 'text')}

<p><strong>POC Tip:</strong> During POC, set firewall to <strong>monitor mode</strong> to identify traffic patterns before enforcing rules. Review Falcon Firewall logs for 1 week before switching to enforce mode.</p>
`, true)}
`;
}

function buildTab2_IOARules() {
    return `
<h2 class="cs-section-title">CUSTOM IOA RULES LIBRARY (25+ Rules by MITRE ATT&CK)</h2>
<p class="cs-note">Each rule below can be created in <strong>Falcon Console > Custom IOA Rule Groups</strong>. Create a Rule Group first, then add individual rules. Assign the Rule Group to your Prevention Policy.</p>

<h3 class="cs-mitre-tactic">INITIAL ACCESS (TA0001)</h3>

${csCollapsible('Rule 19: Macro Execution from Office Applications', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Office Macro Child Process Execution</td></tr>
<tr><td>Description</td><td>Detects Office applications spawning suspicious child processes, indicating macro-based initial access</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1566.001 — Spearphishing Attachment</td></tr>
</table>
${csCode(`Rule Configuration:
  Parent Image Filename: WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, OUTLOOK.EXE
  Image Filename: cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, certutil.exe, regsvr32.exe, rundll32.exe, bitsadmin.exe
  Action: Detect / Monitor (switch to Prevent after tuning)

  CLI Equivalent Filter:
  event_simpleName=ProcessRollup2
  | ParentBaseFileName IN ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE")
  | FileName IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe")`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">EXECUTION (TA0002)</h3>

${csCollapsible('Rule 1: Detect Mimikatz Execution', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Mimikatz Process Execution Detected</td></tr>
<tr><td>Description</td><td>Detects execution of Mimikatz credential harvesting tool by process name, command line arguments, or known hashes</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>Critical</td></tr>
<tr><td>MITRE</td><td>T1003 — OS Credential Dumping</td></tr>
</table>
${csCode(`Rule Configuration:
  Image Filename: .*mimikatz.*
  OR Command Line: .*(sekurlsa|kerberos::list|crypto::certificates|lsadump|privilege::debug).*
  Action: Detect + Prevent (Block & Alert)

  Additional Matching:
  Command Line Regex: .*(sekurlsa::logonpasswords|sekurlsa::wdigest|lsadump::sam|lsadump::dcsync).*`, 'text')}
`, false)}

${csCollapsible('Rule 3: Detect PowerShell Encoded Commands', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>PowerShell Base64 Encoded Command Execution</td></tr>
<tr><td>Description</td><td>Detects PowerShell running with encoded command parameter, commonly used for obfuscation by attackers</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1059.001 — PowerShell</td></tr>
</table>
${csCode(`Rule Configuration:
  Image Filename: powershell.exe, pwsh.exe
  Command Line: .*(-enc|-EncodedCommand|-ec)\\s+[A-Za-z0-9+/=]{20,}.*
  Action: Detect (high FP potential — tune first)

  Refinement — Exclude known IT automation:
  Exclude Command Line containing: "SCCM", "Intune", "ConfigMgr"
  Exclude Parent Process: svchost.exe (with SCCM context)`, 'text')}
`, false)}

${csCollapsible('Rule 20: Suspicious Script Interpreter Execution', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Unusual Script Interpreter Activity</td></tr>
<tr><td>Description</td><td>Detects script interpreters (wscript, cscript, mshta) executing from unusual locations or with suspicious arguments</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>Medium</td></tr>
<tr><td>MITRE</td><td>T1059.005 — Visual Basic, T1059.007 — JavaScript</td></tr>
</table>
${csCode(`Rule Configuration:
  Image Filename: wscript.exe, cscript.exe, mshta.exe
  Command Line: .*(http:|https:|\\\\\\\\|%temp%|%appdata%|\\\\Users\\\\Public).*
  Action: Detect

  Additional Context:
  Flag when script interpreter runs from:
  - User temp directories
  - User Downloads folder
  - Public folders
  - With network paths (UNC or HTTP)`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">PERSISTENCE (TA0003)</h3>

${csCollapsible('Rule 5: Detect Scheduled Task Persistence', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Suspicious Scheduled Task Creation</td></tr>
<tr><td>Description</td><td>Detects creation of scheduled tasks via schtasks.exe or Task Scheduler COM, commonly used for persistence</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>Medium</td></tr>
<tr><td>MITRE</td><td>T1053.005 — Scheduled Task</td></tr>
</table>
${csCode(`Rule Configuration:
  Image Filename: schtasks.exe
  Command Line: .*(/create|/change).*
  Action: Detect

  High-Fidelity Variant (reduce FP):
  Command Line: .*schtasks.*/create.*(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin).*
  Exclude: Known IT management task names`, 'text')}
`, false)}

${csCollapsible('Rule 6: Detect New Service Creation', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Suspicious Service Installation</td></tr>
<tr><td>Description</td><td>Detects creation of new Windows services via sc.exe or PowerShell, often used for persistence and privilege escalation</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>Medium</td></tr>
<tr><td>MITRE</td><td>T1543.003 — Windows Service</td></tr>
</table>
${csCode(`Rule Configuration:
  Image Filename: sc.exe
  Command Line: .*(create|config).*binpath.*
  Action: Detect

  PowerShell Variant:
  Image Filename: powershell.exe
  Command Line: .*New-Service.*`, 'text')}
`, false)}

${csCollapsible('Rule 7: Detect Registry Run Key Modification', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Registry Run Key Persistence</td></tr>
<tr><td>Description</td><td>Detects modifications to registry run keys used for auto-start persistence</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Registry Modification</td></tr>
<tr><td>Severity</td><td>Medium</td></tr>
<tr><td>MITRE</td><td>T1547.001 — Registry Run Keys</td></tr>
</table>
${csCode(`Rule Configuration:
  Registry Path:
    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*
    HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*
    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce*
    HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce*
  Operation: SetValue
  Action: Detect

  High-Fidelity Filter — Exclude:
  - Values set by known installers (SCCM, Windows Update)
  - Signed Microsoft binaries setting their own run keys`, 'text')}
`, false)}

${csCollapsible('Rule 11: Detect DLL Hijacking / Side-Loading', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>DLL Side-Loading Detected</td></tr>
<tr><td>Description</td><td>Detects DLLs loaded from unexpected paths by trusted executables — indicates DLL hijacking or side-loading</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Module Load</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1574.002 — DLL Side-Loading</td></tr>
</table>
${csCode(`Rule Configuration:
  Process Image: Known vulnerable executables:
    - OneDriveStandaloneUpdater.exe
    - MicrosoftEdgeUpdate.exe
    - Any signed binary known to side-load

  Module Path NOT IN:
    - C:\\Windows\\System32\\*
    - C:\\Windows\\SysWOW64\\*
    - C:\\Program Files\\*
    - C:\\Program Files (x86)\\*

  Action: Detect + Alert`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">PRIVILEGE ESCALATION (TA0004)</h3>

${csCollapsible('Rule 18: Detect UAC Bypass', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>UAC Bypass via Trusted Binary</td></tr>
<tr><td>Description</td><td>Detects common UAC bypass techniques using auto-elevating Windows binaries</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1548.002 — Bypass User Account Control</td></tr>
</table>
${csCode(`Rule Configuration:
  Technique 1 — fodhelper.exe:
    Image Filename: fodhelper.exe
    Child Process NOT: legitimate Windows settings

  Technique 2 — eventvwr.exe / computerdefaults.exe:
    Image Filename: eventvwr.exe, computerdefaults.exe
    Has unexpected child processes (cmd.exe, powershell.exe)

  Technique 3 — Registry-based:
    Registry Path: HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command
    Operation: SetValue
    Action: Detect + Prevent`, 'text')}
`, false)}

${csCollapsible('Rule 25: Detect Token Manipulation', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Access Token Manipulation</td></tr>
<tr><td>Description</td><td>Detects attempts to manipulate access tokens for privilege escalation or impersonation</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation + API Call</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1134 — Access Token Manipulation</td></tr>
</table>
${csCode(`Rule Configuration:
  Detect processes calling:
    - AdjustTokenPrivileges with SeDebugPrivilege
    - ImpersonateLoggedOnUser
    - DuplicateToken / DuplicateTokenEx
    - CreateProcessWithTokenW / CreateProcessAsUserW

  Image Filename NOT IN known admin tools:
    Exclude: SCCM, Intune management agents
  Action: Detect

  Command Line Indicators:
  - .*incognito.*
  - .*token::elevate.*
  - .*steal_token.*`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">DEFENSE EVASION (TA0005)</h3>

${csCollapsible('Rule 12: Detect Process Injection', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Process Injection Activity Detected</td></tr>
<tr><td>Description</td><td>Detects indicators of process injection including process hollowing, DLL injection, and shellcode injection</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation + API Monitoring</td></tr>
<tr><td>Severity</td><td>Critical</td></tr>
<tr><td>MITRE</td><td>T1055 — Process Injection</td></tr>
</table>
${csCode(`Rule Configuration:
  Indicators (Falcon detects natively but custom rule adds context):

  Process Hollowing Pattern:
    - CreateProcess with CREATE_SUSPENDED flag
    - Followed by WriteProcessMemory
    - Followed by ResumeThread

  Classic DLL Injection:
    - OpenProcess on remote process
    - VirtualAllocEx in target
    - WriteProcessMemory
    - CreateRemoteThread

  Behavioral Indicator:
    Process with unsigned image writing to memory of:
    - svchost.exe, explorer.exe, lsass.exe, winlogon.exe
  Action: Detect + Prevent`, 'text')}
`, false)}

${csCollapsible('Rule 9: Detect Living-off-the-Land Binaries (LOLBins)', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>LOLBin Suspicious Usage</td></tr>
<tr><td>Description</td><td>Detects abuse of legitimate Windows binaries for malicious purposes (download, execute, bypass)</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>Medium-High</td></tr>
<tr><td>MITRE</td><td>T1218 — System Binary Proxy Execution</td></tr>
</table>
${csCode(`Rule Configuration — Multiple sub-rules:

  certutil.exe abuse:
    Command Line: .*certutil.*(urlcache|verifyctl|encode|decode).*

  mshta.exe abuse:
    Command Line: .*mshta.*(http|https|javascript|vbscript).*

  regsvr32.exe abuse (Squiblydoo):
    Command Line: .*regsvr32.*/s.*/n.*/u.*/i:(http|https).*

  rundll32.exe abuse:
    Command Line: .*rundll32.*javascript:.*
    OR Parent NOT: explorer.exe, svchost.exe

  bitsadmin.exe abuse:
    Command Line: .*bitsadmin.*/transfer.*http.*

  msiexec.exe abuse:
    Command Line: .*msiexec.*/q.*(http|https).*

  Action: Detect (tune for environment before prevent)`, 'text')}
`, false)}

${csCollapsible('Rule 21: Detect Certutil Abuse for File Download', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Certutil File Download or Decode</td></tr>
<tr><td>Description</td><td>Detects certutil.exe being used to download files or decode Base64 content — a common LOLBin technique</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1140 — Deobfuscate/Decode, T1105 — Ingress Tool Transfer</td></tr>
</table>
${csCode(`Rule Configuration:
  Image Filename: certutil.exe
  Command Line: .*(-urlcache|-verifyctl|-encode|-decode|-decodehex).*

  High-Fidelity Filter:
  Command Line: .*certutil.*-urlcache.*-split.*-f.*(http|https|ftp).*

  Action: Detect + Prevent

  Note: Very few legitimate uses for certutil downloading files.
  Low false positive rate — safe to set to Prevent early.`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">CREDENTIAL ACCESS (TA0006)</h3>

${csCollapsible('Rule 2: Detect LSASS Memory Access (Credential Dumping)', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>LSASS Memory Access — Credential Dumping</td></tr>
<tr><td>Description</td><td>Detects processes accessing LSASS memory, indicating credential harvesting via Mimikatz, procdump, comsvcs.dll, or direct memory access</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation + API Monitoring</td></tr>
<tr><td>Severity</td><td>Critical</td></tr>
<tr><td>MITRE</td><td>T1003.001 — LSASS Memory</td></tr>
</table>
${csCode(`Rule Configuration:
  Method 1 — procdump:
    Image Filename: procdump.exe, procdump64.exe
    Command Line: .*lsass.*

  Method 2 — comsvcs.dll MiniDump:
    Image Filename: rundll32.exe
    Command Line: .*comsvcs.dll.*MiniDump.*

  Method 3 — Task Manager dump:
    Watch for: taskmgr.exe creating lsass.dmp

  Method 4 — Direct API:
    Process accessing lsass.exe with PROCESS_VM_READ
    Exclude: Known security tools, AV engines

  Action: Detect + Prevent (Critical — always prevent)`, 'text')}
`, false)}

${csCollapsible('Rule 10: Detect Kerberoasting (TGS Requests)', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Kerberoasting Activity Detected</td></tr>
<tr><td>Description</td><td>Detects mass TGS ticket requests for service accounts, indicating Kerberoasting attack for offline password cracking</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation + Network</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1558.003 — Kerberoasting</td></tr>
</table>
${csCode(`Rule Configuration:
  Detect known Kerberoasting tools:
    Image Filename / Command Line containing:
    - Rubeus.exe.*kerberoast.*
    - Invoke-Kerberoast
    - GetUserSPNs
    - .*hashcat.*krb5tgs.*

  Behavioral (requires Identity Protection module):
    - Single user requesting TGS tickets for >5 unique SPNs in 10 minutes
    - TGS requests with RC4 encryption (downgrade indicator)

  Action: Detect + Alert (escalate immediately)`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">DISCOVERY (TA0007)</h3>

${csCollapsible('Rule 17: Detect AD Enumeration Tools (BloodHound/SharpHound)', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Active Directory Enumeration Tool Detected</td></tr>
<tr><td>Description</td><td>Detects execution of AD enumeration tools like BloodHound, SharpHound, ADFind, and similar reconnaissance tools</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1087.002 — Domain Account Discovery</td></tr>
</table>
${csCode(`Rule Configuration:
  Image Filename / Command Line:
    - .*SharpHound.*
    - .*BloodHound.*
    - .*ADFind.*
    - .*ldapdomaindump.*
    - .*PowerView.*
    - .*Get-DomainUser.*
    - .*Get-DomainGroup.*
    - .*Get-DomainComputer.*
    - .*Invoke-ACLScanner.*

  ADFind-specific:
    Image Filename: adfind.exe
    Command Line: .*(objectcategory|trustdmp|domainlist|gcb|sc).*

  Action: Detect + Prevent`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">LATERAL MOVEMENT (TA0008)</h3>

${csCollapsible('Rule 4: Detect WMI Lateral Movement', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>WMI Remote Process Execution</td></tr>
<tr><td>Description</td><td>Detects use of WMI (wmic.exe or PowerShell WMI cmdlets) for remote code execution — lateral movement indicator</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1047 — Windows Management Instrumentation</td></tr>
</table>
${csCode(`Rule Configuration:
  wmic.exe remote execution:
    Image Filename: wmic.exe, WMIC.exe
    Command Line: .*(/node:|/NODE:).*process.*call.*create.*

  PowerShell WMI remoting:
    Image Filename: powershell.exe
    Command Line: .*(Invoke-WmiMethod|Invoke-CimMethod).*-ComputerName.*

  WMI Provider Host spawning unexpected children:
    Parent Image: WmiPrvSE.exe
    Child Image: cmd.exe, powershell.exe, mshta.exe

  Action: Detect`, 'text')}
`, false)}

${csCollapsible('Rule 22: Detect PsExec Usage', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>PsExec Remote Execution Detected</td></tr>
<tr><td>Description</td><td>Detects PsExec and PsExec-like tools used for lateral movement via remote service creation</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation + Named Pipe</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1570 — Lateral Tool Transfer, T1021.002 — SMB/Windows Admin Shares</td></tr>
</table>
${csCode(`Rule Configuration:
  Direct PsExec detection:
    Image Filename: psexec.exe, psexec64.exe, PsExec.exe

  PsExec behavioral pattern (catches renamed PsExec):
    Service Name: PSEXESVC
    Named Pipe: \\\\psexec*

  Network indicator:
    SMB (445) connection followed by service creation on remote host

  Action: Detect (PsExec is used legitimately by some IT teams — tune first)

  Exclusion guidance:
  - Whitelist known IT admin workstations as source
  - Whitelist known management scripts by parent process`, 'text')}
`, false)}

${csCollapsible('Rule 16: Detect Unauthorized RDP Connections', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Unauthorized RDP Connection Detected</td></tr>
<tr><td>Description</td><td>Detects RDP connections from unexpected sources or RDP being enabled/tunneled</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Network + Process</td></tr>
<tr><td>Severity</td><td>Medium</td></tr>
<tr><td>MITRE</td><td>T1021.001 — Remote Desktop Protocol</td></tr>
</table>
${csCode(`Rule Configuration:
  RDP enabled via command line:
    Command Line: .*reg add.*Terminal Server.*fDenyTSConnections.*0.*
    Command Line: .*netsh.*firewall.*3389.*

  RDP tunneling detection:
    Detect SSH or other tunnel with local port forward to 3389:
    Command Line: .*ssh.*-L.*3389.*
    Detect plink.exe usage:
    Image Filename: plink.exe

  Unusual RDP source:
    Network connection inbound on 3389 from non-corporate subnet

  Action: Detect`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">COMMAND AND CONTROL (TA0011)</h3>

${csCollapsible('Rule 8: Detect DNS Tunneling Patterns', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>DNS Tunneling Activity Detected</td></tr>
<tr><td>Description</td><td>Detects indicators of DNS-based command and control tunneling (high volume, long subdomain labels, high entropy queries)</td></tr>
<tr><td>Platform</td><td>Windows, Linux, macOS</td></tr>
<tr><td>Rule Type</td><td>DNS Query / Network</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1071.004 — DNS</td></tr>
</table>
${csCode(`Rule Configuration:
  Behavioral indicators (combine for high fidelity):
  1. DNS queries with subdomain labels >40 characters
  2. >50 unique DNS queries to same domain in 1 minute
  3. TXT record queries to unusual domains
  4. DNS queries with high Shannon entropy (>3.5)

  Known tunneling tool patterns:
  - iodine: *.v137.* or long hex subdomain queries
  - dnscat2: hex-encoded subdomain patterns
  - DNSExfiltrator: base64/base32 encoded subdomains

  Process indicators:
  - Non-browser process making high volume DNS queries
  - PowerShell/cmd.exe resolving unusual domains

  Action: Detect + Alert`, 'text')}
`, false)}

${csCollapsible('Rule 15: Detect C2 Beaconing Patterns', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>C2 Beaconing Pattern Detected</td></tr>
<tr><td>Description</td><td>Detects regular interval network connections indicative of command-and-control beaconing</td></tr>
<tr><td>Platform</td><td>Windows, Linux, macOS</td></tr>
<tr><td>Rule Type</td><td>Network Connection</td></tr>
<tr><td>Severity</td><td>High</td></tr>
<tr><td>MITRE</td><td>T1071 — Application Layer Protocol</td></tr>
</table>
${csCode(`Rule Configuration:
  Behavioral detection (best done via LogScale query):
  - Process making outbound connections at regular intervals (jitter <20%)
  - Connections to IPs/domains not in corporate whitelist
  - Low data volume per connection (beacons are small)
  - HTTPS connections with unusual JA3/JA3S hashes

  Known C2 framework indicators:
  - Cobalt Strike: Default sleep 60s, HTTPS with specific URI patterns
  - Sliver: mTLS connections on unusual ports
  - Covenant: HTTP with specific cookie patterns
  - Mythic: Variable but detectable JA3 hashes

  Action: Detect + Investigate immediately`, 'text')}
`, false)}

${csCollapsible('Rule 23: Detect Cobalt Strike Patterns', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Cobalt Strike Indicator Detected</td></tr>
<tr><td>Description</td><td>Detects multiple indicators associated with Cobalt Strike beacon activity</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process + Network + Named Pipe</td></tr>
<tr><td>Severity</td><td>Critical</td></tr>
<tr><td>MITRE</td><td>T1071.001 — Web Protocols (C2)</td></tr>
</table>
${csCode(`Rule Configuration:
  Named Pipe indicators:
    \\\\MSSE-*  (default CS named pipe)
    \\\\msagent_*
    \\\\postex_*
    \\\\status_*
    \\\\mypipe-f*  (p2p beacon)

  Process indicators:
    - rundll32.exe with no arguments or DLL path
    - Orphaned rundll32.exe processes
    - PowerShell downloading and IEX-ing from unusual URLs
    - regsvr32.exe loading from temp directories

  Network indicators:
    - Regular interval HTTPS beaconing (default 60s)
    - HTTP requests with /visit.js, /pixel, /__utm.gif patterns
    - JA3 hash matching known CS configurations

  Memory indicators:
    - Beacon reflective DLL in memory of legitimate process
    - MZ header in allocated memory regions of unexpected processes

  Action: Detect + Prevent + Immediate Escalation`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">EXFILTRATION (TA0010)</h3>

${csCollapsible('Rule 14: Detect Data Staging for Exfiltration', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Data Staging and Compression Detected</td></tr>
<tr><td>Description</td><td>Detects file compression and staging activities that precede data exfiltration</td></tr>
<tr><td>Platform</td><td>Windows, Linux</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>Medium</td></tr>
<tr><td>MITRE</td><td>T1560.001 — Archive via Utility</td></tr>
</table>
${csCode(`Rule Configuration:
  Windows archiving:
    Image Filename: 7z.exe, 7za.exe, rar.exe, WinRAR.exe
    Command Line: .*(a |a$).*(-p|-hp).*  (password-protected archives)

  PowerShell archiving:
    Command Line: .*Compress-Archive.*

  Large archive creation:
    File Write to .zip, .rar, .7z > 100MB in temp directories

  Linux:
    Command Line: .*tar.*czf.*(etc|home|var|opt).*
    Command Line: .*zip.*-r.*(etc|home|var|opt).*

  Staging directory indicators:
    File writes to C:\\Users\\Public, C:\\ProgramData, %TEMP%
    Multiple file copies to single directory in short time

  Action: Detect`, 'text')}
`, false)}

<h3 class="cs-mitre-tactic">IMPACT (TA0040)</h3>

${csCollapsible('Rule 13: Detect Shadow Copy Deletion (Ransomware)', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Volume Shadow Copy Deletion — Ransomware Indicator</td></tr>
<tr><td>Description</td><td>Detects deletion of Volume Shadow Copies, a critical ransomware precursor activity</td></tr>
<tr><td>Platform</td><td>Windows</td></tr>
<tr><td>Rule Type</td><td>Process Creation</td></tr>
<tr><td>Severity</td><td>Critical</td></tr>
<tr><td>MITRE</td><td>T1490 — Inhibit System Recovery</td></tr>
</table>
${csCode(`Rule Configuration:
  vssadmin shadow deletion:
    Image Filename: vssadmin.exe
    Command Line: .*delete shadows.*(\/all|\/for).*

  WMIC shadow deletion:
    Image Filename: wmic.exe, WMIC.exe
    Command Line: .*shadowcopy.*delete.*

  PowerShell variant:
    Command Line: .*Get-WmiObject.*Win32_ShadowCopy.*Delete.*

  BCDEdit recovery disable:
    Image Filename: bcdedit.exe
    Command Line: .*(recoveryenabled.*no|bootstatuspolicy.*ignoreallfailures).*

  wbadmin backup deletion:
    Image Filename: wbadmin.exe
    Command Line: .*delete.*catalog.*-quiet.*

  Action: PREVENT (always — no legitimate reason to mass-delete shadow copies)

  This rule should be in PREVENT mode from Day 1 of POC.`, 'text')}
`, false)}

${csCollapsible('Rule 24: Detect Ransomware Encryption Behavior', `
<table class="cs-table">
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Name</td><td>Ransomware Encryption Pattern Detected</td></tr>
<tr><td>Description</td><td>Detects behavioral patterns consistent with ransomware file encryption activity</td></tr>
<tr><td>Platform</td><td>Windows, Linux</td></tr>
<tr><td>Rule Type</td><td>File Modification + Process</td></tr>
<tr><td>Severity</td><td>Critical</td></tr>
<tr><td>MITRE</td><td>T1486 — Data Encrypted for Impact</td></tr>
</table>
${csCode(`Rule Configuration:
  Behavioral indicators (Falcon detects natively — custom rule adds specificity):

  1. Mass file rename with new extension:
     - >50 files renamed with same new extension in 60 seconds
     - Extensions: .encrypted, .locked, .crypt, .enc, random extensions

  2. Ransom note creation:
     - File creation matching: *README*, *DECRYPT*, *RESTORE*, *HOW_TO*
     - In multiple directories simultaneously

  3. File entropy change:
     - Files being written with significantly higher entropy (encrypted)
     - Multiple file types affected (.docx, .xlsx, .pdf, .jpg)

  4. Combination trigger (highest fidelity):
     - Shadow copy deletion + mass file modification + ransom note = confirmed ransomware

  Action: PREVENT (Critical — always prevent from Day 1)`, 'text')}
`, false)}
`;
}

function buildTab3_LogScaleQueries() {
    return `
<h2 class="cs-section-title">FALCON LOGSCALE (HUMIO) HUNTING QUERIES</h2>
<p class="cs-note">These queries run in <strong>Investigate > Advanced event search</strong> or <strong>Falcon LogScale</strong>. Falcon uses the LogScale Query Language (LQL). All queries assume data from the Falcon sensor data repository.</p>

<h3 class="cs-mitre-tactic">PROCESS HUNTING</h3>

${csCollapsible('1. Find Encoded PowerShell Executions', `
<p>Detects PowerShell executing with Base64-encoded commands, a common obfuscation technique.</p>
${csCode(`event_simpleName=ProcessRollup2
| FileName=powershell.exe OR FileName=pwsh.exe
| CommandLine=/(-enc|-EncodedCommand|-ec)\\s+/i
| select([aid, ComputerName, UserName, CommandLine, ParentBaseFileName, timestamp])
| sort(timestamp, order=desc)
| head(100)`, 'logscale')}
`, false)}

${csCollapsible('2. Suspicious Process Spawned from Office Applications', `
<p>Detects Word, Excel, PowerPoint spawning shells — classic macro attack indicator.</p>
${csCode(`event_simpleName=ProcessRollup2
| ParentBaseFileName IN ["WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE","MSACCESS.EXE"]
| FileName IN ["cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","certutil.exe","regsvr32.exe","rundll32.exe"]
| select([aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('3. Process Execution from Suspicious Paths', `
<p>Finds executables running from temp folders, downloads, recycle bin, and other unusual locations.</p>
${csCode(`event_simpleName=ProcessRollup2
| ImageFileName=/(\\\\Temp\\\\|\\\\Downloads\\\\|\\\\AppData\\\\Local\\\\Temp\\\\|\\\\ProgramData\\\\|\\\\Users\\\\Public\\\\|\\\\Recycle|\\\\Windows\\\\Temp\\\\)/i
| FileName!=/^(setup|install|update|msi|chrome_installer)/i
| select([aid, ComputerName, UserName, ImageFileName, CommandLine, timestamp])
| groupBy([ImageFileName], function=count())
| sort(_count, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('4. Rundll32 with No Arguments or Unusual DLL', `
<p>Orphaned rundll32 is a strong indicator of injected code (Cobalt Strike, etc.).</p>
${csCode(`event_simpleName=ProcessRollup2
| FileName=rundll32.exe
| CommandLine=/(^"?[A-Z]:\\\\Windows\\\\[Ss]ystem32\\\\rundll32\\.exe"?\\s*$|^rundll32\\.exe\\s*$)/
| select([aid, ComputerName, UserName, ParentBaseFileName, CommandLine, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('5. LSASS Access by Non-Standard Processes', `
<p>Detects processes accessing LSASS for credential dumping.</p>
${csCode(`event_simpleName=ProcessRollup2
| FileName=lsass.exe
| select([aid, TargetProcessId])

// Better approach using raw events:
event_simpleName=LsassHandleOperation
| ContextBaseFileName!=/^(svchost|lsass|csrss|wininit|MsMpEng|CsFalconService|vmtoolsd)\\.exe$/i
| select([aid, ComputerName, ContextBaseFileName, ContextProcessId, timestamp])
| groupBy([ContextBaseFileName, ComputerName], function=count())
| sort(_count, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('6. Detect Living-off-the-Land Binary Usage', `
<p>Broad LOLBin hunting query covering multiple abused binaries.</p>
${csCode(`event_simpleName=ProcessRollup2
| FileName IN ["certutil.exe","mshta.exe","regsvr32.exe","bitsadmin.exe","msiexec.exe","wmic.exe","cmstp.exe","msdt.exe","msbuild.exe","installutil.exe","regasm.exe","regsvcs.exe"]
| CommandLine=/(http|https|ftp|urlcache|encode|decode|transfer|\/i:|scrobj|javascript)/i
| select([aid, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

<h3 class="cs-mitre-tactic">NETWORK HUNTING</h3>

${csCollapsible('7. Outbound Connections on Unusual Ports', `
<p>Finds connections to non-standard ports that may indicate C2 or data exfiltration.</p>
${csCode(`event_simpleName=NetworkConnectIP4
| RemotePort!=80 AND RemotePort!=443 AND RemotePort!=53 AND RemotePort!=22 AND RemotePort!=445 AND RemotePort!=135 AND RemotePort!=8080 AND RemotePort!=8443
| RemoteAddressIP4!=/^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)/
| select([aid, ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort, timestamp])
| groupBy([RemoteAddressIP4, RemotePort, ContextBaseFileName], function=count())
| sort(_count, order=desc)
| head(50)`, 'logscale')}
`, false)}

${csCollapsible('8. DNS Tunneling Detection — Long Query Names', `
<p>Finds DNS queries with unusually long subdomain labels indicating DNS tunneling.</p>
${csCode(`event_simpleName=DnsRequest
| DomainName=/.{50,}/
| DomainName!=/\\.microsoft\\.com$|\\.windows\\.com$|\\.windowsupdate\\.com$|\\.office\\.com$/
| select([aid, ComputerName, ContextBaseFileName, DomainName, timestamp])
| groupBy([DomainName], function=count())
| sort(_count, order=desc)
| head(50)`, 'logscale')}
`, false)}

${csCollapsible('9. Beaconing Detection — Regular Interval Connections', `
<p>Identifies processes making connections at regular intervals (C2 beaconing).</p>
${csCode(`event_simpleName=NetworkConnectIP4
| RemoteAddressIP4!=/^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)/
| groupBy([aid, ContextBaseFileName, RemoteAddressIP4], function=[count(), selectFromMin(field=timestamp, include=[timestamp]), selectFromMax(field=timestamp, include=[timestamp])])
| _count > 20
| sort(_count, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('10. Connections to Known Malicious TLDs', `
<p>Monitors DNS requests to top-level domains commonly associated with malicious activity.</p>
${csCode(`event_simpleName=DnsRequest
| DomainName=/\\.(xyz|top|buzz|club|work|surf|icu|tk|ml|ga|cf|gq|pw|cc|ws|bit|onion)$/i
| select([aid, ComputerName, ContextBaseFileName, DomainName, timestamp])
| groupBy([DomainName, ComputerName], function=count())
| sort(_count, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('11. Large Outbound Data Transfers', `
<p>Detects large data transfers to external IPs that may indicate exfiltration.</p>
${csCode(`event_simpleName=NetworkConnectIP4
| RemoteAddressIP4!=/^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)/
| BytesSent > 10000000
| select([aid, ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort, BytesSent, timestamp])
| BytesSentMB := BytesSent / 1048576
| sort(BytesSentMB, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('12. SMB Connections to Non-File Servers', `
<p>Detects lateral movement via SMB to machines that are not file servers.</p>
${csCode(`event_simpleName=NetworkConnectIP4
| RemotePort=445
| RemoteAddressIP4!=/^(10\\.0\\.1\\.|fileserver_ip_here)/
| select([aid, ComputerName, ContextBaseFileName, RemoteAddressIP4, UserName, timestamp])
| groupBy([ComputerName, RemoteAddressIP4], function=count())
| sort(_count, order=desc)`, 'logscale')}
`, false)}

<h3 class="cs-mitre-tactic">FILE HUNTING</h3>

${csCollapsible('13. Suspicious File Writes to Startup Folders', `
<p>Detects files being written to startup directories for persistence.</p>
${csCode(`event_simpleName=NewExecutableWritten OR event_simpleName=PeFileWritten
| FilePath=/(Start Menu\\\\Programs\\\\Startup|\\\\Startup\\\\)/i
| select([aid, ComputerName, ContextBaseFileName, FilePath, FileName, SHA256HashData, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('14. Executables Written to Temp Directories', `
<p>Finds new executables dropped in temp folders — common malware staging behavior.</p>
${csCode(`event_simpleName=PeFileWritten
| FilePath=/(\\\\Temp\\\\|\\\\tmp\\\\|\\\\AppData\\\\Local\\\\Temp\\\\)/i
| select([aid, ComputerName, ContextBaseFileName, FilePath, FileName, SHA256HashData, timestamp])
| groupBy([FileName, SHA256HashData], function=[count(), selectFromMin(field=ComputerName, include=[ComputerName])])
| sort(_count, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('15. Ransomware: Mass File Rename Detection', `
<p>Detects mass file renaming which indicates encryption activity.</p>
${csCode(`event_simpleName=RenameFile
| TargetFileName=/(\.encrypted|\.locked|\.crypt|\.enc|\.pay|\.ransom|\.[a-z]{5,8}$)/i
| groupBy([aid, ComputerName], function=count(), as=rename_count)
| rename_count > 50
| sort(rename_count, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('16. Script Files Written to Disk', `
<p>Monitors creation of script files that could be used for execution.</p>
${csCode(`event_simpleName=NewScriptWritten
| select([aid, ComputerName, ContextBaseFileName, FilePath, FileName, timestamp])
| FileName=/(\.ps1|\.vbs|\.js|\.wsf|\.hta|\.bat|\.cmd)$/i
| FilePath!=/(Windows\\\\ccmcache|SCCM|Intune)/i
| sort(timestamp, order=desc)
| head(100)`, 'logscale')}
`, false)}

<h3 class="cs-mitre-tactic">AUTHENTICATION HUNTING</h3>

${csCollapsible('17. Failed Logon Brute Force Detection', `
<p>Finds accounts with high numbers of failed authentication attempts.</p>
${csCode(`event_simpleName=UserLogonFailed2
| groupBy([UserName, ComputerName], function=count(), as=fail_count)
| fail_count > 10
| sort(fail_count, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('18. Logons Outside Business Hours', `
<p>Detects successful authentications occurring outside normal working hours.</p>
${csCode(`event_simpleName=UserLogon
| LogonType=10 OR LogonType=2
| dayOfWeek := formatTime("%u", field=timestamp, timezone="America/New_York")
| hourOfDay := formatTime("%H", field=timestamp, timezone="America/New_York")
| (dayOfWeek >= 6) OR (hourOfDay < 06) OR (hourOfDay >= 22)
| select([aid, ComputerName, UserName, LogonType, dayOfWeek, hourOfDay, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('19. RDP Logons from External Sources', `
<p>Detects RDP (Type 10) logons that might originate from unusual sources.</p>
${csCode(`event_simpleName=UserLogon
| LogonType=10
| select([aid, ComputerName, UserName, RemoteAddressIP4, timestamp])
| RemoteAddressIP4!=/^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)/
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('20. Service Account Interactive Logons', `
<p>Detects service accounts used for interactive logons (should never happen).</p>
${csCode(`event_simpleName=UserLogon
| LogonType IN [2, 10, 11]
| UserName=/(svc_|service_|sa_|SQL|backup|admin)/i
| select([aid, ComputerName, UserName, LogonType, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('21. Multiple Accounts Used from Single Host', `
<p>Identifies hosts where many different accounts are logging in, which may indicate compromise.</p>
${csCode(`event_simpleName=UserLogon
| LogonType IN [2, 10]
| groupBy([ComputerName], function=[count(UserName, distinct=true, as=unique_users), collect([UserName])])
| unique_users > 5
| sort(unique_users, order=desc)`, 'logscale')}
`, false)}

<h3 class="cs-mitre-tactic">CLOUD & IDENTITY HUNTING</h3>

${csCollapsible('22. New User Account Created', `
<p>Detects creation of new local user accounts which could indicate persistence.</p>
${csCode(`event_simpleName=UserAccountCreated
| select([aid, ComputerName, UserName, UserSid, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('23. User Added to Privileged Group', `
<p>Detects users being added to high-privilege groups like Domain Admins.</p>
${csCode(`event_simpleName=UserGroupMembershipChanged
| GroupName=/(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators)/i
| select([aid, ComputerName, UserName, GroupName, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('24. Suspicious PowerShell Module Loads', `
<p>Detects PowerShell loading offensive modules (PowerSploit, Empire, etc.).</p>
${csCode(`event_simpleName=ProcessRollup2
| FileName IN ["powershell.exe", "pwsh.exe"]
| CommandLine=/(Invoke-Mimikatz|Invoke-TokenManipulation|Invoke-CredentialInjection|Invoke-Shellcode|Invoke-ReflectivePEInjection|Invoke-DllInjection|Get-GPPPassword|Invoke-BloodHound|Invoke-Kerberoast|Invoke-SMBExec|Invoke-WMIExec|Invoke-PowerShellTcp|Get-Keystrokes|PowerView|PowerUp|SharpHound)/i
| select([aid, ComputerName, UserName, CommandLine, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('25. Scheduled Task Creation Events', `
<p>Monitors scheduled task creation for persistence detection.</p>
${csCode(`event_simpleName=ScheduledTaskRegistered
| select([aid, ComputerName, UserName, TaskName, TaskExecCommand, timestamp])
| TaskExecCommand=/(powershell|cmd|wscript|cscript|mshta|http|https|\\\\Temp\\\\|\\\\AppData\\\\)/i
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('26. WMI Persistence (Event Subscription)', `
<p>Detects WMI event subscriptions used for fileless persistence.</p>
${csCode(`event_simpleName=WmiCreateProcess OR event_simpleName=ProcessRollup2
| (FileName=scrcons.exe) OR (ParentBaseFileName=WmiPrvSE.exe AND FileName IN ["cmd.exe","powershell.exe"])
| select([aid, ComputerName, FileName, CommandLine, ParentBaseFileName, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('27. Detect Use of Alternate Data Streams', `
<p>Detects writing to NTFS Alternate Data Streams which can hide malicious content.</p>
${csCode(`event_simpleName=ProcessRollup2
| CommandLine=/:/
| CommandLine=/(type.*>.*:.*|streams|dir.*\\/r)/i
| select([aid, ComputerName, FileName, CommandLine, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('28. Process Running with SYSTEM Privileges from User Context', `
<p>Detects potential privilege escalation where user-initiated processes obtain SYSTEM privileges.</p>
${csCode(`event_simpleName=ProcessRollup2
| UserSid=/S-1-5-18/
| ParentBaseFileName!=/(services|svchost|wininit|lsass|System|smss|csrss)\\.exe/i
| select([aid, ComputerName, UserName, UserSid, FileName, ParentBaseFileName, CommandLine, timestamp])
| sort(timestamp, order=desc)
| head(50)`, 'logscale')}
`, false)}

${csCollapsible('29. Cleartext Password in Command Line', `
<p>Detects potential password exposure in command line arguments.</p>
${csCode(`event_simpleName=ProcessRollup2
| CommandLine=/(password|passwd|pwd|credentials|secret)\\s*[=:]/i
| CommandLine!=/(Get-Help|man |--help|\\?$)/
| select([aid, ComputerName, UserName, FileName, CommandLine, timestamp])
| sort(timestamp, order=desc)`, 'logscale')}
`, false)}

${csCollapsible('30. Hunt for Rare Processes Across Environment', `
<p>Find processes that are unique or very rare across all endpoints — good for finding attacker tools.</p>
${csCode(`event_simpleName=ProcessRollup2
| groupBy([FileName], function=[count(), collect([ComputerName], limit=5)])
| _count <= 3
| sort(_count, order=asc)
| head(100)

// This shows processes that ran on 3 or fewer endpoints
// Investigate each one — attacker tools will be rare`, 'logscale')}
`, false)}
`;
}

function buildTab4_RTR() {
    return `
<h2 class="cs-section-title">REAL TIME RESPONSE (RTR) COMPLETE GUIDE</h2>
<p class="cs-note">RTR provides remote shell access to managed endpoints directly from the Falcon console. Navigate to <strong>Host management > select host > Connect</strong>.</p>

<div class="cs-warning">RTR access levels are role-based. Ensure your account has the appropriate permissions: <strong>Real Time Response - Read Only</strong>, <strong>Active Responder</strong>, or <strong>Real Time Response Admin</strong>.</div>

<h3>RTR ACCESS LEVELS</h3>
<table class="cs-table">
<tr><th>Level</th><th>Permissions</th><th>Use Case</th></tr>
<tr><td>Read Only Analyst</td><td>View system state, no modifications</td><td>Triage, investigation</td></tr>
<tr><td>Active Responder</td><td>Read + modify files, kill processes, quarantine</td><td>Incident response</td></tr>
<tr><td>RTR Admin</td><td>Full access + custom scripts + put files</td><td>Advanced remediation</td></tr>
</table>

${csCollapsible('READ-ONLY COMMANDS', `
<h4>cat — Display file contents</h4>
${csCode(`cat "C:\\Windows\\System32\\drivers\\etc\\hosts"
cat /etc/passwd
cat /etc/crontab`, 'rtr')}

<h4>cd — Change directory</h4>
${csCode(`cd C:\\Users\\Administrator\\Desktop
cd /var/log`, 'rtr')}

<h4>env — Show environment variables</h4>
${csCode(`env
# Useful for finding PATH hijacking, proxy settings, temp paths`, 'rtr')}

<h4>eventlog — Query Windows Event Logs</h4>
${csCode(`# List available event logs
eventlog list

# View Security log (last 50 entries)
eventlog view Security --count 50

# Backup event log for offline analysis
eventlog backup Security "C:\\temp\\security.evtx"`, 'rtr')}

<h4>filehash — Calculate file hash</h4>
${csCode(`filehash "C:\\Windows\\Temp\\suspicious.exe"
filehash /tmp/malware_sample
# Returns MD5, SHA1, SHA256 — compare with VirusTotal/MalwareBazaar`, 'rtr')}

<h4>getsid — Get SID for user</h4>
${csCode(`getsid Administrator
getsid "DOMAIN\\username"`, 'rtr')}

<h4>ifconfig / ipconfig — Network interface configuration</h4>
${csCode(`# Windows
ipconfig

# Linux/macOS
ifconfig`, 'rtr')}

<h4>ls — List directory contents</h4>
${csCode(`ls C:\\Users\\Administrator\\Desktop
ls C:\\Windows\\Temp
ls /tmp
ls -la /etc/cron.d`, 'rtr')}

<h4>mount — Show mounted filesystems</h4>
${csCode(`mount
# Linux: shows all mount points
# Useful for finding mounted network shares or unusual mounts`, 'rtr')}

<h4>netstat — Network connections</h4>
${csCode(`netstat
# Shows all active connections
# Look for:
#   - Unusual ESTABLISHED connections to external IPs
#   - LISTENING ports that should not be open
#   - Connections from unexpected processes`, 'rtr')}

<h4>ps — List running processes</h4>
${csCode(`ps
# Shows PID, process name, memory usage, user context
# Look for:
#   - Processes running from temp directories
#   - Unsigned processes running as SYSTEM
#   - Duplicate system process names (process masquerading)`, 'rtr')}

<h4>reg — Query registry (read-only)</h4>
${csCode(`# Check Run keys for persistence
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

# Check installed services
reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\SuspiciousService

# Check Windows Firewall state
reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy`, 'rtr')}

<h4>users — List logged-in users</h4>
${csCode(`users
# Shows active sessions, login time, source IP (for RDP sessions)`, 'rtr')}
`, true)}

${csCollapsible('ACTIVE RESPONDER COMMANDS', `
<h4>cp — Copy files</h4>
${csCode(`cp "C:\\Users\\Admin\\malware.exe" "C:\\quarantine\\malware.exe"`, 'rtr')}

<h4>get — Download file from endpoint</h4>
${csCode(`# Download suspicious file for analysis
get "C:\\Windows\\Temp\\suspicious.exe"
get "C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.dll"
get /tmp/backdoor.elf

# File downloads to Falcon console for retrieval
# Maximum file size: 4 GB`, 'rtr')}

<h4>kill — Terminate process</h4>
${csCode(`# Kill by PID
kill 1234

# First identify the PID with ps, then kill
# Example: Kill suspicious PowerShell
ps
# Find PID of malicious powershell.exe
kill 5678`, 'rtr')}

<h4>memdump — Dump process memory</h4>
${csCode(`# Full process memory dump
memdump 1234
# Downloads as .dmp file for analysis in WinDbg or Volatility

# Useful for:
# - Extracting C2 config from beacon memory
# - Recovering encryption keys
# - Identifying injected code`, 'rtr')}

<h4>mkdir — Create directory</h4>
${csCode(`mkdir C:\\quarantine
mkdir /tmp/investigation`, 'rtr')}

<h4>mv — Move files</h4>
${csCode(`mv "C:\\Users\\Admin\\malware.exe" "C:\\quarantine\\malware.exe.quarantined"`, 'rtr')}

<h4>put — Upload file to endpoint</h4>
${csCode(`# Upload remediation tools or scripts
# Files must first be uploaded to the RTR Cloud (Falcon console > RTR > Put Files)
put "remediation_script.ps1"
put "autoruns.exe"`, 'rtr')}

<h4>reg (write) — Modify registry</h4>
${csCode(`# Remove malicious Run key
reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v MaliciousEntry /f

# Disable a malicious service
reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\BadService /v Start /t REG_DWORD /d 4 /f`, 'rtr')}

<h4>rm — Remove files</h4>
${csCode(`rm "C:\\Windows\\Temp\\malware.exe"
rm "C:\\Users\\Public\\beacon.dll"
rm /tmp/backdoor.sh`, 'rtr')}

<h4>remediate — Auto-remediate detections</h4>
${csCode(`# Quarantine a detected file by SHA256
remediate --quarantine --sha256 abc123def456...

# Remediate a specific detection
remediate --detection-id ldt:abc123:456`, 'rtr')}

<h4>runscript — Execute scripts on endpoint</h4>
${csCode(`# Run a pre-uploaded RTR script
runscript -CloudFile="CollectArtifacts" -CommandLine=""
runscript -CloudFile="RemovePersistence" -CommandLine="ServiceName"

# Run inline PowerShell
runscript -Raw="Get-Process | Where-Object {\$_.Path -like '*Temp*'}"

# Run inline shell (Linux)
runscript -Raw="find / -name '*.sh' -mtime -1 2>/dev/null"`, 'rtr')}

<h4>zip — Compress files for collection</h4>
${csCode(`zip "C:\\evidence\\collected_artifacts.zip" "C:\\Users\\Admin\\AppData\\Local\\Temp\\*"`, 'rtr')}

<h4>Network Contain / Uncontain</h4>
${csCode(`# Network contain isolates the host from everything except CrowdStrike cloud
# Done via the Falcon console: Host Management > Select Host > Network Contain

# Via API:
curl -X POST "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"ids": ["DEVICE_AID"]}'

# To lift containment:
curl -X POST "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=lift_containment" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"ids": ["DEVICE_AID"]}'`, 'bash')}
`, true)}

${csCollapsible('RTR SCRIPTS LIBRARY — 10 Ready-to-Use Scripts', `
<h4>Script 1: Collect Forensic Triage Package</h4>
${csCode(`# RTR Script: CollectTriagePackage
# Upload as RTR Cloud Script, then run: runscript -CloudFile="CollectTriagePackage"

$outputDir = "C:\\CrowdStrike_Triage_\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $outputDir -Force

# Collect running processes
Get-Process | Select-Object Name, Id, Path, StartTime, CPU, WorkingSet | Export-Csv "$outputDir\\processes.csv" -NoTypeInformation

# Collect network connections
Get-NetTCPConnection | Where-Object {\$_.State -eq 'Established'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State | Export-Csv "$outputDir\\network.csv" -NoTypeInformation

# Collect scheduled tasks
Get-ScheduledTask | Where-Object {\$_.State -ne 'Disabled'} | Select-Object TaskName, TaskPath, State, Author | Export-Csv "$outputDir\\tasks.csv" -NoTypeInformation

# Collect services
Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv "$outputDir\\services.csv" -NoTypeInformation

# Collect auto-run entries
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -ErrorAction SilentlyContinue | Out-File "$outputDir\\autoruns_hklm.txt"
Get-ItemProperty "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -ErrorAction SilentlyContinue | Out-File "$outputDir\\autoruns_hkcu.txt"

# Collect recent event logs
Get-WinEvent -LogName Security -MaxEvents 500 | Export-Csv "$outputDir\\security_events.csv" -NoTypeInformation
Get-WinEvent -LogName System -MaxEvents 500 | Export-Csv "$outputDir\\system_events.csv" -NoTypeInformation

# Compress
Compress-Archive -Path "$outputDir\\*" -DestinationPath "$outputDir.zip"
Write-Output "Triage package created: $outputDir.zip"`, 'powershell')}

<h4>Script 2: Hunt for Persistence Mechanisms</h4>
${csCode(`# RTR Script: HuntPersistence
$results = @()

# Run keys
$runKeys = @(
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
)
foreach ($key in $runKeys) {
    $entries = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($entries) { $results += "=== $key ==="; $entries.PSObject.Properties | ForEach-Object { $results += "  $($_.Name) = $($_.Value)" } }
}

# Scheduled tasks with actions
$results += "\`n=== Scheduled Tasks with Executable Actions ==="
Get-ScheduledTask | ForEach-Object {
    $actions = $_.Actions | Where-Object { $_.Execute }
    if ($actions) { $results += "  Task: $($_.TaskName) | Exec: $($actions.Execute) $($actions.Arguments)" }
}

# Services with non-standard paths
$results += "\`n=== Non-Standard Services ==="
Get-WmiObject Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch 'Windows|System32|Program Files' } | ForEach-Object {
    $results += "  $($_.Name) | $($_.PathName) | $($_.State)"
}

# WMI subscriptions
$results += "\`n=== WMI Event Subscriptions ==="
Get-WmiObject -Namespace root\\subscription -Class __EventFilter -ErrorAction SilentlyContinue | ForEach-Object { $results += "  Filter: $($_.Name) | Query: $($_.Query)" }
Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { $results += "  Consumer: $($_.Name) | Cmd: $($_.CommandLineTemplate)" }

$results | Out-String`, 'powershell')}

<h4>Script 3: Kill Process Tree</h4>
${csCode(`# RTR Script: KillProcessTree
# Usage: runscript -CloudFile="KillProcessTree" -CommandLine="ProcessName"
param([string]$ProcessName)

function Kill-ProcessTree {
    param([int]$ParentId)
    Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $ParentId } | ForEach-Object {
        Kill-ProcessTree -ParentId $_.ProcessId
        Write-Output "Killing child process: $($_.Name) (PID: $($_.ProcessId))"
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

$procs = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
foreach ($proc in $procs) {
    Write-Output "Killing process tree rooted at: $($proc.Name) (PID: $($proc.Id))"
    Kill-ProcessTree -ParentId $proc.Id
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
Write-Output "Done."`, 'powershell')}

<h4>Script 4: Collect Browser Artifacts</h4>
${csCode(`# RTR Script: CollectBrowserArtifacts
$outputDir = "C:\\browser_artifacts_\$(Get-Date -Format 'yyyyMMdd')"
New-Item -ItemType Directory -Path $outputDir -Force

$users = Get-ChildItem C:\\Users -Directory

foreach ($user in $users) {
    $base = $user.FullName
    # Chrome history
    $chromeHistory = "$base\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
    if (Test-Path $chromeHistory) { Copy-Item $chromeHistory "$outputDir\\$($user.Name)_chrome_history" -Force }
    # Edge history
    $edgeHistory = "$base\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"
    if (Test-Path $edgeHistory) { Copy-Item $edgeHistory "$outputDir\\$($user.Name)_edge_history" -Force }
    # Firefox
    $ffProfile = Get-ChildItem "$base\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-release" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($ffProfile) { Copy-Item "$($ffProfile.FullName)\\places.sqlite" "$outputDir\\$($user.Name)_firefox_places.sqlite" -Force -ErrorAction SilentlyContinue }
}
Compress-Archive -Path "$outputDir\\*" -DestinationPath "$outputDir.zip"
Write-Output "Browser artifacts collected: $outputDir.zip"`, 'powershell')}

<h4>Script 5: Remove Malicious Scheduled Task</h4>
${csCode(`# RTR Script: RemoveScheduledTask
# Usage: runscript -CloudFile="RemoveScheduledTask" -CommandLine="TaskName"
param([string]$TaskName)
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Output "Removed scheduled task: $TaskName"
} else {
    Write-Output "Task not found: $TaskName"
}`, 'powershell')}

<h4>Script 6: Check for Open Shares</h4>
${csCode(`# RTR Script: CheckOpenShares
Get-SmbShare | Where-Object { $_.Name -notmatch '^(ADMIN|IPC|C|D)\\$' } | Select-Object Name, Path, Description | Format-Table -AutoSize
Get-SmbShareAccess -Name * -ErrorAction SilentlyContinue | Where-Object { $_.AccountName -match 'Everyone|Users|Authenticated' } | Format-Table -AutoSize`, 'powershell')}

<h4>Script 7: Quarantine Suspicious File</h4>
${csCode(`# RTR Script: QuarantineFile
# Usage: runscript -CloudFile="QuarantineFile" -CommandLine="C:\\path\\to\\file.exe"
param([string]$FilePath)

$quarantineDir = "C:\\CrowdStrike_Quarantine"
if (!(Test-Path $quarantineDir)) { New-Item -ItemType Directory -Path $quarantineDir -Force }

if (Test-Path $FilePath) {
    $hash = (Get-FileHash $FilePath -Algorithm SHA256).Hash
    $dest = "$quarantineDir\\$hash.quarantined"
    Move-Item $FilePath $dest -Force
    # Log the quarantine action
    "$((Get-Date).ToString()) | $FilePath | SHA256: $hash | Moved to $dest" | Out-File "$quarantineDir\\quarantine_log.txt" -Append
    Write-Output "Quarantined: $FilePath -> $dest (SHA256: $hash)"
} else {
    Write-Output "File not found: $FilePath"
}`, 'powershell')}

<h4>Script 8: Collect Prefetch Files</h4>
${csCode(`# RTR Script: CollectPrefetch
$prefetchDir = "C:\\Windows\\Prefetch"
$outputZip = "C:\\prefetch_collection_\$(Get-Date -Format 'yyyyMMdd').zip"

if (Test-Path $prefetchDir) {
    Compress-Archive -Path "$prefetchDir\\*.pf" -DestinationPath $outputZip -Force
    $count = (Get-ChildItem "$prefetchDir\\*.pf").Count
    Write-Output "Collected $count prefetch files to $outputZip"
} else {
    Write-Output "Prefetch directory not found (may be disabled)"
}`, 'powershell')}

<h4>Script 9: Linux — Collect Cron and Startup Persistence</h4>
${csCode(`#!/bin/bash
# RTR Script: LinuxPersistenceHunt
OUTPUT="/tmp/linux_persistence_$(date +%Y%m%d).txt"

echo "=== CRON JOBS (all users) ===" > $OUTPUT
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u $user 2>/dev/null && echo "--- User: $user ---" >> $OUTPUT
done
cat /etc/crontab >> $OUTPUT 2>/dev/null
ls -la /etc/cron.d/ >> $OUTPUT 2>/dev/null
ls -la /etc/cron.daily/ >> $OUTPUT 2>/dev/null

echo -e "\\n=== SYSTEMD SERVICES (enabled) ===" >> $OUTPUT
systemctl list-unit-files --type=service --state=enabled >> $OUTPUT 2>/dev/null

echo -e "\\n=== /etc/rc.local ===" >> $OUTPUT
cat /etc/rc.local >> $OUTPUT 2>/dev/null

echo -e "\\n=== INIT.D SCRIPTS ===" >> $OUTPUT
ls -la /etc/init.d/ >> $OUTPUT 2>/dev/null

echo -e "\\n=== AUTHORIZED_KEYS ===" >> $OUTPUT
find /home -name "authorized_keys" -exec echo "--- {} ---" \\; -exec cat {} \\; >> $OUTPUT 2>/dev/null
cat /root/.ssh/authorized_keys >> $OUTPUT 2>/dev/null

echo -e "\\n=== LD_PRELOAD ===" >> $OUTPUT
cat /etc/ld.so.preload >> $OUTPUT 2>/dev/null
env | grep LD_PRELOAD >> $OUTPUT 2>/dev/null

cat $OUTPUT`, 'bash')}

<h4>Script 10: Network IOC Check</h4>
${csCode(`# RTR Script: NetworkIOCCheck
# Checks current connections against a list of known bad IPs/domains
param([string]$IOCList)

# Get all established connections
$connections = Get-NetTCPConnection -State Established | Select-Object RemoteAddress, RemotePort, OwningProcess

# DNS cache
$dnsCache = Get-DnsClientCache | Select-Object Entry, Data

Write-Output "=== Active Connections ==="
foreach ($conn in $connections) {
    $proc = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
    Write-Output "$($conn.RemoteAddress):$($conn.RemotePort) - PID: $($conn.OwningProcess) ($proc)"
}

Write-Output "\`n=== DNS Cache Entries (last resolved) ==="
$dnsCache | ForEach-Object { Write-Output "$($_.Entry) -> $($_.Data)" }

Write-Output "\`n=== Listening Ports ==="
Get-NetTCPConnection -State Listen | ForEach-Object {
    $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
    Write-Output "Port $($_.LocalPort) - PID: $($_.OwningProcess) ($proc)"
}`, 'powershell')}
`, true)}

${csCollapsible('CUSTOM SCRIPT DEPLOYMENT GUIDE', `
<h3>How to Deploy Custom RTR Scripts</h3>
<ol>
<li><strong>Create the script</strong> — PowerShell (.ps1) for Windows, Bash (.sh) for Linux/macOS</li>
<li><strong>Upload to RTR Cloud</strong>:
    <ul>
    <li>Navigate to <strong>Host setup and management > Real Time Response > Scripts</strong></li>
    <li>Click <strong>Upload Script</strong></li>
    <li>Give it a descriptive name (this is the CloudFile name)</li>
    <li>Set permissions: who can run this script</li>
    <li>Set platform: Windows, Linux, macOS</li>
    </ul>
</li>
<li><strong>Run the script</strong>:
${csCode(`# In an RTR session:
runscript -CloudFile="ScriptName" -CommandLine="optional arguments"

# Via API (batch RTR):
curl -X POST "https://api.crowdstrike.com/real-time-response/combined/batch-active-responder-command/v1" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "base_command": "runscript",
    "batch_id": "BATCH_SESSION_ID",
    "command_string": "runscript -CloudFile=ScriptName",
    "optional_hosts": ["AID1","AID2"]
  }'`, 'bash')}
</li>
</ol>

<h3>RTR Script Best Practices</h3>
<ul>
<li>Always test scripts on a canary endpoint first</li>
<li>Include error handling and output messages</li>
<li>Use parameters for flexibility (don't hardcode values)</li>
<li>Log all actions taken for audit trail</li>
<li>Set appropriate timeouts (default RTR script timeout is 30 seconds, can be extended)</li>
<li>Use <code>-Timeout=120</code> for longer-running scripts</li>
</ul>
`, true)}
`;
}

function buildTab5_PreventionPolicies() {
    return `
<h2 class="cs-section-title">PREVENTION POLICIES — COMPLETE REFERENCE</h2>
<p class="cs-note">Navigate to <strong>Endpoint security > Configure > Prevention policies</strong> in the Falcon console. Each setting below maps to a toggle in the policy editor.</p>

${csCollapsible('CLOUD MACHINE LEARNING ANALYSIS', `
<h3>What It Does</h3>
<p>Files are uploaded to the CrowdStrike cloud for ML analysis when first seen. The cloud ML engine uses multiple models trained on millions of malware samples.</p>

<h3>Settings</h3>
<table class="cs-table">
<tr><th>Setting</th><th>Detection Sensitivity</th><th>Prevention Sensitivity</th></tr>
<tr><td>Disabled</td><td>No cloud analysis</td><td>No blocking</td></tr>
<tr><td>Cautious</td><td>High confidence malware only (~99% sure)</td><td>Block only highest confidence</td></tr>
<tr><td>Moderate</td><td>Medium+ confidence (~95% sure)</td><td>Block medium+ confidence</td></tr>
<tr><td>Aggressive</td><td>Low+ confidence (~85% sure)</td><td>Block even borderline detections</td></tr>
<tr><td>Extra Aggressive</td><td>Very low threshold</td><td>Maximum blocking (highest FP rate)</td></tr>
</table>

<h3>POC Recommendation</h3>
<ul>
<li>Week 1: Detect=Moderate, Prevent=Disabled</li>
<li>Week 2: Detect=Aggressive, Prevent=Cautious</li>
<li>Week 3+: Detect=Aggressive, Prevent=Aggressive</li>
</ul>
`, true)}

${csCollapsible('SENSOR MACHINE LEARNING ANALYSIS', `
<h3>What It Does</h3>
<p>On-sensor ML model that can classify files <strong>without cloud connectivity</strong>. Critical for air-gapped or intermittently connected endpoints. Smaller model than cloud but works offline.</p>

<h3>Settings</h3>
<table class="cs-table">
<tr><th>Setting</th><th>Description</th></tr>
<tr><td>Detection: Cautious/Moderate/Aggressive</td><td>Sensitivity for generating alerts</td></tr>
<tr><td>Prevention: Cautious/Moderate/Aggressive</td><td>Sensitivity for blocking execution</td></tr>
</table>

<h3>POC Recommendation</h3>
<ul>
<li>Always enable sensor ML even if you have cloud ML (defense in depth)</li>
<li>Set slightly less aggressive than cloud to reduce FP (cloud is more accurate)</li>
<li>Week 1: Detect=Moderate, Prevent=Disabled</li>
<li>Week 3+: Detect=Aggressive, Prevent=Moderate</li>
</ul>
`, true)}

${csCollapsible('ADWARE & PUP DETECTION', `
<h3>Settings</h3>
<table class="cs-table">
<tr><th>Toggle</th><th>What It Catches</th></tr>
<tr><td>Detect Adware</td><td>Advertising software, browser toolbars, bundleware</td></tr>
<tr><td>Prevent Adware</td><td>Block adware from executing</td></tr>
<tr><td>Detect PUP</td><td>Potentially Unwanted Programs (download managers, system "optimizers")</td></tr>
<tr><td>Prevent PUP</td><td>Block PUPs from executing</td></tr>
</table>
<p><strong>POC Tip:</strong> Enable detection for both. Only enable prevention if client wants strict control. Can generate noise in environments with lots of freeware.</p>
`, true)}

${csCollapsible('ON-WRITE vs ON-SENSOR ML ANALYSIS', `
<h3>On-Write Analysis</h3>
<p>Scans files <strong>when they are written to disk</strong> (downloaded, copied, extracted). This catches malware before it runs.</p>

<h3>On-Sensor ML</h3>
<p>Uses the local ML model to classify files. Works offline. Complements cloud ML.</p>

<h3>How They Work Together</h3>
<ol>
<li>File written to disk → <strong>On-Write</strong> scan triggers</li>
<li>On-Write sends hash to cloud → <strong>Cloud ML</strong> checks known database + runs ML</li>
<li>If cloud is unavailable → <strong>Sensor ML</strong> classifies locally</li>
<li>If file executes → <strong>Behavioral IOA</strong> engine monitors runtime behavior</li>
</ol>
<p>All four layers work together. Enable all for maximum coverage.</p>
`, true)}

${csCollapsible('EXPLOIT MITIGATION', `
<h3>What It Does</h3>
<p>Protects against exploitation of vulnerabilities using process-level memory protection techniques.</p>

<h3>Individual Settings</h3>
<table class="cs-table">
<tr><th>Setting</th><th>What It Prevents</th></tr>
<tr><td>DEP (Data Execution Prevention)</td><td>Executing code from data memory regions</td></tr>
<tr><td>ASLR (Address Space Layout Randomization)</td><td>Predictable memory addresses for exploitation</td></tr>
<tr><td>Stack Pivot Detection</td><td>ROP chains pivoting the stack to attacker-controlled memory</td></tr>
<tr><td>ROP (Return-Oriented Programming)</td><td>Code reuse attacks chaining existing code gadgets</td></tr>
<tr><td>SEH (Structured Exception Handler) Overwrite</td><td>Exception handler hijacking for code execution</td></tr>
<tr><td>Heap Spray Preallocation</td><td>Heap spraying to place shellcode at predictable addresses</td></tr>
<tr><td>Null Page Allocation</td><td>Null pointer dereference exploitation</td></tr>
<tr><td>JIT (Just-In-Time) Spray</td><td>Exploiting JIT compilers to place controlled code in executable memory</td></tr>
</table>

<h3>POC Recommendation</h3>
<p>Enable ALL exploit mitigations in Prevent mode from Day 1. These have extremely low false positive rates and protect against zero-day exploits.</p>
`, true)}

${csCollapsible('PROCESS HOLLOWING / INJECTION PROTECTION', `
<h3>Process Hollowing</h3>
<p>Detects when a legitimate process is started in suspended state, its code is replaced with malicious code, then resumed. Common in sophisticated malware.</p>

<h3>Process Injection</h3>
<p>Detects various injection techniques: DLL injection, reflective DLL loading, process doppelganging, atom bombing, etc.</p>

<h3>Settings</h3>
<table class="cs-table">
<tr><th>Toggle</th><th>Recommendation</th></tr>
<tr><td>Detect Process Hollowing</td><td>ENABLED always</td></tr>
<tr><td>Prevent Process Hollowing</td><td>ENABLED (very low FP)</td></tr>
<tr><td>Detect Code Injection</td><td>ENABLED always</td></tr>
<tr><td>Prevent Code Injection</td><td>Enable after Week 1 (some legitimate tools inject)</td></tr>
</table>
`, true)}

${csCollapsible('CREDENTIAL GUARD', `
<h3>What It Does</h3>
<p>Protects credential storage mechanisms including LSASS, SAM database, and cached credentials. Works alongside Windows Credential Guard but provides additional sensor-level protection.</p>

<h3>Settings</h3>
<table class="cs-table">
<tr><th>Toggle</th><th>Protection</th></tr>
<tr><td>LSASS Read Protection</td><td>Prevents non-standard processes from reading LSASS memory (blocks Mimikatz)</td></tr>
<tr><td>Credential Dumping Prevention</td><td>Blocks known credential dumping techniques</td></tr>
</table>

<p><strong>POC Recommendation:</strong> Enable detection Day 1, prevention Day 3 (after verifying no false positives with legitimate security tools that may access LSASS).</p>
`, true)}

${csCollapsible('SCRIPT-BASED EXECUTION MONITORING', `
<h3>What It Covers</h3>
<ul>
<li><strong>PowerShell</strong> — Script block logging, AMSI integration, encoded command detection</li>
<li><strong>VBScript/JScript</strong> — via wscript.exe and cscript.exe</li>
<li><strong>Python/Perl/Ruby</strong> — Script interpreter monitoring</li>
<li><strong>Bash/Shell</strong> — Linux/macOS command monitoring</li>
<li><strong>Office Macros</strong> — VBA macro execution monitoring</li>
</ul>

<h3>Settings</h3>
<table class="cs-table">
<tr><th>Toggle</th><th>What It Does</th></tr>
<tr><td>Script-Based Execution Monitoring</td><td>Captures and analyzes script content at execution time</td></tr>
<tr><td>Suspicious Scripts</td><td>Detect/Prevent scripts matching known malicious patterns</td></tr>
<tr><td>Enhanced Visibility</td><td>Sends full script content to cloud for ML analysis</td></tr>
</table>

<p><strong>POC Recommendation:</strong> Enable all monitoring from Day 1. Set suspicious scripts to Detect first, then Prevent after tuning (PowerShell-heavy environments may generate FPs).</p>
`, true)}

${csCollapsible('IOA BEHAVIORAL PREVENTION', `
<h3>What It Does</h3>
<p>Indicators of Attack (IOA) are behavioral rules that detect attack patterns regardless of the tool used. This is CrowdStrike's core differentiator — it catches zero-days and novel attacks by behavior, not signature.</p>

<h3>IOA Categories</h3>
<table class="cs-table">
<tr><th>Category</th><th>Examples</th></tr>
<tr><td>Ransomware</td><td>Mass file encryption, shadow copy deletion, ransom note creation</td></tr>
<tr><td>Credential Theft</td><td>LSASS access, SAM dump, DCSync, Kerberoasting</td></tr>
<tr><td>Lateral Movement</td><td>PsExec, WMI remote, SMB exploitation, RDP tunneling</td></tr>
<tr><td>Defense Evasion</td><td>Process injection, DLL side-loading, AMSI bypass, ETW tampering</td></tr>
<tr><td>Execution</td><td>LOLBin abuse, macro execution, fileless attacks</td></tr>
<tr><td>Persistence</td><td>Registry run keys, scheduled tasks, WMI subscriptions, services</td></tr>
<tr><td>Command & Control</td><td>Beaconing, DNS tunneling, domain fronting, encrypted channels</td></tr>
</table>

<h3>POC Phased Approach</h3>
<ul>
<li><strong>Week 1:</strong> All IOAs in Detect mode — observe what triggers</li>
<li><strong>Week 2:</strong> Enable Prevent for Ransomware, Credential Theft, Exploitation</li>
<li><strong>Week 3:</strong> Enable Prevent for all remaining categories after tuning</li>
</ul>
`, true)}

${csCollapsible('USB DEVICE CONTROL', `
<p>See Tab 1, Section 8 for USB Device Control details.</p>
<h3>Policy Settings Summary</h3>
<table class="cs-table">
<tr><th>Setting</th><th>Options</th></tr>
<tr><td>Enable Device Control</td><td>On/Off</td></tr>
<tr><td>Default Action</td><td>Allow All / Block All / Read Only</td></tr>
<tr><td>Class Exceptions</td><td>Per USB device class (storage, printer, etc.)</td></tr>
<tr><td>Vendor/Product Exceptions</td><td>Whitelist specific devices by VID:PID</td></tr>
<tr><td>Serial Number Exceptions</td><td>Whitelist individual devices by serial</td></tr>
</table>
`, true)}

${csCollapsible('FIREWALL MANAGEMENT', `
<p>See Tab 1, Section 9 for Firewall Management details.</p>
<h3>Policy Settings Summary</h3>
<ul>
<li>Manage Windows Firewall through Falcon console</li>
<li>Create firewall rule groups with ordered rules</li>
<li>Rules support: IP, port, protocol, direction, application path</li>
<li>Monitor mode available for POC (log but don't enforce)</li>
<li>Assign rule groups to host groups for granular control</li>
</ul>
`, true)}

${csCollapsible('DISK ENCRYPTION (BitLocker Management)', `
<h3>What It Does</h3>
<p>Manage and enforce BitLocker encryption on Windows endpoints through Falcon.</p>

<h3>Settings</h3>
<table class="cs-table">
<tr><th>Setting</th><th>Description</th></tr>
<tr><td>Enforce Encryption</td><td>Require BitLocker on OS drive</td></tr>
<tr><td>Encryption Algorithm</td><td>AES-128 or AES-256 (recommend 256)</td></tr>
<tr><td>Recovery Key Escrow</td><td>Store BitLocker recovery keys in Falcon console</td></tr>
<tr><td>Encrypt Used Space Only</td><td>Faster initial encryption (vs full disk)</td></tr>
</table>

<p><strong>POC Note:</strong> Only enable if client specifically wants to evaluate BitLocker management. Not typically part of EDR POC scope.</p>
`, true)}

${csCollapsible('IDENTITY PROTECTION SETTINGS', `
<h3>Falcon Identity Protection (requires module)</h3>
<p>Extends CrowdStrike to Active Directory and identity-based attacks.</p>

<h3>Key Settings</h3>
<table class="cs-table">
<tr><th>Setting</th><th>What It Does</th></tr>
<tr><td>Honey Token Detection</td><td>Alerts when decoy accounts are used</td></tr>
<tr><td>Risky Authentication Detection</td><td>Flags unusual authentication patterns</td></tr>
<tr><td>Pass-the-Hash Detection</td><td>Detects NTLM hash reuse across hosts</td></tr>
<tr><td>Golden Ticket Detection</td><td>Identifies forged Kerberos tickets</td></tr>
<tr><td>DCSync Detection</td><td>Alerts on unauthorized directory replication</td></tr>
<tr><td>Lateral Movement Detection</td><td>Correlates authentication events across hosts</td></tr>
<tr><td>Conditional Access Policies</td><td>Enforce MFA/block based on risk score</td></tr>
</table>

<p><strong>POC Note:</strong> If the client has Falcon Identity Protection licensed, demonstrate it. It is a massive differentiator against competitors.</p>
`, true)}
`;
}

function buildTab6_FusionSOAR() {
    return `
<h2 class="cs-section-title">FALCON FUSION / SOAR WORKFLOWS</h2>
<p class="cs-note">Falcon Fusion is CrowdStrike's built-in SOAR (Security Orchestration, Automation, and Response). Access via <strong>Endpoint security > Detections > Fusion Workflows</strong> or the Fusion SOAR standalone module.</p>

${csCollapsible('Workflow 1: Auto-Contain Host on Critical Detection', `
<h3>Trigger</h3>
<p>Detection with severity = Critical AND tactic = Execution or Lateral Movement</p>

<h3>Workflow Steps</h3>
<ol>
<li><strong>Trigger:</strong> New Detection (Severity: Critical)</li>
<li><strong>Condition:</strong> Check if host is NOT in "VIP-No-Contain" group</li>
<li><strong>Action:</strong> Network Contain Host</li>
<li><strong>Action:</strong> Send notification to SOC Slack channel</li>
<li><strong>Action:</strong> Create high-priority ticket in ServiceNow</li>
<li><strong>Action:</strong> Send email to incident-response@company.com</li>
</ol>

${csCode(`Fusion Workflow Configuration:
  Trigger: Detection
    Severity: Critical
    Tactic: Any

  Condition: Host Group
    Host NOT IN group: "VIP-Servers-No-AutoContain"

  Action 1: Contain Host
    Target: Triggering device

  Action 2: Notification
    Type: Slack Webhook
    URL: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
    Message: "CRITICAL: Host {{hostname}} auto-contained. Detection: {{detection_name}} | Tactic: {{tactic}} | User: {{user_name}}"

  Action 3: Create Ticket
    Integration: ServiceNow
    Priority: P1
    Title: "CrowdStrike Critical Detection - {{hostname}}"
    Description: "Auto-contained host. Detection details: {{detection_description}}"`, 'yaml')}
`, true)}

${csCollapsible('Workflow 2: Auto-Disable Compromised User Account', `
<h3>Trigger</h3>
<p>Detection indicating credential theft or identity compromise</p>

<h3>Workflow Steps</h3>
<ol>
<li><strong>Trigger:</strong> Detection with tactic = Credential Access, severity >= High</li>
<li><strong>Action:</strong> Disable user account in Active Directory (via Falcon Identity or API)</li>
<li><strong>Action:</strong> Force password reset</li>
<li><strong>Action:</strong> Revoke all active sessions (if Azure AD integrated)</li>
<li><strong>Action:</strong> Notify user's manager and SOC</li>
</ol>

${csCode(`Fusion Workflow Configuration:
  Trigger: Detection
    Tactic: Credential Access
    Severity: High, Critical

  Action 1: Identity Protection
    Action: Disable Account
    Target: {{user_name}}

  Action 2: Notification
    Type: Email
    To: security-ops@company.com, {{user_manager_email}}
    Subject: "Account Disabled: {{user_name}} - Credential Compromise Detected"
    Body: "The account {{user_name}} has been automatically disabled due to credential theft detection on {{hostname}}."`, 'yaml')}
`, true)}

${csCollapsible('Workflow 3: Create ServiceNow Ticket on Detection', `
<h3>Trigger</h3>
<p>Any detection with severity Medium or above</p>

${csCode(`Fusion Workflow Configuration:
  Trigger: Detection
    Severity: Medium, High, Critical

  Action: Create ServiceNow Incident
    Integration: ServiceNow (configure in Falcon Store > Integrations)
    Table: incident
    Fields:
      short_description: "CrowdStrike: {{detection_name}} on {{hostname}}"
      description: |
        Detection Details:
        - Host: {{hostname}} ({{local_ip}})
        - User: {{user_name}}
        - Tactic: {{tactic}}
        - Technique: {{technique}}
        - Severity: {{severity}}
        - Detection ID: {{detection_id}}
        - Link: {{falcon_link}}
      priority: Map severity (Critical=1, High=2, Medium=3)
      assignment_group: "Security Operations"
      category: "Security"`, 'yaml')}
`, true)}

${csCollapsible('Workflow 4: Enrich IOCs with VirusTotal', `
<h3>Trigger</h3>
<p>New IOC (hash, domain, or IP) from a detection</p>

${csCode(`Fusion Workflow Configuration:
  Trigger: Detection (any with SHA256 hash)

  Action 1: API Call - VirusTotal
    Method: GET
    URL: https://www.virustotal.com/api/v3/files/{{sha256}}
    Headers: x-apikey: YOUR_VT_API_KEY

  Condition: Check VT Response
    If positives > 5: Escalate to High priority
    If positives > 15: Auto-block hash globally

  Action 2 (conditional): Add IOC to CrowdStrike
    Type: SHA256
    Action: Block
    Severity: High
    Description: "VT Score: {{vt_positives}}/{{vt_total}} - Auto-blocked"

  Action 3: Update Detection
    Add comment: "VT Enrichment: {{vt_positives}}/{{vt_total}} detections. First seen: {{vt_first_seen}}"`, 'yaml')}
`, true)}

${csCollapsible('Workflow 5: Quarantine Malicious File', `
${csCode(`Fusion Workflow Configuration:
  Trigger: Detection
    Type: Malware
    Severity: High, Critical
    Cloud ML Confidence: >80%

  Action 1: Quarantine File
    Target: Triggering file on triggering device
    (Uses sensor's built-in quarantine — file moved to CrowdStrike quarantine vault)

  Action 2: Block Hash
    Add SHA256 to custom IOC blocklist
    Action: Block + Detect
    Platforms: All
    Expiration: 90 days

  Action 3: Notification
    Alert SOC with file details and quarantine confirmation`, 'yaml')}
`, true)}

${csCollapsible('Workflow 6: Network Contain + Notify SOC', `
${csCode(`Fusion Workflow Configuration:
  Trigger: Detection
    Severity: Critical
    OR: Manual trigger from analyst

  Action 1: Network Contain
    Target: Triggering device

  Action 2: Multi-Channel Notification
    Slack: #soc-alerts channel
    Email: soc-team@company.com
    PagerDuty: Trigger incident (P1)
    Teams: Security Operations channel

    Message Template:
    "HOST CONTAINED: {{hostname}} ({{local_ip}})
    Detection: {{detection_name}}
    User: {{user_name}}
    Severity: {{severity}}
    Action Required: Investigate and remediate before lifting containment.
    Falcon Link: {{falcon_link}}"`, 'yaml')}
`, true)}

${csCollapsible('Workflow 7: Escalation Workflow for High Severity', `
${csCode(`Fusion Workflow Configuration:
  Trigger: Detection
    Severity: High
    Status: Not triaged after 30 minutes

  Step 1 (T+0): Assign to Tier 1 Analyst
    Route to SOC queue
    SLA Timer: 30 minutes

  Step 2 (T+30min): If unacknowledged, escalate
    Reassign to Tier 2
    Send Slack DM to Tier 2 on-call
    SLA Timer: 15 minutes

  Step 3 (T+45min): If still unacknowledged
    Page Tier 3 / IR Lead via PagerDuty
    Send email to SOC Manager
    Auto-contain host if severity is Critical

  Step 4 (T+60min): Executive notification
    If Critical and still unresolved:
    Email CISO with summary`, 'yaml')}
`, true)}

${csCollapsible('Workflow 8: Automated Malware Analysis Submission', `
${csCode(`Fusion Workflow Configuration:
  Trigger: Detection
    Type: New unknown file (Cloud ML confidence <70% but >30%)

  Action 1: Submit to Falcon Sandbox
    File: {{sha256}}
    Environment: Windows 10 64-bit
    Analysis Type: Full (5 minutes)

  Action 2: Wait for Results (async)
    Poll every 60 seconds for up to 10 minutes

  Action 3: Process Results
    If verdict = Malicious:
      - Update detection severity
      - Block hash globally
      - Quarantine file on all endpoints
    If verdict = Suspicious:
      - Flag for analyst review
      - Add to watchlist
    If verdict = Clean:
      - Add to allowlist (if recurring FP)
      - Close detection as FP`, 'yaml')}
`, true)}

${csCollapsible('Workflow 9: Block Similar Hashes Across Environment', `
${csCode(`Fusion Workflow Configuration:
  Trigger: Analyst confirms detection as True Positive

  Action 1: Extract IOCs
    SHA256, SHA1, MD5 of malicious file
    Associated domains/IPs from sandbox report

  Action 2: Create Global IOC Block
    Type: SHA256
    Action: Prevent (Block)
    Platforms: Windows, macOS, Linux
    Description: "Blocked from incident {{incident_id}}"
    Tags: incident-response, confirmed-malicious

  Action 3: Retroactive Search
    Query all endpoints for file presence:
    Event search for SHA256 on all hosts

  Action 4: If file found on other hosts
    Auto-quarantine on all hosts
    Create incident linking all affected hosts
    Notify SOC of potential spread`, 'yaml')}
`, true)}

${csCollapsible('Workflow 10: Weekly Threat Report Generation', `
${csCode(`Fusion Workflow Configuration:
  Trigger: Scheduled — Every Monday 08:00 UTC

  Action 1: Query Detection Statistics
    API: GET /detects/queries/detects/v1
    Filter: last 7 days
    Aggregate by: severity, tactic, technique, host_group

  Action 2: Query Incident Statistics
    API: GET /incidents/queries/incidents/v1
    Filter: last 7 days

  Action 3: Build Report
    Template includes:
    - Total detections by severity (Critical/High/Medium/Low)
    - Top 10 most common detection types
    - Hosts with most detections
    - New IOCs added
    - MITRE coverage heatmap
    - Mean time to detect / Mean time to respond
    - Open incidents requiring attention
    - Sensor health (% online, version compliance)

  Action 4: Distribute
    Email: security-leadership@company.com
    Attach: PDF report
    Post to: Confluence/SharePoint security wiki`, 'yaml')}
`, true)}
`;
}

function buildTab7_POCPlaybook() {
    return `
<h2 class="cs-section-title">CLIENT POC SUCCESS PLAYBOOK</h2>

${csCollapsible('WEEK 1: DEPLOY & BASELINE', `
<h3>Goals</h3>
<ul>
<li>100% sensor deployment on POC-scoped endpoints</li>
<li>All sensors reporting to Falcon console</li>
<li>Baseline of normal alerts established</li>
<li>Prevention policies in DETECT-ONLY mode</li>
</ul>

<h3>Day-by-Day Checklist</h3>
<h4>Day 1-2: Setup</h4>
${csCheck('Falcon console access confirmed for all POC team members')}
${csCheck('CID recorded and distributed to deployment team')}
${csCheck('Sensor installers downloaded for all platforms')}
${csCheck('Host groups created (Canary, Workstations, Servers, macOS)')}
${csCheck('Prevention policy created in DETECT-ONLY mode')}
${csCheck('Sensor update policy set to N-1')}
${csCheck('Notification policy configured (email to SOC distribution list)')}
${csCheck('Canary group (5-10 IT machines) deployed and verified')}

<h4>Day 3-4: Phase 1 Deployment</h4>
${csCheck('Deploy sensors to 50% of POC endpoints')}
${csCheck('Verify all sensors show "Online" in Falcon console')}
${csCheck('Check for any Reduced Functionality Mode (RFM) hosts')}
${csCheck('Resolve any deployment failures')}
${csCheck('Document any AV conflicts or compatibility issues')}
${csCheck('Verify sensor is not impacting system performance (task manager spot check)')}

<h4>Day 5-7: Full Deployment + Baseline</h4>
${csCheck('Deploy sensors to remaining 50% of endpoints')}
${csCheck('100% deployment confirmed in Falcon console')}
${csCheck('Review all detections generated during baseline period')}
${csCheck('Identify false positives and document for tuning')}
${csCheck('Create exclusions for known legitimate software causing FPs')}
${csCheck('Document baseline detection volume (detections per day)')}
${csCheck('Send Week 1 status report to POC sponsor')}
`, true)}

${csCollapsible('WEEK 2: CUSTOM POLICIES & TUNING', `
<h3>Goals</h3>
<ul>
<li>Custom IOA rules deployed for client-specific threats</li>
<li>False positives reduced to &lt;5%</li>
<li>Prevention mode enabled for high-confidence categories</li>
<li>Exclusions tuned and documented</li>
</ul>

<h3>Checklist</h3>
${csCheck('Review all Week 1 detections with client security team')}
${csCheck('Create exclusions for verified false positives')}
${csCheck('Deploy custom IOA rule group with 10+ rules from Tab 2')}
${csCheck('Enable prevention for Ransomware IOAs')}
${csCheck('Enable prevention for Exploitation categories')}
${csCheck('Enable Cloud ML prevention at Cautious level')}
${csCheck('Configure USB Device Control in monitor mode')}
${csCheck('Set up Falcon Fusion workflow: auto-contain on Critical')}
${csCheck('Set up Falcon Fusion workflow: ServiceNow ticket creation')}
${csCheck('Demonstrate Falcon UI to client SOC team (walkthrough session)')}
${csCheck('Train client on detection triage workflow')}
${csCheck('Review and resolve any performance complaints')}
${csCheck('Send Week 2 status report with FP metrics')}
`, true)}

${csCollapsible('WEEK 3: DETECTION TESTING & HUNTING', `
<h3>Goals</h3>
<ul>
<li>Validate detection coverage against MITRE ATT&CK</li>
<li>Demonstrate threat hunting capabilities</li>
<li>Show RTR incident response capabilities</li>
<li>Full prevention mode on workstations</li>
</ul>

<h3>Checklist</h3>
${csCheck('Run Atomic Red Team tests (safe simulations) on test machines')}
${csCheck('Document detection results per MITRE technique')}
${csCheck('Create MITRE coverage heatmap showing detected techniques')}
${csCheck('Run 5+ threat hunting queries from Tab 3 and present findings')}
${csCheck('Demonstrate Real Time Response on test endpoint')}
${csCheck('Show RTR script execution for forensic collection')}
${csCheck('Enable Aggressive prevention on workstations')}
${csCheck('Enable Moderate prevention on servers')}
${csCheck('Demonstrate Falcon Sandbox (malware analysis) if licensed')}
${csCheck('Demonstrate Identity Protection if licensed')}
${csCheck('Show Falcon Fusion automated response in action')}
${csCheck('Review competitor comparison talking points')}
${csCheck('Send Week 3 status report with detection coverage metrics')}
`, true)}

${csCollapsible('WEEK 4: REPORTING & PO DECISION', `
<h3>Goals</h3>
<ul>
<li>Executive summary delivered</li>
<li>ROI documented</li>
<li>PO initiated or clear next steps defined</li>
</ul>

<h3>Checklist</h3>
${csCheck('Compile all POC metrics into executive summary')}
${csCheck('Calculate ROI vs current solution')}
${csCheck('Prepare MITRE ATT&CK coverage comparison (CrowdStrike vs current)')}
${csCheck('Document all detections that would have been missed by current solution')}
${csCheck('Prepare competitive differentiator summary')}
${csCheck('Schedule executive readout meeting')}
${csCheck('Deliver executive presentation')}
${csCheck('Address all outstanding questions/objections')}
${csCheck('Provide pricing proposal (with your SE/AE)')}
${csCheck('Define next steps: PO timeline, deployment plan, training needs')}
${csCheck('Get verbal commitment or clear objection to address')}
${csCheck('Send formal POC completion report')}
`, true)}

${csCollapsible('POC SUCCESS METRICS DASHBOARD', `
<h3>Key Metrics to Track and Present</h3>
<table class="cs-table">
<tr><th>Metric</th><th>How to Measure</th><th>Target</th></tr>
<tr><td>Sensor Deployment Rate</td><td>Falcon console host count / total POC scope</td><td>>98%</td></tr>
<tr><td>Sensor Online Rate</td><td>Online hosts / total deployed hosts</td><td>>95%</td></tr>
<tr><td>Mean Time to Detect</td><td>Time from execution to alert in Falcon</td><td>&lt;1 minute</td></tr>
<tr><td>Detection Coverage (MITRE)</td><td>Techniques detected / techniques tested</td><td>>80%</td></tr>
<tr><td>False Positive Rate</td><td>FP detections / total detections</td><td>&lt;5%</td></tr>
<tr><td>Unique Threats Found</td><td>Count of real threats discovered during POC</td><td>Track all</td></tr>
<tr><td>CPU Impact (Average)</td><td>Task Manager / top measurements</td><td>&lt;3%</td></tr>
<tr><td>Memory Usage</td><td>Falcon sensor memory consumption</td><td>&lt;200MB</td></tr>
<tr><td>User Complaints</td><td>Help desk tickets related to Falcon</td><td>0</td></tr>
<tr><td>Time to Contain</td><td>Detection to network containment</td><td>&lt;5 minutes (manual), instant (automated)</td></tr>
</table>
`, true)}

${csCollapsible('EXECUTIVE SUMMARY REPORT TEMPLATE', `
<h3>CrowdStrike Falcon POC Results — Executive Summary</h3>
${csCode(`CROWDSTRIKE FALCON POC RESULTS
================================
Client: [Client Name]
POC Duration: [Start Date] - [End Date]
POC Scope: [X] Endpoints ([Y] Windows, [Z] Linux, [W] macOS)

EXECUTIVE SUMMARY
-----------------
CrowdStrike Falcon was deployed across [X] endpoints over [N] weeks.
The platform detected [Y] real security events that were previously
invisible, while maintaining near-zero performance impact and zero
user-reported disruptions.

KEY RESULTS
-----------
1. DEPLOYMENT: [98%+] successful sensor deployment within [2] days
2. DETECTION: [X] real threats identified including [specific examples]
3. COVERAGE: [85%+] MITRE ATT&CK technique coverage (vs [X%] current solution)
4. PERFORMANCE: [<2%] average CPU impact, [0] user complaints
5. RESPONSE: Mean time to detect: [<1 min] | Mean time to contain: [<5 min]

THREATS DISCOVERED DURING POC
-----------------------------
[List actual findings — this is the most impactful section]
1. [Finding 1: e.g., "Unauthorized admin tool usage on 3 servers"]
2. [Finding 2: e.g., "Outdated/vulnerable software on 12 endpoints"]
3. [Finding 3: e.g., "Suspicious PowerShell scripts running from temp dirs"]

ROI ANALYSIS
-----------
Annual Cost Savings:
- Reduced incident response time: $[X]
- Prevented potential breach (avg cost $4.45M): Risk reduction value
- Consolidation of [X] existing tools: $[Y] savings
- Reduced analyst hours for investigation: $[Z]

RECOMMENDATION
--------------
Based on POC results, we recommend proceeding with CrowdStrike Falcon
deployment across the full environment of [X] endpoints.

Next Steps:
1. Finalize licensing and pricing
2. Plan production deployment (phased, 4-week rollout)
3. Schedule training for SOC team (CCFA certification)`, 'text')}
`, true)}

${csCollapsible('ROI CALCULATOR', `
<h3>Simple ROI Estimator</h3>
<div class="cs-roi-calc">
    <div class="cs-roi-row">
        <label>Number of Endpoints:</label>
        <input type="number" id="roi-endpoints" value="500" onchange="csCalcROI()">
    </div>
    <div class="cs-roi-row">
        <label>Security Incidents per Year:</label>
        <input type="number" id="roi-incidents" value="50" onchange="csCalcROI()">
    </div>
    <div class="cs-roi-row">
        <label>Avg Hours to Investigate per Incident:</label>
        <input type="number" id="roi-hours" value="4" onchange="csCalcROI()">
    </div>
    <div class="cs-roi-row">
        <label>Analyst Hourly Rate ($):</label>
        <input type="number" id="roi-rate" value="75" onchange="csCalcROI()">
    </div>
    <div class="cs-roi-row">
        <label>Current Annual Security Tool Costs ($):</label>
        <input type="number" id="roi-current" value="50000" onchange="csCalcROI()">
    </div>
    <div class="cs-roi-row">
        <label>Estimated Breach Probability Reduction (%):</label>
        <input type="number" id="roi-breach" value="60" onchange="csCalcROI()">
    </div>
    <div class="cs-roi-result" id="roi-result">
        <p>Click Calculate or change values above</p>
    </div>
    <button class="cs-btn" onclick="csCalcROI()">Calculate ROI</button>
</div>
`, true)}

${csCollapsible('COMPETITIVE COMPARISON TALKING POINTS', `
<h3>CrowdStrike vs Microsoft Defender for Endpoint</h3>
<table class="cs-table">
<tr><th>Capability</th><th>CrowdStrike Falcon</th><th>Microsoft Defender</th></tr>
<tr><td>Architecture</td><td>Purpose-built cloud-native, single lightweight agent</td><td>Evolved from on-prem AV, multiple components</td></tr>
<tr><td>OS Coverage</td><td>Windows, macOS, Linux (broad distro support), Chrome OS</td><td>Best on Windows, limited Linux/macOS features</td></tr>
<tr><td>Cloud Dependency</td><td>Sensor ML works offline, cloud enhances</td><td>Requires Microsoft cloud connectivity for full features</td></tr>
<tr><td>Threat Intelligence</td><td>Industry-leading (170+ threat actors tracked)</td><td>Good but Microsoft-ecosystem focused</td></tr>
<tr><td>MDR Service</td><td>Falcon Complete (fully managed)</td><td>Experts for XDR (newer offering)</td></tr>
<tr><td>Identity Protection</td><td>Native AD protection, conditional access</td><td>Requires Azure AD P2 separately</td></tr>
<tr><td>Deployment Speed</td><td>Hours (single MSI/DEB/PKG)</td><td>Varies, can require Intune/SCCM infrastructure</td></tr>
</table>

<h3>CrowdStrike vs SentinelOne</h3>
<table class="cs-table">
<tr><th>Capability</th><th>CrowdStrike Falcon</th><th>SentinelOne</th></tr>
<tr><td>Detection Approach</td><td>Cloud ML + Sensor ML + IOA behavioral</td><td>Static AI + Behavioral AI on-agent</td></tr>
<tr><td>Threat Intelligence</td><td>Integrated (Falcon Intelligence)</td><td>Requires separate purchase or integration</td></tr>
<tr><td>Managed Hunting</td><td>Falcon OverWatch (included in some bundles)</td><td>Vigilance (separate SKU)</td></tr>
<tr><td>Log Management</td><td>Falcon LogScale (Humio) — included/add-on</td><td>Requires third-party SIEM</td></tr>
<tr><td>IR Services</td><td>CrowdStrike Services (industry gold standard)</td><td>Available but less established</td></tr>
<tr><td>Market Position</td><td>#1 in Gartner MQ, IDC, Forrester</td><td>Strong challenger, visionary position</td></tr>
</table>

<h3>CrowdStrike vs Carbon Black (VMware/Broadcom)</h3>
<table class="cs-table">
<tr><th>Capability</th><th>CrowdStrike Falcon</th><th>Carbon Black</th></tr>
<tr><td>Architecture</td><td>Cloud-native SaaS</td><td>On-prem or cloud (hybrid complexity)</td></tr>
<tr><td>Agent Size/Impact</td><td>~25MB, &lt;3% CPU</td><td>Larger footprint, historically heavier</td></tr>
<tr><td>Ownership</td><td>Independent security-focused company</td><td>Acquired by Broadcom (uncertainty)</td></tr>
<tr><td>Innovation Pace</td><td>Rapid (cloud-delivered updates)</td><td>Slower under acquisition transitions</td></tr>
<tr><td>Platform Breadth</td><td>23+ modules (EDR, XDR, ITDR, cloud, etc.)</td><td>Fewer modules, narrower scope</td></tr>
</table>
`, true)}

${csCollapsible('COMMON OBJECTIONS & RESPONSES', `
<h3>Objection Handling Guide</h3>

<h4>"CrowdStrike is too expensive"</h4>
<p><strong>Response:</strong> "Let's look at total cost of ownership. CrowdStrike consolidates multiple tools (AV, EDR, threat intel, vulnerability management, log management) into one platform. When you factor in the tools you can retire, analyst time savings from automation, and the risk reduction, the TCO is often lower. The average breach costs $4.45M — CrowdStrike's breach prevention warranty provides additional assurance."</p>

<h4>"We already have Microsoft Defender included with our E5 license"</h4>
<p><strong>Response:</strong> "Defender is a good baseline, but the POC results speak for themselves. We detected [X] threats that Defender missed. CrowdStrike provides superior cross-platform coverage (your Linux servers), dedicated threat intelligence on 170+ adversary groups, and 24/7 managed threat hunting. Free doesn't mean best — the cost of a missed detection far exceeds the licensing cost."</p>

<h4>"We're concerned about another CrowdStrike outage"</h4>
<p><strong>Response:</strong> "CrowdStrike has implemented comprehensive changes since that event: staged sensor updates, enhanced testing, customer-controlled update policies, and a Content Certification process. Your sensor update policy gives you full control over when updates deploy to your environment. The N-1 policy we configured during the POC ensures you never receive the absolute latest update."</p>

<h4>"The cloud dependency concerns us"</h4>
<p><strong>Response:</strong> "The Falcon sensor's on-sensor ML engine provides full protection even without cloud connectivity. Cloud enhances detection with its larger ML models, but the sensor operates independently. During the POC, the sensor continued protecting endpoints during the brief network interruption on [date]. For highly sensitive environments, we can configure proxy-based communication."</p>

<h4>"We need to evaluate more vendors"</h4>
<p><strong>Response:</strong> "Absolutely — due diligence is important. I'd recommend running a parallel POC if possible, using the same test criteria and MITRE techniques. This gives you an apples-to-apples comparison. Based on independent evaluations (MITRE Engenuity, Gartner, Forrester), CrowdStrike consistently leads. I'm confident in a head-to-head comparison."</p>

<h4>"Our team doesn't have the expertise to manage this"</h4>
<p><strong>Response:</strong> "That's exactly what Falcon Complete is for — CrowdStrike's fully managed MDR service provides 24/7 monitoring, investigation, and response by CrowdStrike's own experts. It's like having a world-class SOC team without hiring one. For teams that want to grow internally, CrowdStrike University and certifications (CCFA, CCFR) provide excellent training."</p>
`, true)}

${csCollapsible('GETTING FROM POC TO PO: CLOSING THE DEAL', `
<h3>Closing Framework</h3>
<ol>
<li><strong>Confirm Value:</strong> "Based on the POC results, do you agree CrowdStrike meets your detection and response requirements?"</li>
<li><strong>Identify Blockers:</strong> "What obstacles do we need to overcome to move forward?"</li>
<li><strong>Address Each Blocker:</strong> Work through each concern systematically</li>
<li><strong>Define Timeline:</strong> "What does your procurement process look like? How long does it typically take?"</li>
<li><strong>Create Urgency:</strong> "Your current coverage gap means you are exposed to [specific threats found in POC]. Every day without full protection is a day of risk."</li>
<li><strong>Provide Options:</strong> Present tiered pricing (Falcon Go, Falcon Pro, Falcon Enterprise, Falcon Elite)</li>
<li><strong>Offer Sweeteners:</strong> Extended POC, additional modules trial, training included, multi-year discount</li>
<li><strong>Get the PO:</strong> "Can we get the paperwork started this week?"</li>
</ol>

<h3>CrowdStrike Falcon Bundles Reference</h3>
<table class="cs-table">
<tr><th>Bundle</th><th>Modules Included</th><th>Best For</th></tr>
<tr><td>Falcon Go</td><td>Falcon Prevent (NGAV)</td><td>AV replacement only</td></tr>
<tr><td>Falcon Pro</td><td>Prevent + Insight (EDR)</td><td>Basic EDR</td></tr>
<tr><td>Falcon Enterprise</td><td>Prevent + Insight + OverWatch + Threat Intel</td><td>Full EDR + managed hunting</td></tr>
<tr><td>Falcon Elite</td><td>Enterprise + Identity Protection + LogScale + IT Hygiene</td><td>Full platform</td></tr>
<tr><td>Falcon Complete</td><td>Everything + fully managed MDR</td><td>Outsourced security operations</td></tr>
</table>
`, true)}
`;
}

function buildTab8_Certification() {
    return `
<h2 class="cs-section-title">CROWDSTRIKE CERTIFICATION PREP</h2>

${csCollapsible('CCFA — CrowdStrike Certified Falcon Administrator', `
<h3>Exam Overview</h3>
<table class="cs-table">
<tr><th>Detail</th><th>Value</th></tr>
<tr><td>Duration</td><td>90 minutes</td></tr>
<tr><td>Questions</td><td>60 multiple choice</td></tr>
<tr><td>Passing Score</td><td>80%</td></tr>
<tr><td>Prerequisites</td><td>None (Falcon training recommended)</td></tr>
<tr><td>Renewal</td><td>Every 2 years</td></tr>
</table>

<h3>Study Domains</h3>

<h4>1. Falcon Platform Overview (10-15%)</h4>
<ul>
<li>CrowdStrike cloud architecture (US-1, US-2, EU-1, US-GOV)</li>
<li>Falcon module names and purposes (Prevent, Insight, Discover, Spotlight, etc.)</li>
<li>CID and AID concepts</li>
<li>Falcon sensor architecture (kernel mode driver, user mode service)</li>
<li>Cloud-delivered protection vs on-sensor protection</li>
</ul>

<h4>2. Sensor Deployment & Management (20-25%)</h4>
<ul>
<li>Sensor installation on Windows, Linux, macOS</li>
<li>CID assignment and provisioning tokens</li>
<li>Sensor update policies (N, N-1, N-2, sensor version pinning)</li>
<li>Uninstall protection and maintenance tokens</li>
<li>Host groups (static vs dynamic, assignment rules)</li>
<li>Sensor proxy configuration</li>
<li>Reduced Functionality Mode (RFM) — what causes it, how to resolve</li>
<li>Sensor tags for host management</li>
</ul>

<h4>3. Prevention Policies (20-25%)</h4>
<ul>
<li>Cloud ML and Sensor ML settings (sensitivity levels)</li>
<li>IOA behavioral prevention toggles</li>
<li>Exploit mitigation settings</li>
<li>Script monitoring and prevention</li>
<li>Exclusions (ML exclusions, IOA exclusions, sensor visibility exclusions)</li>
<li>Policy precedence and assignment</li>
</ul>

<h4>4. Detection & Response (20-25%)</h4>
<ul>
<li>Detection severity levels (Informational, Low, Medium, High, Critical)</li>
<li>Detection types (ML, IOA, Custom IOA, IOC)</li>
<li>Detection triage workflow (new, in progress, true/false positive, closed)</li>
<li>Process tree analysis</li>
<li>Indicator of Compromise (IOC) management</li>
<li>Network containment and lift containment</li>
</ul>

<h4>5. Real Time Response (10-15%)</h4>
<ul>
<li>RTR access levels (read-only, active responder, admin)</li>
<li>Common RTR commands</li>
<li>RTR scripts (put files, run scripts)</li>
<li>Batch RTR sessions</li>
</ul>

<h4>6. Falcon Fusion & Integrations (5-10%)</h4>
<ul>
<li>Basic Fusion workflow creation</li>
<li>Notification policies</li>
<li>API client creation and scopes</li>
</ul>
`, true)}

${csCollapsible('CCFR — CrowdStrike Certified Falcon Responder', `
<h3>Exam Overview</h3>
<table class="cs-table">
<tr><th>Detail</th><th>Value</th></tr>
<tr><td>Duration</td><td>90 minutes</td></tr>
<tr><td>Questions</td><td>60 multiple choice</td></tr>
<tr><td>Passing Score</td><td>80%</td></tr>
<tr><td>Prerequisites</td><td>CCFA recommended</td></tr>
<tr><td>Focus</td><td>Incident response and threat hunting using Falcon</td></tr>
</table>

<h3>Study Domains</h3>

<h4>1. Event Data & Telemetry (15-20%)</h4>
<ul>
<li>Event types: ProcessRollup2, NetworkConnectIP4, DnsRequest, FileWritten, etc.</li>
<li>Understanding event fields (aid, ContextProcessId, ParentProcessId, etc.)</li>
<li>Event timeline reconstruction</li>
<li>Sensor vs cloud-generated events</li>
</ul>

<h4>2. Detection Analysis (20-25%)</h4>
<ul>
<li>Deep-dive detection analysis (process tree, execution chain)</li>
<li>MITRE ATT&CK mapping of detections</li>
<li>Differentiating true positives from false positives</li>
<li>Detection chaining (correlating related detections into incidents)</li>
<li>Indicator Graph (visual relationship mapping)</li>
</ul>

<h4>3. Threat Hunting (20-25%)</h4>
<ul>
<li>Event Search queries (Falcon LogScale query language)</li>
<li>Hunting for specific attack techniques</li>
<li>Saved searches and scheduled queries</li>
<li>Hunting dashboards</li>
<li>IOA hunting vs IOC hunting</li>
</ul>

<h4>4. Incident Response with RTR (20-25%)</h4>
<ul>
<li>Full RTR command set (read-only, active, admin)</li>
<li>Evidence collection procedures</li>
<li>Containment strategies</li>
<li>Remediation steps</li>
<li>RTR scripts for IR automation</li>
<li>Memory dump analysis</li>
</ul>

<h4>5. Falcon Intelligence & IOCs (10-15%)</h4>
<ul>
<li>Threat intelligence reports</li>
<li>IOC types and management</li>
<li>Falcon Sandbox integration</li>
<li>Adversary profiles and tracking</li>
</ul>
`, true)}

${csCollapsible('KEY CONCEPTS TO KNOW', `
<h3>Critical Terminology</h3>
<table class="cs-table">
<tr><th>Term</th><th>Definition</th></tr>
<tr><td>CID</td><td>Customer ID — unique identifier for your Falcon tenant. Required for all sensor installations.</td></tr>
<tr><td>AID</td><td>Agent ID — unique identifier for each individual sensor/endpoint. Generated at installation.</td></tr>
<tr><td>IOA</td><td>Indicator of Attack — behavioral pattern indicating an attack in progress (detects the "how" regardless of tool)</td></tr>
<tr><td>IOC</td><td>Indicator of Compromise — specific artifact (hash, IP, domain) associated with known malicious activity</td></tr>
<tr><td>RFM</td><td>Reduced Functionality Mode — sensor state when it cannot communicate with the cloud. Still provides basic protection.</td></tr>
<tr><td>RTR</td><td>Real Time Response — remote shell access to endpoints for investigation and remediation</td></tr>
<tr><td>TTP</td><td>Tactics, Techniques, and Procedures — the behavior patterns of threat actors (aligned with MITRE ATT&CK)</td></tr>
<tr><td>NGAV</td><td>Next-Generation Antivirus — Falcon Prevent module, replaces traditional AV with ML and behavioral detection</td></tr>
<tr><td>EDR</td><td>Endpoint Detection and Response — Falcon Insight module, provides visibility, detection, and response capabilities</td></tr>
<tr><td>XDR</td><td>Extended Detection and Response — Falcon XDR correlates across endpoints, cloud, identity, and third-party data</td></tr>
<tr><td>MDR</td><td>Managed Detection and Response — Falcon Complete, CrowdStrike manages your security operations</td></tr>
<tr><td>OverWatch</td><td>CrowdStrike's 24/7 managed threat hunting team that proactively hunts across all Falcon customers</td></tr>
<tr><td>LogScale</td><td>CrowdStrike's log management and SIEM platform (formerly Humio)</td></tr>
<tr><td>Fusion</td><td>CrowdStrike's built-in SOAR platform for automated workflows</td></tr>
<tr><td>Spotlight</td><td>Vulnerability management module — scans for CVEs without additional agents/scans</td></tr>
<tr><td>Discover</td><td>IT hygiene and asset inventory — discovers all assets and applications</td></tr>
</table>
`, true)}

${csCollapsible('PRACTICE QUESTIONS (20 Questions with Answers)', `
<div class="cs-quiz">

<div class="cs-question">
<p><strong>Q1:</strong> What is the CID used for in CrowdStrike Falcon?</p>
<p>A) Identifying individual sensors<br>B) Authenticating API requests<br>C) Associating sensors with the correct Falcon tenant<br>D) Encrypting sensor communications</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: C</strong> — The CID (Customer ID) associates each sensor with the correct Falcon tenant. The AID identifies individual sensors.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q2:</strong> Which ML analysis level has the highest detection rate but also the highest false positive rate?</p>
<p>A) Cautious<br>B) Moderate<br>C) Aggressive<br>D) Extra Aggressive</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: D</strong> — Extra Aggressive casts the widest net, detecting more threats but also generating more false positives.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q3:</strong> What is Reduced Functionality Mode (RFM)?</p>
<p>A) When the sensor is uninstalled<br>B) When the sensor cannot connect to the CrowdStrike cloud<br>C) When prevention is set to detect-only<br>D) When the sensor is outdated</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — RFM occurs when the sensor loses cloud connectivity. It still provides basic protection using the on-sensor ML model but cannot receive cloud-based updates or analysis.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q4:</strong> Which command verifies the Falcon sensor is running on Windows?</p>
<p>A) falcon status<br>B) sc query csagent<br>C) systemctl status falcon<br>D) Get-FalconStatus</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — <code>sc query csagent</code> checks the CrowdStrike service status on Windows. On Linux it would be <code>systemctl status falcon-sensor</code>.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q5:</strong> What is the difference between an IOA and an IOC?</p>
<p>A) IOAs are file-based, IOCs are behavioral<br>B) IOAs detect attack behaviors, IOCs match known artifacts<br>C) IOAs are cloud-only, IOCs are sensor-only<br>D) They are the same thing</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — IOAs (Indicators of Attack) detect behavioral patterns regardless of the specific tool used. IOCs (Indicators of Compromise) match known malicious artifacts like hashes, IPs, or domains.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q6:</strong> Which RTR access level allows you to kill processes and delete files?</p>
<p>A) Read Only Analyst<br>B) Active Responder<br>C) RTR Admin<br>D) Both B and C</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: D</strong> — Both Active Responder and RTR Admin can kill processes and delete files. RTR Admin additionally can run custom scripts and put files.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q7:</strong> What does the N-1 sensor update policy mean?</p>
<p>A) Update sensors immediately when new version releases<br>B) Keep sensors one major version behind latest<br>C) Keep sensors one build behind the latest available<br>D) Never update sensors</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: C</strong> — N-1 means sensors receive the second-most-recent build, giving the latest version time to be validated in the field before deployment to your environment.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q8:</strong> Which Falcon module provides vulnerability management without running scans?</p>
<p>A) Falcon Insight<br>B) Falcon Spotlight<br>C) Falcon Discover<br>D) Falcon Prevent</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — Falcon Spotlight uses the sensor's existing telemetry to identify installed software and map it against CVE databases — no additional scanning needed.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q9:</strong> What is the maximum file size you can download from an endpoint using RTR's "get" command?</p>
<p>A) 100 MB<br>B) 1 GB<br>C) 4 GB<br>D) No limit</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: C</strong> — The RTR "get" command supports file downloads up to 4 GB from the endpoint to the Falcon console.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q10:</strong> When you network-contain a host, what connections remain active?</p>
<p>A) All connections are blocked<br>B) Only connections to the CrowdStrike cloud<br>C) Only connections to the local subnet<br>D) Only DNS and HTTPS connections</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — Network containment blocks all network traffic except communication with the CrowdStrike cloud, allowing continued management and RTR access.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q11:</strong> What type of host group automatically adds hosts based on properties like OS or OU?</p>
<p>A) Static group<br>B) Dynamic group<br>C) Policy group<br>D) Containment group</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — Dynamic host groups use assignment rules to automatically add/remove hosts based on properties like OS, hostname pattern, OU, or IP range.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q12:</strong> Which CrowdStrike team provides 24/7 proactive threat hunting across all customer environments?</p>
<p>A) Falcon Complete<br>B) CrowdStrike Intelligence<br>C) Falcon OverWatch<br>D) CrowdStrike Services</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: C</strong> — Falcon OverWatch is CrowdStrike's dedicated managed threat hunting team that proactively hunts for threats across the entire customer base.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q13:</strong> What Linux command sets the CID on a Falcon sensor?</p>
<p>A) falconctl set-cid<br>B) sudo /opt/CrowdStrike/falconctl -s --cid=CID<br>C) sudo falcon-sensor --cid CID<br>D) sudo csconfig --cid CID</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — <code>sudo /opt/CrowdStrike/falconctl -s --cid=YOUR_CID</code> sets the Customer ID on the Linux Falcon sensor.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q14:</strong> What is the purpose of a maintenance token?</p>
<p>A) To authenticate API requests<br>B) To prevent unauthorized sensor uninstallation<br>C) To enable cloud connectivity<br>D) To activate premium features</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — Maintenance tokens are required to uninstall or modify the Falcon sensor when uninstall protection is enabled, preventing unauthorized removal.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q15:</strong> Which event type in Falcon captures process creation events?</p>
<p>A) ProcessCreate<br>B) ProcessRollup2<br>C) NewProcess<br>D) ProcessStart</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — ProcessRollup2 is the primary event type for process creation/execution events in CrowdStrike Falcon telemetry.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q16:</strong> What type of exclusion should you create when a legitimate application is being blocked by ML-based detection?</p>
<p>A) IOA Exclusion<br>B) ML Exclusion<br>C) Sensor Visibility Exclusion<br>D) Prevention Exclusion</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — ML Exclusions prevent the machine learning engines from flagging specific files or paths. IOA Exclusions are for behavioral detections. Sensor Visibility Exclusions prevent the sensor from monitoring specified paths entirely (use sparingly).</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q17:</strong> In the Falcon console, what does the process tree visualization show?</p>
<p>A) All processes running on the system<br>B) The parent-child relationship chain of a detected process<br>C) Network connections of a process<br>D) File modifications by a process</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — The process tree shows the execution chain: which process spawned which, allowing analysts to understand the full attack chain from initial access to detected activity.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q18:</strong> Which API authentication method does the CrowdStrike Falcon API use?</p>
<p>A) Basic Authentication<br>B) API Key in header<br>C) OAuth 2.0 Client Credentials<br>D) SAML</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: C</strong> — CrowdStrike uses OAuth 2.0 Client Credentials flow. You exchange a client_id and client_secret for a bearer token valid for 30 minutes.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q19:</strong> What is the recommended approach for deploying prevention policies during a POC?</p>
<p>A) Enable full prevention immediately on all endpoints<br>B) Start in detect-only mode, then gradually enable prevention<br>C) Only use prevention on servers, detect on workstations<br>D) Disable all detection and prevention for the first week</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — The recommended approach is phased: start in detect-only mode to establish a baseline and identify false positives, then gradually enable prevention categories starting with high-confidence items like ransomware and exploitation.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

<div class="cs-question">
<p><strong>Q20:</strong> What macOS-specific step is required after installing the Falcon sensor?</p>
<p>A) Reboot the system<br>B) Approve the System Extension and grant Full Disk Access<br>C) Disable SIP (System Integrity Protection)<br>D) Install Rosetta 2</p>
<div class="cs-answer" onclick="this.style.display='block'" style="display:none">
<p><strong>Answer: B</strong> — macOS requires approving the CrowdStrike System Extension (either manually or via MDM profile) and granting Full Disk Access to the Falcon agent for full functionality.</p>
</div>
<button class="cs-btn-sm" onclick="this.previousElementSibling.style.display=this.previousElementSibling.style.display==='none'?'block':'none'">Show/Hide Answer</button>
</div>

</div>
`, true)}
`;
}


// ─── TAB 9: API INTEGRATION ──────────────────────────────────────

function buildTab9_APIIntegration() {
    return `
<h2 class="cs-section-title">CROWDSTRIKE FALCON API COMPLETE GUIDE</h2>

${csCollapsible('1. AUTHENTICATION (OAuth2)', `
<h3>Getting API Access</h3>
<ol>
<li>Go to <strong>Support and resources > API clients and keys</strong></li>
<li>Click <strong>Add new API client</strong></li>
<li>Name it: <code>POC-Integration</code></li>
<li>Select required scopes (see table below)</li>
<li>Save the <strong>Client ID</strong> and <strong>Client Secret</strong></li>
</ol>

<h4>OAuth2 Token Request</h4>
${csCode(`# cURL — Get Bearer Token
curl -X POST "https://api.crowdstrike.com/oauth2/token" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"

# Response:
# { "access_token": "eyJ0eX...", "token_type": "bearer", "expires_in": 1799 }`, 'bash')}

${csCode(`# Python — Using FalconPy SDK
pip install crowdstrike-falconpy

from falconpy import OAuth2

auth = OAuth2(client_id="YOUR_CLIENT_ID",
              client_secret="YOUR_CLIENT_SECRET")

# Token is managed automatically by FalconPy
response = auth.token()
print(f"Token: {response['body']['access_token']}")`, 'python')}

${csCode(`# PowerShell — Using PSFalcon
Install-Module -Name PSFalcon -Scope CurrentUser
Import-Module PSFalcon

Request-FalconToken -ClientId 'YOUR_CLIENT_ID' -ClientSecret 'YOUR_CLIENT_SECRET' -Cloud 'us-1'`, 'powershell')}

<table class="cs-table">
<tr><th>API Scope</th><th>Permission</th><th>Use Case</th></tr>
<tr><td>Hosts</td><td>Read + Write</td><td>List/manage hosts, contain/lift containment</td></tr>
<tr><td>Detections</td><td>Read + Write</td><td>Pull detections, update status</td></tr>
<tr><td>Incidents</td><td>Read + Write</td><td>Manage incidents, perform actions</td></tr>
<tr><td>IOCs</td><td>Read + Write</td><td>Create/manage custom IOCs</td></tr>
<tr><td>Real Time Response</td><td>Read + Write + Admin</td><td>RTR sessions, scripts, commands</td></tr>
<tr><td>Prevention Policies</td><td>Read + Write</td><td>Policy management</td></tr>
<tr><td>Custom IOA Rules</td><td>Read + Write</td><td>Detection rule management</td></tr>
<tr><td>Sensor Download</td><td>Read</td><td>Download sensor installers</td></tr>
<tr><td>Spotlight Vulnerabilities</td><td>Read</td><td>Vulnerability assessment data</td></tr>
</table>
`, true)}

${csCollapsible('2. HOSTS API', `
<h3>List All Hosts</h3>
${csCode(`# Python — FalconPy
from falconpy import Hosts

hosts = Hosts(client_id="ID", client_secret="SECRET")

# List host AIDs
response = hosts.query_devices_by_filter(limit=100,
    filter="platform_name:'Windows'")
aids = response["body"]["resources"]

# Get host details
details = hosts.get_device_details(ids=aids)
for host in details["body"]["resources"]:
    print(f"{host['hostname']} | {host['os_version']} | {host['last_seen']} | {host['status']}")`, 'python')}

<h3>Contain a Host (Network Isolation)</h3>
${csCode(`# Python — Contain host
response = hosts.perform_action(
    action_name="contain",
    ids=["HOST_AID_HERE"]
)
print(f"Containment status: {response['status_code']}")

# Lift containment
response = hosts.perform_action(
    action_name="lift_containment",
    ids=["HOST_AID_HERE"]
)`, 'python')}

<h3>FQL Filter Examples</h3>
${csCode(`# Hosts not seen in 7 days
filter="last_seen:<='2024-01-01T00:00:00Z'"

# Windows servers only
filter="platform_name:'Windows'+os_version:'*Server*'"

# Hosts with detections
filter="status:'containment_pending'+platform_name:'Windows'"

# Search by hostname
filter="hostname:'WORKSTATION-*'"

# Hosts in specific OU/Group
filter="groups:['GROUP_ID_HERE']"`, 'fql')}
`, true)}

${csCollapsible('3. DETECTIONS API', `
<h3>Query and Manage Detections</h3>
${csCode(`from falconpy import Detects

detects = Detects(client_id="ID", client_secret="SECRET")

# Query recent detections
response = detects.query_detects(
    filter="status:'new'+max_severity_displayname:'Critical'",
    limit=50,
    sort="last_behavior|desc"
)
detection_ids = response["body"]["resources"]

# Get detection details
details = detects.get_detect_summaries(ids=detection_ids)
for d in details["body"]["resources"]:
    print(f"[{d['max_severity_displayname']}] {d['behaviors'][0]['tactic']} - "
          f"{d['behaviors'][0]['technique']} on {d['device']['hostname']}")
    print(f"  File: {d['behaviors'][0].get('filename','N/A')}")
    print(f"  CMD:  {d['behaviors'][0].get('cmdline','N/A')}")

# Update detection status
detects.update_detects_by_ids(
    ids=detection_ids[:5],
    status="in_progress",
    assigned_to_uuid="analyst-uuid-here",
    comment="Investigating as part of POC exercise"
)`, 'python')}
`, true)}

${csCollapsible('4. IOC API — Push Custom Indicators', `
<h3>Create Custom IOCs</h3>
${csCode(`from falconpy import IOC

ioc = IOC(client_id="ID", client_secret="SECRET")

# Create IP IOC — Block + Detect
response = ioc.indicator_create(
    body={
        "indicators": [
            {
                "type": "ipv4",
                "value": "185.220.101.1",
                "action": "detect",
                "severity": "high",
                "description": "Known Tor exit node - C2 traffic",
                "platforms": ["windows", "mac", "linux"],
                "tags": ["tor", "c2", "poc-test"],
                "expiration": "2024-12-31T00:00:00Z"
            },
            {
                "type": "domain",
                "value": "malicious-domain.xyz",
                "action": "block",
                "severity": "critical",
                "description": "Phishing domain",
                "platforms": ["windows", "mac", "linux"]
            },
            {
                "type": "sha256",
                "value": "e3b0c44298fc1c149afbf4c8996fb924...",
                "action": "block",
                "severity": "critical",
                "description": "Known ransomware hash",
                "platforms": ["windows"]
            }
        ]
    }
)
print(f"IOCs created: {response['status_code']}")`, 'python')}

${csCode(`# PowerShell — PSFalcon IOC creation
New-FalconIoc -Type ipv4 -Value '185.220.101.1' -Action detect -Severity high \\
  -Description 'Known C2 IP' -Platform windows,mac,linux`, 'powershell')}
`, true)}

${csCollapsible('5. SIEM INTEGRATION EXAMPLES', `
<h3>Splunk Integration</h3>
${csCode(`# Install CrowdStrike Falcon Event Streams TA for Splunk
# Configure in Splunk:
# 1. Install "CrowdStrike Falcon Event Streams Technical Add-on"
# 2. Configuration > Add-on Settings > CrowdStrike Account
# 3. Enter API Client ID + Secret (need Event Streams scope)
# 4. Data will flow into index=crowdstrike

# SPL to query CrowdStrike detections in Splunk:
index=crowdstrike sourcetype="crowdstrike:events:detect"
| spath
| table _time, hostinfo.hostname, detect.tactic, detect.technique, detect.severity, detect.description
| sort -_time`, 'spl')}

<h3>Sentinel Integration</h3>
${csCode(`# 1. In Sentinel, go to Data Connectors
# 2. Search "CrowdStrike Falcon"
# 3. Install the solution from Content Hub
# 4. Configure with API Client ID + Secret
# 5. Enable data collection for: Detections, Incidents, Host data

# KQL to query CrowdStrike data in Sentinel:
CrowdStrike_Detections_CL
| where Severity_s in ("Critical", "High")
| project TimeGenerated, HostName_s, Tactic_s, Technique_s, Description_s
| sort by TimeGenerated desc`, 'kql')}
`, true)}

${csCollapsible('6. PAGINATION & RATE LIMITS', `
<h3>Handling Pagination</h3>
${csCode(`from falconpy import Hosts

hosts = Hosts(client_id="ID", client_secret="SECRET")

all_aids = []
offset = 0
limit = 5000

while True:
    response = hosts.query_devices_by_filter(limit=limit, offset=offset)
    aids = response["body"]["resources"]
    if not aids:
        break
    all_aids.extend(aids)
    offset += limit

print(f"Total hosts: {len(all_aids)}")`, 'python')}

<h3>Rate Limiting</h3>
<table class="cs-table">
<tr><th>Endpoint Category</th><th>Rate Limit</th><th>Notes</th></tr>
<tr><td>OAuth2 Token</td><td>100 requests/min</td><td>Cache tokens, don't request per call</td></tr>
<tr><td>Detections</td><td>6000 requests/min</td><td>Batch IDs in groups of 500</td></tr>
<tr><td>Hosts</td><td>6000 requests/min</td><td>Use query + details pattern</td></tr>
<tr><td>IOCs</td><td>6000 requests/min</td><td>Batch create up to 200 IOCs per call</td></tr>
<tr><td>RTR Sessions</td><td>100 sessions concurrently</td><td>Close sessions when done</td></tr>
</table>
`, true)}
`;
}

// ─── TAB 10: FIREWALL & USB DEVICE CONTROL ──────────────────────

function buildTab10_FirewallUSB() {
    return `
<h2 class="cs-section-title">FALCON FIREWALL & USB DEVICE CONTROL</h2>

${csCollapsible('1. FALCON FIREWALL MANAGEMENT', `
<h3>Overview</h3>
<p>Falcon Firewall Management provides host-based firewall control managed from the Falcon console. Create rules to block/allow traffic by port, protocol, IP, and application.</p>

<h3>Creating Firewall Rule Groups</h3>
<ol>
<li>Navigate to <strong>Host setup > Firewall Management > Rule Groups</strong></li>
<li>Click <strong>Create rule group</strong></li>
<li>Name: <code>POC-Firewall-Baseline</code></li>
<li>Platform: Windows</li>
<li>Add rules (see examples below)</li>
</ol>

<h3>Common POC Firewall Rules</h3>
<table class="cs-table">
<tr><th>Rule Name</th><th>Direction</th><th>Protocol</th><th>Port</th><th>Action</th><th>Purpose</th></tr>
<tr><td>Block External RDP</td><td>Inbound</td><td>TCP</td><td>3389</td><td>Block</td><td>Prevent external RDP brute force</td></tr>
<tr><td>Block External SMB</td><td>Inbound</td><td>TCP</td><td>445</td><td>Block</td><td>Prevent SMB-based attacks (WannaCry)</td></tr>
<tr><td>Block WinRM External</td><td>Inbound</td><td>TCP</td><td>5985-5986</td><td>Block</td><td>Prevent remote PS execution from outside</td></tr>
<tr><td>Allow DNS</td><td>Outbound</td><td>UDP</td><td>53</td><td>Allow</td><td>DNS resolution (corporate DNS only)</td></tr>
<tr><td>Block Tor Ports</td><td>Outbound</td><td>TCP</td><td>9001,9030</td><td>Block</td><td>Prevent Tor network connections</td></tr>
<tr><td>Block IRC</td><td>Outbound</td><td>TCP</td><td>6667,6697</td><td>Block</td><td>Prevent IRC-based C2</td></tr>
<tr><td>Block Mining Pools</td><td>Outbound</td><td>TCP</td><td>3333,4444,8333</td><td>Block</td><td>Prevent cryptomining</td></tr>
</table>

<h3>Network Location Awareness</h3>
<p>Create different rule sets based on network location — more restrictive when off-corporate network:</p>
${csCode(`Location-Based Rules:
  Corporate Network (10.0.0.0/8):
    - Allow all internal communication
    - Block external RDP/SMB
    - Monitor outbound on non-standard ports

  Public/Unknown Network:
    - Block ALL inbound except established
    - Allow only HTTPS, DNS outbound
    - Block all file sharing ports
    - Alert on any P2P traffic`, 'text')}
`, true)}

${csCollapsible('2. USB DEVICE CONTROL', `
<h3>Overview</h3>
<p>Falcon Device Control lets you manage USB and removable media policies — block, allow specific vendors, read-only access, or monitor without blocking.</p>

<h3>Policy Types</h3>
<table class="cs-table">
<tr><th>Policy</th><th>Description</th><th>When to Use</th></tr>
<tr><td>Block All USB</td><td>Block all removable storage devices</td><td>High-security environments, financial/government</td></tr>
<tr><td>Block + Whitelist</td><td>Block all except approved vendor/product IDs</td><td>Standard corporate policy</td></tr>
<tr><td>Read-Only</td><td>Allow reading USB but block writing</td><td>Prevent data exfiltration while allowing data import</td></tr>
<tr><td>Monitor Only</td><td>Allow all USB but log all activity</td><td>POC initial phase, gathering baseline</td></tr>
</table>

<h3>Creating USB Policies</h3>
<ol>
<li>Navigate to <strong>Host setup > Device Control > USB Device Policies</strong></li>
<li>Create new policy: <code>POC-USB-Control</code></li>
<li>Set default action: <strong>Block</strong></li>
<li>Add exceptions for approved devices</li>
<li>Assign to host groups</li>
</ol>

<h3>Whitelisting by Vendor/Product ID</h3>
${csCode(`USB Device Identification:
  Vendor ID (VID):  Identifies the manufacturer
  Product ID (PID): Identifies the specific product
  Serial Number:    Identifies the individual device

Example Whitelist Entries:
  Kingston DataTraveler:   VID=0951, PID=1666
  SanDisk Cruzer:          VID=0781, PID=5567
  YubiKey 5:               VID=1050, PID=0407

How to find VID/PID:
  Windows: Device Manager > USB device > Properties > Details > Hardware Ids
  Linux:   lsusb
  macOS:   system_profiler SPUSBDataType`, 'text')}

<h3>POC USB Monitoring Setup</h3>
${csCode(`Phase 1 — Monitor Only (Week 1-2):
  - Set all policies to "Monitor"
  - Collect data on USB usage patterns
  - Identify which devices are commonly used
  - Generate report of all USB activity

Phase 2 — Block + Whitelist (Week 3):
  - Create whitelist from Phase 1 data
  - Switch policy to "Block" with exceptions
  - Monitor for user complaints
  - Fine-tune whitelist

Phase 3 — Enforce (Week 4):
  - Full enforcement with whitelist
  - Read-only for non-whitelisted devices
  - Complete audit trail`, 'text')}
`, true)}
`;
}

// ─── TAB 11: CLIENT PRESENTATION ────────────────────────────────

function buildTab11_ClientPresentation() {
    return `
<h2 class="cs-section-title">CLIENT PRESENTATION & POC CLOSE GUIDE</h2>

${csCollapsible('1. EXECUTIVE SUMMARY TEMPLATE', `
<h3>Fill-in-the-Blank Executive Summary</h3>
${csCode(`CROWDSTRIKE FALCON POC — EXECUTIVE SUMMARY
═══════════════════════════════════════════

Client:          [CLIENT NAME]
POC Duration:    [START DATE] to [END DATE] ([X] days)
Endpoints:       [X] Windows, [X] Linux, [X] macOS = [TOTAL]
POC Sponsor:     [CISO/VP NAME]
CrowdStrike SE:  [YOUR NAME]

KEY RESULTS:
─────────────
✓ Sensor deployment:     [X]% success rate ([X]/[TOTAL] endpoints)
✓ Mean time to detect:   [X] seconds (target: <60s)
✓ Detections generated:  [X] total ([X] Critical, [X] High, [X] Medium)
✓ False positive rate:   [X]% (target: <5%)
✓ MITRE ATT&CK coverage: [X]% of tested techniques detected
✓ CPU impact:            [X]% average (target: <3%)
✓ User complaints:       [X] (target: 0)

DETECTIONS HIGHLIGHTS:
─────────────────────
1. [Detection name] — [Brief description of what was found]
2. [Detection name] — [Brief description]
3. [Detection name] — [Brief description]

ENVIRONMENT INSIGHTS:
───────────────────
• [X] unique threat detections found in existing environment
• [X] vulnerable applications identified via Spotlight
• [X] unmanaged endpoints discovered via Discover
• [Key insight about client's security posture]

RECOMMENDATION:
──────────────
Based on the POC results, CrowdStrike Falcon demonstrated [summary].
We recommend proceeding with a [X]-endpoint deployment of Falcon
[modules] at an estimated investment of $[X]/endpoint/year.

NEXT STEPS:
──────────
1. Executive presentation: [DATE]
2. Commercial proposal review: [DATE]
3. Procurement process: [DATE]
4. Production deployment target: [DATE]`, 'text')}
`, true)}

${csCollapsible('2. COMPETITIVE COMPARISON', `
<table class="cs-table">
<tr><th>Feature</th><th>CrowdStrike</th><th>Microsoft Defender</th><th>SentinelOne</th><th>Carbon Black</th><th>Cortex XDR</th></tr>
<tr><td>Architecture</td><td>Cloud-native, single agent</td><td>Cloud + on-prem hybrid</td><td>Cloud-native, single agent</td><td>Cloud/on-prem options</td><td>Cloud-native</td></tr>
<tr><td>Detection Engine</td><td>AI + IOA behavioral</td><td>Signature + behavioral</td><td>AI/ML static + behavioral</td><td>Behavioral + reputation</td><td>ML + behavioral + analytics</td></tr>
<tr><td>MITRE Coverage</td><td>Highest (Leader)</td><td>High</td><td>High</td><td>Medium-High</td><td>High</td></tr>
<tr><td>Threat Hunting</td><td>Falcon OverWatch (24/7 MDR)</td><td>Experts on Demand</td><td>Vigilance (add-on)</td><td>Limited</td><td>Unit 42 (add-on)</td></tr>
<tr><td>Threat Intel</td><td>Falcon X (integrated)</td><td>Microsoft TI</td><td>Built-in TI</td><td>3rd party needed</td><td>AutoFocus</td></tr>
<tr><td>SIEM Integration</td><td>Event Streams + API</td><td>Native to Sentinel</td><td>Syslog + API</td><td>Syslog + API</td><td>Native to Cortex</td></tr>
<tr><td>Cloud Security</td><td>Falcon Cloud Security</td><td>Defender for Cloud</td><td>Cloud Workload Security</td><td>Limited</td><td>Prisma Cloud</td></tr>
<tr><td>Vulnerability Mgmt</td><td>Falcon Spotlight (agentless)</td><td>TVM (integrated)</td><td>Ranger (network)</td><td>Limited</td><td>Cortex Xpanse</td></tr>
<tr><td>Pricing Model</td><td>Per endpoint/year</td><td>Per user/month (M365)</td><td>Per endpoint/year</td><td>Per endpoint/year</td><td>Per endpoint/year</td></tr>
</table>

<h3>CrowdStrike Differentiators (Talking Points)</h3>
<ul>
<li><strong>Single lightweight agent:</strong> ~1% CPU, 60MB RAM — competitors average 3-5%</li>
<li><strong>Cloud-native from day 1:</strong> No on-prem servers, no VPN needed for management</li>
<li><strong>OverWatch:</strong> 24/7 human threat hunters watching your environment — no one else includes this</li>
<li><strong>Threat Graph:</strong> Processes 7+ trillion events/week — the largest security dataset in the world</li>
<li><strong>1-second SLA:</strong> Detect in 1 second, investigate in 10 minutes, respond in 60 minutes</li>
<li><strong>MITRE ATT&CK Leader:</strong> Consistently top performer in MITRE evaluations</li>
<li><strong>Platform consolidation:</strong> Replace 5-8 tools with one platform (AV, EDR, vuln mgmt, threat intel, IT hygiene)</li>
</ul>
`, true)}

${csCollapsible('3. OBJECTION HANDLING', `
<table class="cs-table">
<tr><th>Objection</th><th>Response</th></tr>
<tr><td>"Too expensive"</td><td>Calculate TCO including tool consolidation. CrowdStrike replaces AV + EDR + vuln scanner + threat intel + IT hygiene. Show ROI calculator. Average customer saves 30-40% on total security tooling.</td></tr>
<tr><td>"We already have Microsoft Defender"</td><td>Defender is good for basic protection but lacks: dedicated 24/7 threat hunting (OverWatch), integrated threat intelligence (Falcon X), cloud workload protection depth, and CrowdStrike's detection efficacy leads in every MITRE evaluation.</td></tr>
<tr><td>"Cloud concerns / data privacy"</td><td>CrowdStrike holds SOC 2 Type II, FedRAMP, ISO 27001, GDPR compliance. Data is encrypted in transit + at rest. Multiple cloud regions (US-1, US-2, EU-1, US-GOV). Metadata only — no file content uploaded.</td></tr>
<tr><td>"We need on-prem"</td><td>Cloud-native is MORE secure and reliable. No patching SIEM servers, no capacity planning. CrowdStrike's cloud processes 7T+ events/week — impossible on-prem. For air-gapped, discuss Falcon Flex.</td></tr>
<tr><td>"Our team is too small"</td><td>That's exactly why you need CrowdStrike. OverWatch provides 24/7 hunting. Falcon Complete provides full MDR. One SOC analyst can manage 10,000 endpoints with Falcon vs 500 with legacy tools.</td></tr>
<tr><td>"Need to see it work first"</td><td>That's what the POC is for! We'll deploy on [X] endpoints, run real-world tests, and show you detections in your own environment. No cost, no obligation.</td></tr>
</table>
`, true)}

${csCollapsible('4. EMAIL TEMPLATES', `
<h3>POC Kickoff Email</h3>
${csCode(`Subject: CrowdStrike Falcon POC — Kickoff Details

Hi [Client Name],

Thank you for the opportunity to demonstrate CrowdStrike Falcon in your
environment. Here are the details for our POC engagement:

POC Timeline: [Start Date] - [End Date]
Target Endpoints: [Number] across [Windows/Linux/macOS]
Falcon Console Access: [URL]

Pre-POC Requirements:
  1. Admin access to [X] test endpoints
  2. Network access from endpoints to *.crowdstrike.com (port 443)
  3. Existing AV exclusion for CrowdStrike (if running side-by-side)
  4. Designated technical contact for sensor deployment

I've attached the deployment guide and will send calendar invites for:
  - Kickoff call: [Date/Time]
  - Week 1 check-in: [Date/Time]
  - Closeout presentation: [Date/Time]

Please let me know if you have any questions.

Best regards,
[Your Name]`, 'text')}

<h3>POC Closeout / PO Request Email</h3>
${csCode(`Subject: CrowdStrike Falcon POC Results — Next Steps

Hi [Client Name],

Thank you for a successful POC. Here's a summary of what we found:

Key Results:
  ✓ [X]% deployment success rate
  ✓ [X] real threats detected in your environment
  ✓ [X]-second average detection time
  ✓ <[X]% CPU impact on endpoints
  ✓ [X]% MITRE ATT&CK coverage

Based on these results, I'd like to propose the following:

Recommended Package: Falcon [Insight/Prevent/Complete]
Endpoint Count: [X]
Annual Investment: $[X]

I've attached the detailed POC report and commercial proposal.
Could we schedule a call this week to discuss next steps?

Best regards,
[Your Name]`, 'text')}
`, true)}

${csCollapsible('5. DISCOVERY CALL QUESTIONS', `
<h3>Questions to Ask the Client</h3>
<table class="cs-table">
<tr><th>Category</th><th>Questions</th></tr>
<tr><td>Current State</td><td>What AV/EDR do you currently use? What are your biggest pain points? Have you had any incidents in the last 12 months?</td></tr>
<tr><td>Environment</td><td>How many endpoints? OS mix? Any cloud workloads (AWS/Azure/GCP)? Remote workers? Any OT/IoT?</td></tr>
<tr><td>Team</td><td>How big is your security team? Do you have a SOC? What are your biggest skill gaps? Do you use an MSSP?</td></tr>
<tr><td>Compliance</td><td>What compliance requirements? (PCI, HIPAA, SOX, GDPR, FedRAMP) Any upcoming audits?</td></tr>
<tr><td>Budget</td><td>What's your security budget cycle? When does current contract expire? Who approves the purchase?</td></tr>
<tr><td>Decision</td><td>What does the evaluation process look like? Who else is being evaluated? What would make this a successful POC for you?</td></tr>
</table>
`, true)}
`;
}

// ─── TAB 12: TROUBLESHOOTING & FAQ ──────────────────────────────

function buildTab12_TroubleshootFAQ() {
    return `
<h2 class="cs-section-title">TROUBLESHOOTING & FAQ</h2>

${csCollapsible('SENSOR NOT REPORTING TO CONSOLE', `
<h3>Windows</h3>
${csCode(`# Check if sensor service is running
sc query csagent
sc query csfalconservice

# Check sensor connectivity
netsh advfirewall firewall show rule name="CrowdStrike"

# Test connectivity to CrowdStrike cloud
Test-NetConnection ts01-b.cloudsink.net -Port 443
Test-NetConnection lfodown01-b.cloudsink.net -Port 443

# Check sensor logs
Get-Content "C:\\Windows\\System32\\drivers\\CrowdStrike\\hbfw.log" -Tail 50

# Verify CID
reg query "HKLM\\SYSTEM\\CrowdStrike\\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\\{16e0423f-7058-48c9-a204-725362b67639}\\Default" /v CU

# Reinstall sensor
msiexec /x {product-code} /quiet
msiexec /i CsAgentMSI.msi CID=YOUR_CID /quiet /norestart`, 'powershell')}

<h3>Linux</h3>
${csCode(`# Check sensor status
sudo /opt/CrowdStrike/falconctl -g --cid
sudo systemctl status falcon-sensor
sudo /opt/CrowdStrike/falconctl -g --rfm-state

# RFM (Reduced Functionality Mode) means kernel module issue
# Check kernel compatibility
uname -r
sudo /opt/CrowdStrike/falconctl -g --version

# Reinstall sensor
sudo dpkg -r falcon-sensor  # Debian/Ubuntu
sudo rpm -e falcon-sensor   # RHEL/CentOS
# Then reinstall with dpkg -i or rpm -i`, 'bash')}

<h3>macOS</h3>
${csCode(`# Check sensor status
sudo /Applications/Falcon.app/Contents/Resources/falconctl stats

# Common issue: System Extension not approved
# Fix: System Preferences > Security & Privacy > Allow CrowdStrike
# Or deploy MDM profile to pre-approve

# Check Full Disk Access
# System Preferences > Security & Privacy > Privacy > Full Disk Access
# Falcon.app must be listed and checked`, 'bash')}
`, true)}

${csCollapsible('SENSOR HIGH CPU USAGE', `
<h3>Diagnosis Steps</h3>
${csCode(`# Check which process is using CPU
# In Falcon console: Host Management > Host > System Performance

# Common causes:
1. Initial scan after deployment (normal — wait 24-48 hours)
2. Scanning large file shares or backup volumes
3. Incompatible software (check exclusions)
4. Outdated sensor version (update to latest N-1)

# Fix: Add performance exclusions
# Falcon Console > Host setup > Sensor Exclusions
# Add paths for:
# - Backup volumes
# - Database files (.mdf, .ldf, .bak)
# - Development build directories
# - AV scan directories (if running side-by-side)`, 'text')}

<h3>Recommended Exclusions for Common Software</h3>
<table class="cs-table">
<tr><th>Software</th><th>Exclude Paths</th></tr>
<tr><td>SQL Server</td><td>*.mdf, *.ldf, *.ndf, *.bak, C:\\Program Files\\Microsoft SQL Server\\</td></tr>
<tr><td>Exchange</td><td>*.edb, *.stm, *.log in Exchange directories</td></tr>
<tr><td>Backup Software</td><td>Backup volume mount points, *.bak, *.vhdx</td></tr>
<tr><td>Development</td><td>node_modules, .git, build output directories</td></tr>
<tr><td>Other AV/EDR</td><td>Other security product directories (if running side-by-side)</td></tr>
</table>
`, true)}

${csCollapsible('COMMON INSTALLATION ERRORS', `
<table class="cs-table">
<tr><th>Error</th><th>Cause</th><th>Fix</th></tr>
<tr><td>Error 1603</td><td>Generic MSI failure</td><td>Check C:\\cs_install.log, ensure admin rights, check disk space</td></tr>
<tr><td>Error 1638</td><td>Another version installed</td><td>Uninstall existing sensor first, then reinstall</td></tr>
<tr><td>Sensor installed but not in console</td><td>Wrong CID or network blocked</td><td>Verify CID, test connectivity to *.crowdstrike.com:443</td></tr>
<tr><td>RFM state on Linux</td><td>Kernel not supported</td><td>Update sensor or use supported kernel version</td></tr>
<tr><td>macOS System Extension blocked</td><td>MDM profile not deployed</td><td>Approve in System Preferences or deploy MDM KEXT profile</td></tr>
</table>
`, true)}

${csCollapsible('NETWORK REQUIREMENTS', `
<h3>URLs to Whitelist</h3>
<table class="cs-table">
<tr><th>URL Pattern</th><th>Port</th><th>Purpose</th></tr>
<tr><td>ts01-b.cloudsink.net</td><td>443</td><td>Sensor telemetry upload</td></tr>
<tr><td>lfodown01-b.cloudsink.net</td><td>443</td><td>Sensor updates & downloads</td></tr>
<tr><td>falcon.crowdstrike.com</td><td>443</td><td>Console access (US-1)</td></tr>
<tr><td>api.crowdstrike.com</td><td>443</td><td>API access</td></tr>
<tr><td>firehose.crowdstrike.com</td><td>443</td><td>Event streaming</td></tr>
</table>

<p class="cs-note">For proxy environments: configure proxy during sensor install with APP_PROXYNAME and APP_PROXYPORT parameters.</p>
`, true)}

${csCollapsible('FAQ', `
<h3>Licensing</h3>
<table class="cs-table">
<tr><th>Question</th><th>Answer</th></tr>
<tr><td>Licensing model?</td><td>Per-endpoint/year subscription. Volume discounts available. Bundles: Falcon Go, Pro, Enterprise, Elite, Complete.</td></tr>
<tr><td>What modules are included?</td><td>Depends on bundle. Falcon Prevent (NGAV) is base. Add Insight (EDR), Discover (IT hygiene), Spotlight (vuln), OverWatch (MDR), Complete (full MDR).</td></tr>
<tr><td>Cloud regions?</td><td>US-1 (Virginia), US-2 (Oregon), EU-1 (Frankfurt), US-GOV (GovCloud). Data stays in chosen region.</td></tr>
<tr><td>Data residency?</td><td>Customer chooses cloud region at onboarding. Data doesn't leave the region. Metadata only (no file content) is uploaded.</td></tr>
<tr><td>Compliance certs?</td><td>SOC 2 Type II, FedRAMP, ISO 27001/27018, GDPR, PCI DSS, HIPAA, CSA STAR, NSA CISA recommendations.</td></tr>
<tr><td>Sensor update frequency?</td><td>Sensor updates every ~2 weeks. Content updates (IOAs/IOCs) multiple times daily. N-1 policy recommended for stability.</td></tr>
<tr><td>Can we uninstall easily?</td><td>Yes — requires maintenance token (prevents unauthorized removal). Standard MSI/RPM/DEB uninstall process.</td></tr>
<tr><td>Does it replace AV?</td><td>Yes. Falcon Prevent is a certified NGAV. You can remove legacy AV after deploying Falcon in PREVENT mode.</td></tr>
</table>
`, true)}
`;
}

// ─── ROI CALCULATOR ──────────────────────────────────────────────
function csCalcROI() {
    const endpoints = parseInt(document.getElementById('roi-endpoints').value) || 0;
    const incidents = parseInt(document.getElementById('roi-incidents').value) || 0;
    const hours = parseInt(document.getElementById('roi-hours').value) || 0;
    const rate = parseInt(document.getElementById('roi-rate').value) || 0;
    const currentCost = parseInt(document.getElementById('roi-current').value) || 0;
    const breachReduction = parseInt(document.getElementById('roi-breach').value) || 0;

    const investigationSavings = incidents * hours * 0.5 * rate; // 50% time reduction
    const avgBreachCost = 4450000;
    const breachRiskValue = avgBreachCost * (breachReduction / 100) * 0.05; // 5% annual probability
    const toolConsolidation = currentCost * 0.3; // 30% tool consolidation
    const totalSavings = investigationSavings + breachRiskValue + toolConsolidation;
    const csEstCost = endpoints * 25 * 12; // ~$25/endpoint/month estimate
    const netROI = totalSavings - csEstCost;
    const roiPercent = csEstCost > 0 ? ((netROI / csEstCost) * 100).toFixed(0) : 0;

    document.getElementById('roi-result').innerHTML = `
        <h4>ROI Analysis Results</h4>
        <table class="cs-table">
        <tr><td>Investigation Time Savings (50% reduction)</td><td>$${investigationSavings.toLocaleString()}/year</td></tr>
        <tr><td>Breach Risk Reduction Value</td><td>$${breachRiskValue.toLocaleString()}/year</td></tr>
        <tr><td>Tool Consolidation Savings (est. 30%)</td><td>$${toolConsolidation.toLocaleString()}/year</td></tr>
        <tr><td><strong>Total Estimated Savings</strong></td><td><strong>$${totalSavings.toLocaleString()}/year</strong></td></tr>
        <tr><td>Estimated CrowdStrike Cost (~$25/endpoint/mo)</td><td>$${csEstCost.toLocaleString()}/year</td></tr>
        <tr><td><strong>Net ROI</strong></td><td><strong style="color:${netROI >= 0 ? '#0f0' : '#f00'}">$${netROI.toLocaleString()}/year (${roiPercent}%)</strong></td></tr>
        </table>
        <p class="cs-note">* These are estimates for discussion purposes. Adjust inputs to match client's environment.</p>
    `;
}

// ─── MAIN FUNCTION ───────────────────────────────────────────────

function loadCrowdStrikePOC() {
    document.getElementById('dashboard').classList.add('hidden');
    const content = document.getElementById('page-content');
    content.classList.remove('hidden');

    content.innerHTML = `
<style>
    .cs-container { max-width: 1200px; margin: 0 auto; padding: 20px; font-family: 'Courier New', monospace; }
    .cs-header { text-align: center; border-bottom: 2px solid #0f0; padding-bottom: 20px; margin-bottom: 20px; }
    .cs-header h1 { color: #0f0; font-size: 1.8em; text-shadow: 0 0 10px rgba(0,255,0,0.3); margin: 0; }
    .cs-header p { color: #888; margin: 5px 0 0 0; }
    .cs-tab-bar { display: flex; flex-wrap: wrap; gap: 2px; margin-bottom: 0; border-bottom: 2px solid #0f0; background: #0a0a0a; }
    .cs-tab-btn { background: #111; color: #0f0; border: 1px solid #333; border-bottom: none; padding: 10px 14px; cursor: pointer; font-family: 'Courier New', monospace; font-size: 0.75em; transition: all 0.2s; white-space: nowrap; }
    .cs-tab-btn:hover { background: #1a2a1a; }
    .cs-tab-btn.active { background: #0a1a0a; border-color: #0f0; color: #fff; font-weight: bold; border-bottom: 2px solid #0a1a0a; position: relative; top: 2px; }
    .cs-tab-content { display: none; padding: 20px; background: #0a0a0a; border: 1px solid #222; border-top: none; }
    .cs-tab-content.active { display: block; }
    .cs-section-title { color: #0f0; font-size: 1.4em; border-bottom: 1px solid #333; padding-bottom: 10px; margin-top: 0; }
    .cs-mitre-tactic { color: #ff6600; font-size: 1.1em; margin-top: 25px; border-left: 3px solid #ff6600; padding-left: 10px; }
    .cs-table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 0.85em; }
    .cs-table th { background: #1a1a1a; color: #0f0; padding: 8px 10px; text-align: left; border: 1px solid #333; }
    .cs-table td { padding: 8px 10px; border: 1px solid #222; color: #ccc; }
    .cs-table tr:hover td { background: #111; }
    .cs-code-block { background: #0d0d0d; border: 1px solid #333; border-radius: 4px; margin: 10px 0; overflow: hidden; }
    .cs-code-header { display: flex; justify-content: space-between; align-items: center; padding: 5px 10px; background: #1a1a1a; border-bottom: 1px solid #333; }
    .cs-code-header span { color: #666; font-size: 0.75em; }
    .cs-code-header button { background: none; border: 1px solid #444; color: #0f0; padding: 2px 10px; cursor: pointer; font-family: 'Courier New', monospace; font-size: 0.75em; }
    .cs-code-header button:hover { background: #1a2a1a; }
    .cs-code-block pre { margin: 0; padding: 12px; overflow-x: auto; }
    .cs-code-block code { color: #0f0; font-size: 0.82em; line-height: 1.5; white-space: pre; }
    .cs-collapsible { margin: 10px 0; border: 1px solid #222; border-radius: 4px; }
    .cs-collapse-header { padding: 10px 15px; background: #111; color: #0f0; cursor: pointer; font-weight: bold; font-size: 0.9em; }
    .cs-collapse-header:hover { background: #1a2a1a; }
    .cs-collapse-arrow { color: #666; margin-right: 8px; font-size: 0.8em; }
    .cs-collapse-body { padding: 15px; background: #0a0a0a; }
    .cs-check { display: block; padding: 5px 0; color: #ccc; cursor: pointer; font-size: 0.85em; }
    .cs-check input { margin-right: 8px; accent-color: #0f0; }
    .cs-check input:checked + span { color: #0f0; text-decoration: line-through; opacity: 0.7; }
    .cs-note { color: #888; font-style: italic; font-size: 0.85em; border-left: 3px solid #444; padding-left: 10px; margin: 10px 0; }
    .cs-warning { color: #ff6600; background: #1a1000; border: 1px solid #ff6600; padding: 10px 15px; border-radius: 4px; margin: 15px 0; font-size: 0.85em; }
    .cs-btn { background: #0f0; color: #000; border: none; padding: 8px 20px; cursor: pointer; font-family: 'Courier New', monospace; font-weight: bold; margin: 10px 0; }
    .cs-btn:hover { background: #0c0; }
    .cs-btn-sm { background: #222; color: #0f0; border: 1px solid #444; padding: 3px 10px; cursor: pointer; font-family: 'Courier New', monospace; font-size: 0.8em; margin: 5px 0; }
    .cs-btn-sm:hover { background: #333; }
    .cs-roi-calc { background: #111; padding: 20px; border: 1px solid #333; border-radius: 4px; }
    .cs-roi-row { margin: 10px 0; display: flex; justify-content: space-between; align-items: center; }
    .cs-roi-row label { color: #ccc; font-size: 0.85em; }
    .cs-roi-row input { background: #0a0a0a; border: 1px solid #444; color: #0f0; padding: 5px 10px; width: 150px; font-family: 'Courier New', monospace; text-align: right; }
    .cs-roi-result { margin-top: 15px; padding: 15px; background: #0a1a0a; border: 1px solid #0f0; border-radius: 4px; }
    .cs-quiz .cs-question { margin: 15px 0; padding: 15px; background: #111; border: 1px solid #222; border-radius: 4px; }
    .cs-quiz .cs-question p { color: #ccc; font-size: 0.85em; margin: 5px 0; }
    .cs-quiz .cs-answer { margin-top: 10px; padding: 10px; background: #0a1a0a; border: 1px solid #0f0; border-radius: 4px; }
    .cs-quiz .cs-answer p { color: #0f0; }
    .cs-back-btn { background: none; border: 1px solid #0f0; color: #0f0; padding: 5px 15px; cursor: pointer; font-family: 'Courier New', monospace; float: right; }
    .cs-back-btn:hover { background: #1a2a1a; }
    h3 { color: #0f0; margin-top: 20px; }
    h4 { color: #0a0; margin-top: 15px; }
    p, li { color: #ccc; font-size: 0.88em; line-height: 1.6; }
    ul, ol { padding-left: 25px; }
    strong { color: #0f0; }
    code { color: #0f0; background: #111; padding: 1px 5px; border-radius: 3px; }
    @media (max-width: 768px) {
        .cs-tab-btn { font-size: 0.65em; padding: 6px 8px; }
        .cs-roi-row { flex-direction: column; align-items: flex-start; }
        .cs-roi-row input { width: 100%; margin-top: 5px; }
    }
</style>

<div class="cs-container">
    <div class="cs-header">
        <button class="cs-back-btn" onclick="goHome()">&#9666; DASHBOARD</button>
        <h1>&#x1F6E1; CROWDSTRIKE FALCON POC MODULE</h1>
        <p>Complete Proof-of-Concept Deployment, Configuration & Success Guide</p>
    </div>

    <div class="cs-tab-bar">
        <button class="cs-tab-btn active" data-tab="cs-tab-1" onclick="csSwitchTab('cs-tab-1')">1. DEPLOYMENT</button>
        <button class="cs-tab-btn" data-tab="cs-tab-2" onclick="csSwitchTab('cs-tab-2')">2. IOA RULES</button>
        <button class="cs-tab-btn" data-tab="cs-tab-3" onclick="csSwitchTab('cs-tab-3')">3. LOGSCALE</button>
        <button class="cs-tab-btn" data-tab="cs-tab-4" onclick="csSwitchTab('cs-tab-4')">4. RTR</button>
        <button class="cs-tab-btn" data-tab="cs-tab-5" onclick="csSwitchTab('cs-tab-5')">5. PREVENTION</button>
        <button class="cs-tab-btn" data-tab="cs-tab-6" onclick="csSwitchTab('cs-tab-6')">6. FUSION/SOAR</button>
        <button class="cs-tab-btn" data-tab="cs-tab-7" onclick="csSwitchTab('cs-tab-7')">7. POC PLAYBOOK</button>
        <button class="cs-tab-btn" data-tab="cs-tab-8" onclick="csSwitchTab('cs-tab-8')">8. CERT PREP</button>
        <button class="cs-tab-btn" data-tab="cs-tab-9" onclick="csSwitchTab('cs-tab-9')" style="color:#00d4ff">9. API</button>
        <button class="cs-tab-btn" data-tab="cs-tab-10" onclick="csSwitchTab('cs-tab-10')" style="color:#00d4ff">10. FW/USB</button>
        <button class="cs-tab-btn" data-tab="cs-tab-11" onclick="csSwitchTab('cs-tab-11')" style="color:#ff6600">11. CLIENT</button>
        <button class="cs-tab-btn" data-tab="cs-tab-12" onclick="csSwitchTab('cs-tab-12')" style="color:#ff6600">12. FAQ</button>
    </div>

    <div id="cs-tab-1" class="cs-tab-content active">${buildTab1_DeploymentGuide()}</div>
    <div id="cs-tab-2" class="cs-tab-content">${buildTab2_IOARules()}</div>
    <div id="cs-tab-3" class="cs-tab-content">${buildTab3_LogScaleQueries()}</div>
    <div id="cs-tab-4" class="cs-tab-content">${buildTab4_RTR()}</div>
    <div id="cs-tab-5" class="cs-tab-content">${buildTab5_PreventionPolicies()}</div>
    <div id="cs-tab-6" class="cs-tab-content">${buildTab6_FusionSOAR()}</div>
    <div id="cs-tab-7" class="cs-tab-content">${buildTab7_POCPlaybook()}</div>
    <div id="cs-tab-8" class="cs-tab-content">${buildTab8_Certification()}</div>
    <div id="cs-tab-9" class="cs-tab-content">${buildTab9_APIIntegration()}</div>
    <div id="cs-tab-10" class="cs-tab-content">${buildTab10_FirewallUSB()}</div>
    <div id="cs-tab-11" class="cs-tab-content">${buildTab11_ClientPresentation()}</div>
    <div id="cs-tab-12" class="cs-tab-content">${buildTab12_TroubleshootFAQ()}</div>
</div>
`;
}
