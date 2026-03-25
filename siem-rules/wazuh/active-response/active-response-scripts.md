# Wazuh Active Response Scripts Guide

## Overview

Wazuh Active Response allows automated actions when specific rules trigger. This guide covers configuring and creating custom active response scripts.

## Built-in Active Responses

### 1. Block IP with Firewall (Linux iptables)

**ossec.conf configuration:**
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100,100101,100110</rules_id>
  <timeout>3600</timeout>
</active-response>
```

### 2. Block IP with Windows Firewall

```xml
<active-response>
  <command>netsh</command>
  <location>local</location>
  <rules_id>100100,100143</rules_id>
  <timeout>3600</timeout>
</active-response>
```

### 3. Disable User Account

```xml
<active-response>
  <command>disable-account</command>
  <location>server</location>
  <rules_id>100105,100262</rules_id>
  <timeout>0</timeout>
</active-response>
```

## Custom Active Response Scripts

### Script: Block IP and Notify SOC

**Location:** `/var/ossec/active-response/bin/block-and-notify.sh`

```bash
#!/bin/bash
# Block IP and send notification to SOC

ACTION=$1
USER=$2
IP=$3
ALERT_ID=$4
RULE_ID=$5
AGENT=$6
FILENAME=$7

LOG_FILE="/var/ossec/logs/active-responses.log"
SLACK_WEBHOOK="${WAZUH_SLACK_WEBHOOK}"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

if [ "$ACTION" = "add" ]; then
    # Block IP
    iptables -I INPUT -s "$IP" -j DROP
    iptables -I FORWARD -s "$IP" -j DROP
    log "BLOCKED: IP $IP (Rule: $RULE_ID, Agent: $AGENT)"

    # Send Slack notification
    if [ -n "$SLACK_WEBHOOK" ]; then
        PAYLOAD="{\"text\":\"*Wazuh Active Response*\nBlocked IP: \`$IP\`\nRule ID: $RULE_ID\nAgent: $AGENT\nAlert ID: $ALERT_ID\"}"
        curl -s -X POST -H 'Content-type: application/json' --data "$PAYLOAD" "$SLACK_WEBHOOK"
    fi

elif [ "$ACTION" = "delete" ]; then
    # Unblock IP (timeout reached)
    iptables -D INPUT -s "$IP" -j DROP
    iptables -D FORWARD -s "$IP" -j DROP
    log "UNBLOCKED: IP $IP (timeout)"
fi

exit 0
```

### Script: Kill Malicious Process

**Location:** `/var/ossec/active-response/bin/kill-process.sh`

```bash
#!/bin/bash
# Kill process matching suspicious criteria

ACTION=$1
USER=$2
IP=$3

LOG_FILE="/var/ossec/logs/active-responses.log"

if [ "$ACTION" = "add" ]; then
    # Extract process info from alert
    ALERT=$(cat /var/ossec/logs/alerts/alerts.json | tail -1)
    PROCESS_NAME=$(echo "$ALERT" | jq -r '.data.win.eventdata.image // empty')
    PROCESS_PID=$(echo "$ALERT" | jq -r '.data.win.eventdata.processId // empty')

    if [ -n "$PROCESS_PID" ]; then
        kill -9 "$PROCESS_PID" 2>/dev/null
        echo "$(date) KILLED: PID $PROCESS_PID ($PROCESS_NAME)" >> "$LOG_FILE"
    fi
fi
exit 0
```

### Script: Isolate Host (Network Quarantine)

```bash
#!/bin/bash
# Isolate compromised host by restricting network access

ACTION=$1
IP=$3
MANAGER_IP="10.0.0.100"

if [ "$ACTION" = "add" ]; then
    # Allow only communication with Wazuh manager
    iptables -F
    iptables -A INPUT -s "$MANAGER_IP" -j ACCEPT
    iptables -A OUTPUT -d "$MANAGER_IP" -j ACCEPT
    iptables -A INPUT -j DROP
    iptables -A OUTPUT -j DROP
    echo "$(date) HOST ISOLATED - only Wazuh manager communication allowed" >> /var/ossec/logs/active-responses.log
elif [ "$ACTION" = "delete" ]; then
    iptables -F
    echo "$(date) HOST ISOLATION REMOVED" >> /var/ossec/logs/active-responses.log
fi
exit 0
```

## Registering Custom Commands

Add to **ossec.conf** on the manager:

```xml
<command>
  <name>block-and-notify</name>
  <executable>block-and-notify.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<command>
  <name>kill-process</name>
  <executable>kill-process.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<command>
  <name>isolate-host</name>
  <executable>isolate-host.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

## Linking Rules to Active Responses

```xml
<!-- Block brute force attackers for 1 hour -->
<active-response>
  <command>block-and-notify</command>
  <location>local</location>
  <rules_id>100100,100101,100109,100110</rules_id>
  <timeout>3600</timeout>
</active-response>

<!-- Kill suspicious processes immediately -->
<active-response>
  <command>kill-process</command>
  <location>local</location>
  <rules_id>100262,100185</rules_id>
  <timeout>0</timeout>
</active-response>

<!-- Isolate host on critical detection -->
<active-response>
  <command>isolate-host</command>
  <location>local</location>
  <rules_id>100105,100262</rules_id>
  <timeout>7200</timeout>
</active-response>
```

## Testing Active Responses

```bash
# Test a specific active response
/var/ossec/bin/agent_control -b 192.168.1.100 -f firewall-drop0 -u 001

# Check active response log
tail -f /var/ossec/logs/active-responses.log

# List blocked IPs
iptables -L INPUT -n | grep DROP

# Manually unblock
/var/ossec/active-response/bin/firewall-drop.sh delete - 192.168.1.100
```

## Best Practices

1. **Always set timeouts** - Avoid permanent blocks that could cause operational issues
2. **Test in non-production first** - Active responses can disrupt services
3. **Log all actions** - Maintain audit trail for incident review
4. **Use allowlists** - Prevent blocking critical infrastructure IPs
5. **Rate limit responses** - Avoid response storms from alert floods
6. **Monitor response effectiveness** - Track which responses successfully contain threats
