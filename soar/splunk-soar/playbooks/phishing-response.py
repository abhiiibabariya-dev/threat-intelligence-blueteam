"""
Splunk SOAR Playbook: Phishing Email Response
Automates triage, enrichment, and response for phishing alerts.
"""

import phantom.rules as phantom
import json


@phantom.playbook_block()
def on_start(container):
    """Entry point - extract IOCs from phishing email."""
    phantom.debug("Starting Phishing Response Playbook")

    # Extract email artifacts
    success, message, artifacts = phantom.get_artifacts(container_id=container["id"])

    email_artifacts = [a for a in artifacts if a.get("label") == "email"]
    url_artifacts = [a for a in artifacts if a.get("label") == "url"]
    file_artifacts = [a for a in artifacts if a.get("label") == "file"]

    if email_artifacts:
        extract_indicators(container=container, email_artifacts=email_artifacts)
    if url_artifacts:
        check_url_reputation(container=container, url_artifacts=url_artifacts)
    if file_artifacts:
        detonate_file(container=container, file_artifacts=file_artifacts)


@phantom.playbook_block()
def extract_indicators(container, email_artifacts):
    """Extract URLs, domains, IPs, and hashes from email."""
    for artifact in email_artifacts:
        cef = artifact.get("cef", {})
        sender = cef.get("fromAddress", "")
        subject = cef.get("subject", "")
        body_urls = cef.get("requestURL", [])
        source_ip = cef.get("sourceAddress", "")

        phantom.debug(f"Processing email from: {sender}, Subject: {subject}")

        # Check sender reputation
        if sender:
            phantom.act(
                "domain reputation",
                parameters=[{"domain": sender.split("@")[-1]}],
                assets=["virustotal"],
                callback=process_domain_reputation,
                name="check_sender_domain"
            )

        # Check source IP
        if source_ip:
            phantom.act(
                "ip reputation",
                parameters=[{"ip": source_ip}],
                assets=["virustotal"],
                callback=process_ip_reputation,
                name="check_source_ip"
            )


@phantom.playbook_block()
def check_url_reputation(container, url_artifacts):
    """Check all extracted URLs against threat intelligence."""
    for artifact in url_artifacts:
        url = artifact.get("cef", {}).get("requestURL", "")
        if url:
            phantom.act(
                "url reputation",
                parameters=[{"url": url}],
                assets=["virustotal"],
                callback=process_url_reputation,
                name="check_url_vt"
            )

            phantom.act(
                "url reputation",
                parameters=[{"url": url}],
                assets=["urlscan"],
                callback=process_urlscan_result,
                name="check_url_urlscan"
            )


@phantom.playbook_block()
def detonate_file(container, file_artifacts):
    """Submit suspicious attachments to sandbox."""
    for artifact in file_artifacts:
        vault_id = artifact.get("cef", {}).get("vaultId", "")
        if vault_id:
            phantom.act(
                "detonate file",
                parameters=[{"vault_id": vault_id}],
                assets=["wildfire"],  # or cuckoo, joe_sandbox, any_run
                callback=process_detonation_result,
                name="detonate_attachment"
            )


@phantom.playbook_block()
def process_domain_reputation(action, success, container, results, handle):
    """Process domain reputation results."""
    if not success:
        phantom.debug("Domain reputation check failed")
        return

    for result in results:
        data = result.get("data", {})
        positives = data.get("positives", 0)
        domain = result.get("parameter", {}).get("domain", "")

        if positives > 3:
            phantom.debug(f"MALICIOUS domain detected: {domain} ({positives} detections)")

            # Block sender domain at email gateway
            phantom.act(
                "block sender",
                parameters=[{"email": f"*@{domain}"}],
                assets=["exchange"],
                name="block_malicious_sender"
            )

            # Update incident severity
            phantom.set_severity(container=container, severity="high")
            phantom.add_note(
                container=container,
                content=f"Malicious sender domain: {domain} ({positives} VT detections). Domain blocked.",
                note_type="general",
                title="Phishing - Malicious Domain"
            )
        else:
            phantom.debug(f"Domain {domain} appears clean ({positives} detections)")


@phantom.playbook_block()
def process_url_reputation(action, success, container, results, handle):
    """Process URL reputation results and block if malicious."""
    if not success:
        return

    for result in results:
        data = result.get("data", {})
        positives = data.get("positives", 0)
        url = result.get("parameter", {}).get("url", "")

        if positives > 2:
            phantom.debug(f"MALICIOUS URL detected: {url}")

            # Block URL at proxy
            phantom.act(
                "block url",
                parameters=[{"url": url}],
                assets=["proxy"],
                name="block_malicious_url"
            )

            # Search for other recipients who may have clicked
            phantom.act(
                "run query",
                parameters=[{"query": f'index=proxy url="{url}" | stats count by src_ip, user'}],
                assets=["splunk"],
                callback=identify_affected_users,
                name="search_url_clicks"
            )

            phantom.set_severity(container=container, severity="high")


@phantom.playbook_block()
def process_urlscan_result(action, success, container, results, handle):
    """Process URLscan.io results for screenshot and analysis."""
    if not success:
        return
    for result in results:
        data = result.get("data", {})
        verdict = data.get("verdicts", {}).get("overall", {})
        if verdict.get("malicious", False):
            phantom.add_note(
                container=container,
                content=f"URLscan verdict: MALICIOUS. Screenshot available.",
                note_type="general",
                title="URLscan Analysis"
            )


@phantom.playbook_block()
def process_detonation_result(action, success, container, results, handle):
    """Process sandbox detonation results."""
    if not success:
        return

    for result in results:
        data = result.get("data", {})
        verdict = data.get("verdict", "unknown")
        sha256 = data.get("sha256", "")

        if verdict in ["malicious", "malware"]:
            phantom.debug(f"MALICIOUS file detected: {sha256}")

            # Block hash across EDR
            phantom.act(
                "block hash",
                parameters=[{"hash": sha256}],
                assets=["crowdstrike"],
                name="block_file_hash"
            )

            # Quarantine email from all mailboxes
            phantom.act(
                "quarantine email",
                parameters=[{"message_id": container.get("source_data_identifier")}],
                assets=["exchange"],
                name="quarantine_phishing_email"
            )

            phantom.set_severity(container=container, severity="critical")
            phantom.add_note(
                container=container,
                content=f"Malicious attachment detonated. SHA256: {sha256}. Hash blocked. Email quarantined.",
                note_type="general",
                title="Malicious Attachment"
            )


@phantom.playbook_block()
def identify_affected_users(action, success, container, results, handle):
    """Identify users who clicked the malicious link."""
    if not success:
        return

    for result in results:
        affected_users = result.get("data", [])
        if affected_users:
            user_list = ", ".join([u.get("user", "unknown") for u in affected_users[:20]])
            phantom.add_note(
                container=container,
                content=f"Users who accessed malicious URL: {user_list}",
                note_type="general",
                title="Affected Users"
            )

            # Force password reset for affected users
            for user in affected_users[:10]:
                phantom.act(
                    "reset password",
                    parameters=[{"username": user.get("user")}],
                    assets=["active_directory"],
                    name="reset_affected_user_password"
                )

    # Close with resolution
    finalize_investigation(container=container)


@phantom.playbook_block()
def finalize_investigation(container):
    """Finalize the phishing investigation."""
    phantom.add_note(
        container=container,
        content="Phishing response playbook completed. All IOCs blocked, affected users identified.",
        note_type="general",
        title="Investigation Complete"
    )
    phantom.set_status(container=container, status="closed")
    phantom.debug("Phishing Response Playbook completed")
