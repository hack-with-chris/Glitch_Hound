"""Plain-language impact guidance for findings produced by the scanners."""


def _entry(what, why, attack, impact, data, money, response, fixes):
    return {
        "what": what,
        "why": why,
        "attack": attack,
        "impact": impact,
        "data": data,
        "money": money,
        "response": response,
        "fixes": fixes,
    }


PORT_IMPACT = {
    21: _entry(
        "FTP transfers files, often without encryption.",
        "It is exposed so anyone who can reach the host can try to log in or read traffic.",
        "Credential sniffing or anonymous file theft.",
        "An attacker may copy, replace, or delete files and use stolen credentials elsewhere.",
        "Files, usernames, passwords, backups, and personal documents.",
        "Planning estimate: about INR 500-INR 5,000 for cleanup; more if confidential data is exposed.",
        "Disable the service, rotate FTP passwords, inspect file access logs, and restore changed files from a clean backup.",
        ["Disable FTP and use SFTP or FTPS.", "Require strong unique passwords and limit access by firewall."],
    ),
    22: _entry(
        "SSH provides encrypted remote administration.",
        "An internet-facing login is a common target for automated password guessing.",
        "Brute-force login or abuse of a stolen account.",
        "A successful login can give an attacker control of the server and its files.",
        "Server files, application secrets, logs, databases, and user records.",
        "Planning estimate: about INR 500-INR 10,000 for account recovery and server review.",
        "Block the source, disable affected accounts, rotate keys and secrets, and check login and process logs.",
        ["Use SSH keys and MFA; disable password login.", "Allow SSH only from a VPN or approved IP addresses."],
    ),
    23: _entry(
        "Telnet is remote login with no useful encryption.",
        "Passwords and commands can be read by someone watching the network.",
        "Cleartext credential interception and remote takeover.",
        "An attacker may steal a login and alter the device or server.",
        "Usernames, passwords, commands, configuration, and network details.",
        "Planning estimate: about INR 500-INR 10,000 for credential reset and recovery.",
        "Disconnect Telnet, change exposed passwords, review commands and logins, and check for new accounts.",
        ["Disable Telnet completely.", "Use SSH with MFA and firewall restrictions."],
    ),
    25: _entry(
        "SMTP sends email between mail servers.",
        "A poorly restricted mail service can be used by outsiders to send messages.",
        "Open-relay spam, phishing, or mail account abuse.",
        "Your domain reputation can fall and customers may receive convincing scams.",
        "Email addresses, message content, and possibly mailbox credentials.",
        "Planning estimate: about INR 200-INR 5,000 for cleanup, reputation repair, and notifications.",
        "Close the relay, reset mail credentials, review sent-mail logs, and notify recipients of malicious messages.",
        ["Require authentication and restrict relay destinations.", "Use SPF, DKIM, and DMARC."],
    ),
    80: _entry(
        "HTTP sends website traffic without encryption.",
        "Anyone controlling the network path may read or change the traffic.",
        "Traffic interception, session theft, or page tampering.",
        "Visitors can be redirected, shown fake content, or have sessions stolen.",
        "Passwords, session cookies, forms, and personal information.",
        "Planning estimate: about INR 200-INR 5,000 for certificate setup, investigation, and user resets.",
        "Force HTTPS, invalidate sessions, rotate exposed credentials, and review web and proxy logs.",
        ["Redirect every HTTP request to HTTPS.", "Enable HSTS after confirming HTTPS works everywhere."],
    ),
    110: _entry(
        "POP3 downloads email and may be unencrypted.",
        "Credentials and messages can be read on the network when TLS is absent.",
        "Mailbox credential interception.",
        "Attackers may read messages or use the mailbox for password resets and fraud.",
        "Email, attachments, contacts, and mailbox passwords.",
        "Planning estimate: about INR 200-INR 5,000 for account recovery and notifications.",
        "Disable cleartext access, reset mailbox passwords, revoke sessions, and inspect mailbox rules.",
        ["Use POP3S on port 995 with TLS.", "Require MFA and monitor unusual mailbox access."],
    ),
    143: _entry(
        "IMAP synchronizes email and may be unencrypted.",
        "Credentials and messages can be read on the network when TLS is absent.",
        "Mailbox credential interception.",
        "Attackers may read messages, set forwarding rules, or reset other accounts.",
        "Email, attachments, contacts, and mailbox passwords.",
        "Planning estimate: about INR 200-INR 5,000 for account recovery and notifications.",
        "Disable cleartext access, reset mailbox passwords, remove unknown forwarding rules, and review access logs.",
        ["Use IMAPS on port 993 with TLS.", "Require MFA and monitor unusual mailbox access."],
    ),
    139: _entry(
        "NetBIOS supports legacy Windows file and printer sharing.",
        "It exposes old network discovery and sharing features to attackers.",
        "Information leakage or SMB-based compromise.",
        "An attacker may discover machines and spread through shared folders.",
        "Hostnames, usernames, shared files, and domain information.",
        "Planning estimate: about INR 1,000-INR 25,000 for containment and workstation review.",
        "Block the port, isolate affected devices, reset credentials, and check shares and endpoint alerts.",
        ["Block it from the internet.", "Disable NetBIOS where it is not required and limit sharing to the LAN."],
    ),
    445: _entry(
        "SMB provides Windows file and printer sharing.",
        "An exposed SMB service is frequently attacked and can spread ransomware.",
        "Ransomware propagation or unauthorized file access.",
        "Files can be encrypted, stolen, or used to move to other computers.",
        "Shared documents, backups, credentials, and business records.",
        "Planning estimate: about INR 1,000-INR 50,000+ depending on downtime and data loss.",
        "Disconnect the host from the network, preserve evidence, contact incident response, and restore only from verified backups.",
        ["Block SMB from the internet.", "Patch Windows, require strong authentication, and restrict shares."],
    ),
    1433: _entry("MSSQL is a database service.", "A public database login can be guessed or exploited.", "Direct database compromise.", "An attacker may read, change, or delete application data.", "Customer records, payments, credentials, and business data.", "Planning estimate: about INR 1,000-INR 50,000+ for investigation and recovery.", "Block access, rotate database credentials, preserve logs, and assess whether records were read or changed.", ["Keep it on a private network.", "Use least-privilege accounts, MFA through a gateway, and regular patching."]),
    3306: _entry("MySQL or MariaDB is a database service.", "A public database login can be guessed or exploited.", "Direct database compromise.", "An attacker may read, change, or delete application data.", "Customer records, payments, credentials, and business data.", "Planning estimate: about INR 1,000-INR 50,000+ for investigation and recovery.", "Block access, rotate database credentials, preserve logs, and assess whether records were read or changed.", ["Keep it on a private network.", "Use least-privilege accounts and regular patching."]),
    3389: _entry("RDP provides Windows remote desktop access.", "Internet-facing RDP is a common ransomware entry point.", "Brute-force login or stolen-credential takeover.", "An attacker may control the computer, install ransomware, or steal files.", "Local files, saved passwords, business data, and backups.", "Planning estimate: about INR 1,000-INR 50,000+ depending on downtime and recovery.", "Isolate the computer, disable the account, preserve evidence, rotate credentials, and check for persistence.", ["Put RDP behind a VPN.", "Enable MFA, lockout protection, patching, and source-IP restrictions."]),
    5432: _entry("PostgreSQL is a database service.", "A public database login can be guessed or exploited.", "Direct database compromise.", "An attacker may read, change, or delete application data.", "Customer records, payments, credentials, and business data.", "Planning estimate: about INR 1,000-INR 50,000+ for investigation and recovery.", "Block access, rotate database credentials, preserve logs, and assess whether records were read or changed.", ["Keep it on a private network.", "Use least-privilege accounts and regular patching."]),
    5900: _entry("VNC provides remote desktop screen sharing.", "Weakly protected VNC can expose interactive control of a computer.", "Unauthorized remote desktop takeover.", "An attacker may watch activity, install software, or steal files.", "Screen contents, documents, passwords, and clipboard data.", "Planning estimate: about INR 500-INR 25,000 for containment and recovery.", "Disconnect the host, disable VNC, reset credentials, and review processes and login history.", ["Require strong authentication.", "Expose it only through a VPN or SSH tunnel." ]),
    6379: _entry("Redis stores application data in memory.", "An unprotected Redis service can allow direct data access or commands.", "Data theft or remote code execution.", "An attacker may read secrets or use the server to attack other systems.", "Session data, tokens, cache contents, and application secrets.", "Planning estimate: about INR 1,000-INR 25,000 for secret rotation and server review.", "Block access, rotate all stored secrets, inspect commands and persistence, and rebuild if integrity is uncertain.", ["Enable authentication and bind to localhost/private interfaces.", "Firewall the port and keep Redis updated."]),
    27017: _entry("MongoDB stores application documents.", "An unprotected database can be queried directly from the internet.", "Unauthenticated database access or data theft.", "An attacker may copy, change, or delete collections.", "Customer records, credentials, tokens, and application data.", "Planning estimate: about INR 1,000-INR 50,000+ depending on records and downtime.", "Block access, preserve database logs, rotate secrets, and assess exposed collections before restoring data.", ["Enable authentication and bind to private interfaces.", "Firewall the port and use least-privilege accounts."]),
}

GENERIC_PORT_IMPACT = _entry("An uncommon service is listening.", "The service purpose and security settings are not known from a port check alone.", "Targeted attack against the service or weak credentials.", "Unneeded exposure can provide an entry point or reveal information.", "Depends on the service; possibly accounts, files, or application data.", "Planning estimate: INR 200-INR 10,000 for review and hardening; actual cost depends on the service.", "Identify the service owner, restrict access, review logs, and investigate anything unexpected.", ["Close the port if it is not needed.", "Patch the service and restrict it to trusted networks."])


def port_impact(port):
    return PORT_IMPACT.get(port, GENERIC_PORT_IMPACT)


def web_impact(kind, subject=""):
    if kind == "header":
        mapping = {
            "Strict-Transport-Security": ("transport downgrade or cookie theft", "A browser can be tricked into using unsafe HTTP."),
            "Content-Security-Policy": ("XSS and script injection", "The browser has fewer rules limiting untrusted scripts."),
            "X-Content-Type-Options": ("MIME-sniffing content injection", "A browser may interpret an uploaded file as executable content."),
            "X-Frame-Options": ("clickjacking", "Another site may hide this page inside a misleading frame."),
            "Referrer-Policy": ("URL and data leakage", "Full URLs may be sent to another site in the Referer header."),
            "Permissions-Policy": ("unwanted camera, microphone, or location access", "Embedded content may request browser features that are not needed."),
        }
        attack, why = mapping.get(subject, ("web attacks", "A recommended browser security control is missing."))
        return _entry("A browser security header is missing.", why, attack, "Attackers get more opportunity to steal sessions, inject content, or trick visitors.", "Session cookies, form data, page content, and sometimes device permissions.", "Planning estimate: INR 200-INR 10,000 for code changes, review, and possible user notification.", "Add the header, review recent web logs and sessions, and reset sessions if misuse is suspected.", [f"Configure {subject} at the web server or application.", "Test the policy on a staging site before enforcing it everywhere."])
    if kind == "cookie":
        return _entry("A login cookie is missing a security flag.", "Browsers may send or expose the session token in unsafe situations.", "Session theft or account takeover.", "An attacker who gets the cookie may act as the user without knowing the password.", "Login sessions, account details, and data visible to that user.", "Planning estimate: INR 200-INR 10,000 for code changes, session invalidation, and review.", "Invalidate active sessions, review account activity, and reset credentials for affected users.", ["Set Secure and HttpOnly on session cookies.", "Use SameSite protection and short session lifetimes."])
    if kind == "path":
        lower = subject.lower()
        if ".env" in lower or ".git" in lower or "config" in lower:
            return _entry("A configuration or source-control file is publicly reachable.", "Private files were placed under the website's public folder or are not blocked.", "Credential and source-code disclosure.", "Attackers may use leaked secrets to log in to databases, mail, or cloud services.", "API keys, passwords, source code, database settings, and personal data.", "Planning estimate: INR 500-INR 25,000+ for secret rotation, investigation, and possible notification.", "Remove the file, revoke every exposed secret, preserve access logs, and check for unauthorized access.", ["Keep secrets outside the web root.", "Block dotfiles and backup files at the server and deployment pipeline."])
        return _entry("A sensitive or administrative path is publicly reachable.", "The path was not restricted to trusted users or networks.", "Information disclosure or admin-panel brute force.", "Attackers may learn system details or find a login surface to attack.", "Usernames, server details, logs, files, and possibly account data.", "Planning estimate: INR 200-INR 10,000 for access control, investigation, and cleanup.", "Restrict the path, review requests and login logs, and reset credentials if the path included authentication.", ["Remove unused paths and backups.", "Require authentication, MFA, and VPN or IP restrictions for admin areas."])
    if kind == "directory":
        return _entry("The server lists files in a directory.", "Directory browsing is enabled instead of returning a controlled page.", "File and directory enumeration.", "Attackers can map the site and download forgotten files or backups.", "Filenames, documents, source code, logs, and backup data.", "Planning estimate: INR 200-INR 10,000 for cleanup and investigation.", "Disable listing, remove exposed files, and review access logs for downloads.", ["Disable autoindexing.", "Keep backups and logs outside the public web root."])
    if kind == "banner":
        return _entry("The server reveals product or version information.", "Version details help attackers match the target to known vulnerabilities.", "Targeted exploitation of known CVEs.", "An attacker may focus on weaknesses specific to the disclosed software version.", "Usually no direct data, but it can expose the route to application and server data.", "Planning estimate: INR 200-INR 5,000 for patching and review.", "Patch the disclosed software, review exploit indicators in logs, and hide the version after patching.", ["Keep the server and framework patched.", "Suppress detailed Server and X-Powered-By headers."])
    if kind == "ssl_expiring":
        return _entry("The TLS certificate expires soon.", "A certificate that expires can cause warnings that users learn to ignore.", "Phishing or man-in-the-middle opportunity.", "Visitors may lose trust or click through a dangerous certificate warning.", "Passwords, session cookies, and submitted personal data.", "Planning estimate: INR 100-INR 2,000 for renewal and incident review.", "Renew immediately, check for certificate warnings, and review unusual traffic during the warning period.", ["Automate certificate renewal.", "Monitor expiry and force HTTPS." ])
    if kind == "ssl_invalid":
        return _entry("The TLS certificate could not be verified.", "The connection may be unencrypted, expired, mismatched, or otherwise untrusted.", "Man-in-the-middle interception.", "An attacker may read or alter traffic between visitors and the site.", "Passwords, session cookies, forms, and personal data.", "Planning estimate: INR 200-INR 5,000 for certificate setup and credential resets.", "Fix the certificate, invalidate sessions, rotate credentials, and inspect logs for suspicious access.", ["Install a valid certificate for the correct hostname.", "Redirect HTTP to HTTPS and enable HSTS after testing."])
    return GENERIC_PORT_IMPACT


def vuln_findings(results):
    """Return one shared, serializable impact record for every failing finding."""
    findings = []
    for item in results.get("headers", {}).get("missing", []):
        findings.append({"title": f"Missing header: {item['header']}", "details": web_impact("header", item["header"])})
    ssl_info = results.get("ssl", {})
    if "ssl" in results and not ssl_info.get("has_valid_cert"):
        findings.append({"title": "Invalid or unverifiable TLS certificate", "details": web_impact("ssl_invalid")})
    elif "ssl" in results and (ssl_info.get("days_until_expiry") or 999) < 14:
        findings.append({"title": "TLS certificate expires soon", "details": web_impact("ssl_expiring")})
    for cookie in results.get("cookie_issues", []):
        for flag in cookie.get("missing_flags", []):
            findings.append({"title": f"Cookie {cookie.get('cookie', '')}: missing {flag}", "details": web_impact("cookie", flag)})
    for path in results.get("exposed_paths", []):
        findings.append({"title": f"Exposed path: {path.get('path', '')}", "details": web_impact("path", path.get("path", ""))})
    if results.get("directory_listing_enabled"):
        findings.append({"title": "Directory listing enabled", "details": web_impact("directory")})
    if results.get("banner", {}).get("discloses_version"):
        findings.append({"title": "Server version disclosed", "details": web_impact("banner")})
    return findings


def port_findings(results):
    return [{"title": f"Open port {p.get('port')} ({p.get('service', 'unknown')})", "details": port_impact(p.get("port"))}
             for p in results.get("open_ports", [])]