=========================================
WordPress Discovery and Enumeration
CATEGORY: Vulnerability Analysis
PUBLISH DATE: 2026-07-02
=========================================

SYNOPSIS:
A comprehensive review of WordPress footprinting, active enumeration, authentication abuse, and plugin vulnerability vectors.

INTEGRATIONS & STACKS:
WordPress, WPScan, LFI, RCE, Security Assessment

# Wordpress Discovery and Enumeration

## 1. Discovery & Manual Footprinting
Initial discovery relies on identifying application-specific files, directory structures, and HTML source code indicators to understand the host's posture:
* **Robots.txt Analysis**: Checking `/robots.txt` frequently exposes definitive hidden paths like `/wp-admin/` and `/wp-content/`. `[Ref-1]`
* **Source Code Inspection**: Using `curl` and `grep` allows testers to identify core version details, target themes, and active plugins directly from the page source. `[Ref-2]`
* **Directory Listing**: Exposed directory access (such as inside plugin folders) often reveals files like `readme.txt` that explicitly detail installed software versions. `[Ref-3]`
* **User Enumeration**: Leveraging distinct login error responses on `/wp-login.php` allows testers to differentiate between valid and invalid usernames. `[Ref-4]`

---

## 2. Automated Enumeration via WPScan
`WPScan` functions as a specialized automation tool to accelerate the fingerprinting process:
* **Passive & Active Checks**: The scanner leverages headers, RSS generators, and directory brute-forcing to flag misconfigurations and unpatched vulnerabilities. `[Ref-5]`
* **Database Integration**: Supplying a WPVulnDB API token (`--api-token`) imports proof-of-concept links and active vulnerability reports. `[Ref-6]`
* **Operational Scope**: Automated scans streamline discovery but may occasionally miss components (such as specific plugins), underscoring the absolute necessity of pairing them with human verification.

### Target Intelligence Blueprint
The combined enumeration process yields a comprehensive tactical profile of the target environment before mounting an attack:

| Vector Component | Discovered Asset / Vulnerability Details | Contextual Vector |
| :--- | :--- | :--- |
| **Core Software** | WordPress Core version 5.8 (Vulnerable to REST API Data Exposure). | Core Fingerprint |
| **Active Theme** | Transport Gravity (identified via automation as a child theme of Business Gravity). | Theme Fingerprint |
| **Mail-Masta Plugin** | Version 1.0.0; explicitly vulnerable to Local File Inclusion (LFI) and SQL Injection. | Public Vulnerability `[Ref-7]` |
| **wpDiscuz Plugin** | Version 7.0.4; highly critical due to an Unauthenticated Remote Code Execution (RCE) flaw. | Public Vulnerability `[Ref-7]` |
| **Validated Users** | Confirmed valid usernames: `admin` and `john`. | Target User List |
| **Misconfigurations** | Global directory listing is enabled; XML-RPC is active (susceptible to brute-force attacks). | System Flaw `[Ref-7]` |

---

## 3. Authentication Abuse (Login Brute-Forcing)
When valid usernames are successfully enumerated, automated brute-force methods are deployed to breach the admin barrier:
* **XML-RPC vs. Standard Login**: `WPScan` executes brute-force attacks via two main routes: standard `/wp-login.php` or the API endpoint `/xmlrpc.php`.
* **Performance Edge**: The `xmlrpc` method is preferred because it handles multiple authentication verification attempts within a single HTTP request, minimizing network overhead.
* **Exploitation Success**: Running `wpscan --password-attack xmlrpc` against user `john` successfully cracked the password `firebird1` using the `rockyou.txt` wordlist. `[Ref-8]`

---

## 4. Achieving Remote Code Execution (RCE)
Once administrator-level permissions are acquired, testers leverage multiple paths to inject code and control the underlying operating system:

### Internal Feature Exploitation (Theme Editor)
* **PHP Source Editing**: Administrators can natively modify source code using the internal theme editor. 
* **Operational Discretion**: Attackers deliberately choose an *inactive* theme (such as `Twenty Nineteen`) rather than the active theme (`Transport Gravity`) to avoid breaking the customer's live storefront website.
* **Web Shell Injection**: Inserting a minimal payload like `system(\$_GET);` into an uncommon theme file (such as `404.php`) permits the execution of system commands through direct URL queries. `[Ref-9]`

### Automation & Framework Tools
* **Metasploit Integration**: The `exploit/unix/webapp/wp_admin_shell_upload` module completely automates the entry sequence. It signs into the panel using the cracked credentials, uploads a custom malicious plugin, launches a PHP Meterpreter reverse shell, and returns low-privilege `www-data` system access. `[Ref-10]`

---

## 5. Third-Party Plugin Exploitation
Statistical historical analysis shows that **89% of all documented WordPress vulnerabilities** sit entirely within third-party plugins, rather than themes (7%) or the stable WordPress core engine (4%). This module highlights the real-world exploitation of two specific unpatched legacy components:

* **Mail-Masta (v1.0.0)**: Contains a devastating Local File Inclusion (LFI) flaw in its `pl` parameter because it lacks input validation. Passing `/etc/passwd` to this parameter allows an unauthenticated external attacker to instantly leak critical Linux server configuration files. `[Ref-7]`
* **wpDiscuz (v7.0.4)**: Features a high-severity file-upload mime-type bypass flaw (CVE-2020-24186). Though designed to only accept image file extensions for comments, an unauthenticated user can completely trick the checker into accepting an uploaded `.php` web shell, establishing immediate interactive command control over the web server. `[Ref-7]`

---

## 6. Professional Clean-Up & Artifact Documentation
Automated tools often leave highly dangerous web shell remnants in publicly accessible directories (such as `/wp-content/plugins/` or `/wp-content/uploads/`). To maintain proper operational security, penetration testing teams must completely delete these files post-assessment and list them inside a dedicated report appendix detailing:
* Exact **exploited systems** (including IP addresses and exploitation pathways).
* **Compromised credentials** (including compromised usernames and user privilege ranks).
* Complete list of **created file artifacts** and structural **system changes**. `[Ref-11]`

---

## MITRE ATT&CK® Reference Index
* `[Ref-1]` **T1593**: [Reconnaissance - Search Open Technical Databases](https://attack.mitre.org/techniques/T1593/)
* `[Ref-2]` **T1518**: [Discovery - Software Discovery](https://attack.mitre.org/techniques/T1518/)
* `[Ref-3]` **T1083**: [Discovery - File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
* `[Ref-4]` **T1087**: [Discovery - Account Discovery](https://attack.mitre.org/techniques/T1087)
* `[Ref-5]` **T1082**: [Discovery - System Information Discovery](https://attack.mitre.org/techniques/T1082)
* `[Ref-6]` **T1593.003**: [Reconnaissance - Search Open CVE Vulnerability Databases](https://attack.mitre.org/techniques/T1593/003/)
* `[Ref-7]` **T1190**: [Initial Access - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
* `[Ref-8]` **T1110**: [Credential Access - Brute Force](https://attack.mitre.org/techniques/T1110)
* `[Ref-9]` **T1505.003**: [Persistence / Defense Evasion - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
* `[Ref-10]` **T1059**: [Execution - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)
* `[Ref-11]` **T1070**: [Defense Evasion - Indicator Removal](https://attack.mitre.org/techniques/T1070)
