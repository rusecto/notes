=========================================
Active Directory Reconnaissance & Hardening
CATEGORY: Active Directory
PUBLISH DATE: 2026-07-02
READ TIME: 8 min read
=========================================

SYNOPSIS:
A detailed manual on unauthenticated AD directory harvesting, response spoofing attacks (LLMNR/NBT-NS), post-exploitation relays, and domain-wide defensive remediation/hardening.

INTEGRATIONS & STACKS:
Active Directory, Group Policy, Responder, LLMNR, NTLM Relay, Hardening

=========================================
FULL DOCUMENTATION CONTENT:
=========================================

# Active Directory Reconnaissance & Hardening

## 1. Unauthenticated Reconnaissance & Enumeration
Legacy holdovers and backward-compatibility features often act as open directory lookup tools, allowing unauthenticated attackers or external operators to extract critical asset landscapes.

### Pre-Windows 2000 Compatible Access Group
* **Legacy Compatibility**: This built-in security principal was introduced to preserve backward compatibility for Windows NT systems shifting to hierarchical AD object trees. `[Ref-1]`
* **Permissions Overreach**: By default, this group inherits broad top-down special permissions (`Read all properties`) over Descendant User, Group, and Computer objects across the entire hierarchy of Organizational Units (OUs). `[Ref-2]`
* **In-Place Upgrade Risk**: While modern deployments restrict this group, domain upgrades (e.g., from Server 2003/2008 up to modern functional levels) regularly pull legacy memberships forward without a cleanup, leaving the `Everyone` group or `Anonymous Logon` nested inside. `[Ref-1]`

### SMB Null Sessions & RID Brute Forcing
* **Information Disclosure**: Misconfigured domain settings allow an attacker to launch null sessions via tools like `NetExec` (`netexec smb <IP> --users` and `--pass-pol`) without valid domain credentials. `[Ref-2]`
* **Password Spray Blueprinting**: This leak returns a complete list of valid domain users alongside the domain's password policy (minimum length, history, and account lockout thresholds). Attackers can then design a high-probability password spraying strategy that intentionally avoids triggering lockout counts. `[Ref-3]`
* **Relative Identifier (RID) Harvesting**: If the GPO setting *Network access: Allow anonymous SID/Name translation* is left enabled, an attacker can programmatically brute-force RID values starting at 500 (Administrator) to map exact username strings to underlying SIDs using local `LookupSids` queries. `[Ref-2]`

### LDAP Anonymous Binds
* **Directory Harvesting**: Setting the directory-level attribute `dSHeuristics` to `0000002` permits unauthenticated users to establish anonymous LDAP base binds. `[Ref-2]`
* **Attribute Leakage**: Attackers use tools like `ldapsearch` to query the entire Directory Service tree, capturing sensitive organizational info, group structures, and exposed description attributes that may contain plaintext passwords. `[Ref-2]`

---

## 2. Initial Access Vectors: Response Spoofing Attacks
When standard DNS name queries fail to resolve, Windows operating systems fallback to legacy multi-cast protocol broadcasts over local network segments, creating a significant spoofing attack surface.

* **LLMNR & NBT-NS Poisoning**: Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) send out unauthenticated UDP local broadcasts when a host tries to locate a resource (e.g., a mistyped share name like `\\\\fileservr`). `[Ref-4]`
* **Credential Harvest**: An attacker running a rogue listener like `Responder` on the segment will spoof the missing resource's identity. The client host, believing it is talking to a valid server, will transmit the user's NTLMv1/NTLMv2 password hash to authenticate. `[Ref-5]`
* **Offline Cracking & Relaying**: These captured hashes are either cracked offline via GPU arrays or directly targeted for NTLM relaying attacks to execute code against separate target systems. `[Ref-5]`
* **mDNS & IPv6 Spoofing Surface**: Multicast DNS (mDNS) over UDP port 5353 remains an active target since it is required for modern application auto-discovery (e.g., Chrome, AirPlay). Concurrently, Windows naturally prioritizes IPv6 over IPv4; if DHCPv6 is unconfigured but active, an attacker can spoof DHCPv6 replies to assign a rogue IPv6 DNS server address, intercepting and inspecting all upstream traffic. `[Ref-4]`

---

## 3. Post-Spoofing Exploitation & Weak AD Defenses
If an attacker successfully positions themselves to capture or intercept authentication traffic, secondary misconfigurations determine whether they achieve full domain compromise.

* **NTLM Relaying**: Attackers route valid intercept requests directly to unhardened services. Relaying a privileged account (e.g., Domain Admin) to an LDAP interface allows an attacker to alter group memberships or assign replication rights to perform a data-dumping `DCSync` attack. `[Ref-6]`
* **Default MachineAccountQuota Abuse**: By default, the active `ms-DS-MachineAccountQuota` attribute allows any standard domain user to join up to 10 computers to the domain. Attackers combine an NTLM relay string with this quota to generate custom computer accounts, bypassing the need to crack password hashes offline to establish a domain foothold. `[Ref-2]`
* **Disabled SMB Signing**: Sever Message Block (SMB) Signing acts as a cryptographic packet validator. If it is disabled or supported but not required, an attacker can safely intercept a session negotiation and relay the authentication token to a target machine to drop a web shell or gain an interactive `SYSTEM` shell. `[Ref-6]`
* **ASREPRoasting Vulnerabilities**: If an account has the attribute *Do not require Kerberos preauthentication* checked, any user can request a Kerberos Ticket Granting Ticket (TGT) on their behalf. The authentication service reply (AS-REP) contains data encrypted with the account password hash, which can be extracted and cracked offline. `[Ref-7]`
* **Domain Controller Coercion**: Tools like `PetitPotam` abuse the Encrypting File System Remote Protocol (EFSRPC) to force a Domain Controller to authenticate to an attacker's listener. If Print Spooler services (`MS-RPRN`) are left running on a Domain Controller, the `PrinterBug` technique can similarly be leveraged to coerce authentication and force direct machine-account relay loops. `[Ref-6]`

---

## 4. Validation, Remediation, & Hardening Procedures

### Unauthenticated Enumeration Remedies
* **Pre-Windows 2000 Group Purge**: Remove the `Everyone` and `Anonymous Logon` groups from the Pre-Windows 2000 Compatible Access security group via `Active Directory Users and Computers` (ADUC).
* **SMB Null Session Disablement**: Modify the Default Domain Controllers GPO to set *Network access: Let Everyone permissions apply to anonymous users* to **Disabled**.
* **LDAP Anonymous Bind Closure**: Clear the `dSHeuristics` attribute within the Directory Service configuration container using `ADSI Edit` (`adsiedit.msc`), or automate via PowerShell:
  ```powershell
  $Dcname = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
  $AnonADSI = [ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$Dcname"
  $AnonADSI.Properties["dSHeuristics"].Clear()
  $AnonADSI.SetInfo()
  ```
* **RID Brute-Force Remediation**: Set *Network access: Allow anonymous SID/Name translation* to **Disabled** in Group Policy, or restrict the local registry value `RestrictAnonymous` under `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa` to `1` or `2`.

### Response Spoofing & Relaying Defenses
* **Disable LLMNR via GPO**: Create a dedicated GPO linked to target OUs. Navigate to `Computer Configuration -> Administrative Templates -> Network -> DNS Client` and set *Turn off multicast name resolution* to **Enabled**.
* **Disable NetBIOS (NBT-NS)**: Since GPO lacks a default global switch for NetBIOS, deploy a Startup Script policy using this registry-targeted PowerShell logic to sweep all network interface indices:
  ```powershell
  $regkey = "HKLM:\\SYSTEM\\CurrentControlSet\\services\\NetBT\\Parameters\\Interfaces"
  Get-ChildItem $regkey | foreach { Set-ItemProperty -Path "$regkey\\$($_.pschildname)" -Name NetbiosOptions -Value 2 }
  ```
* **Enforce SMB Signing**: Configure Group Policy under `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`. Set *Microsoft network server: Digitally sign communications (always)* to **Enabled**. 
* **Enforce LDAP Signing & Channel Binding**: Set *Domain controller: LDAP server signing requirements* to **Require Signing**. Additionally, set *Domain controller: LDAP server channel binding token requirements* to **Always** to secure LDAPS over port 636 against relay chains.
* **Zero-Out MachineAccountQuota**: Restructure the default computer addition permissions by lowering the quota limit from `10` down to `0`:
  ```powershell
  Set-ADObject -Identity ((Get-ADDomain).distinguishedname) -Replace @{"ms-DS-MachineAccountQuota"="0"}
  ```
* **Disable Print Spooler on DCs**: Prevent RPC-based account coercion vectors by shutting down and disabling the print spooler service on all active domain controllers:
  ```powershell
  Stop-Service spooler -Force
  Set-Service spooler -StartupType Disabled
  ```

---

## MITRE ATT&CK® Reference Index
* `[Ref-1]` **T1592**: [Reconnaissance - Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/)
* `[Ref-2]` **T1083**: [Discovery - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
* `[Ref-3]` **T1589**: [Reconnaissance - Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)
* `[Ref-4]` **T1557**: [Credential Access - Adversary-in-the-Middle (Man-in-the-Middle)](https://attack.mitre.org/techniques/T1557/)
* `[Ref-5]` **T1557.001**: [Credential Access - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
