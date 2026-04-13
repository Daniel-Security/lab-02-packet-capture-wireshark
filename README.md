# Lab 02 — Packet Capture & Traffic Analysis

## Objective
Capture and analyze live network traffic using Wireshark to identify protocol behavior, 
recognize port scan signatures, and demonstrate the risk of unencrypted HTTP traffic — 
replicating what a SOC analyst does when investigating suspicious network activity.

## Skills Demonstrated
- Packet capture on a live network interface
- Protocol analysis (ICMP, TCP, HTTP, ARP)
- Identifying port scan signatures in packet data
- Recognizing cleartext credential and session data exposure over HTTP
- Wireshark display filters for traffic isolation
- Evidence collection and documentation (.pcapng)

## Tools Used
- **Kali Linux** — attack/capture machine
- **Wireshark 4.6.4** — packet capture and analysis
- **Nmap** — traffic generation (port scan)
- **Metasploitable 2** — target VM (IP: 10.0.2.3)
- **VirtualBox** — isolated NAT network (CyberLab)

## Environment
- Attacker/Capture: Kali Linux 2026.1 (10.0.2.15)
- Target: Metasploitable 2 (10.0.2.3)
- Network: Isolated NAT Network — no internet exposure

## Captures & Filters Used

| Filter | Purpose |
|--------|---------|
| `icmp` | Isolated ping request/reply pairs |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | Isolated SYN packets to visualize port scan signature |
| `http` | Isolated HTTP traffic to demonstrate plaintext exposure |

## Key Findings

### Finding 1 — ICMP Traffic (Ping)
Captured live ping traffic between Kali (10.0.2.15) and Metasploitable (10.0.2.3).
Observed alternating Echo Request and Echo Reply packets with incrementing sequence 
numbers — confirming host is alive and responsive.

### Finding 2 — Port Scan Signature (Nmap)
Ran Nmap service scan against target while capturing in Wireshark. Filtered to SYN-only 
packets using `tcp.flags.syn==1 && tcp.flags.ack==0` — revealed 1066 SYN packets sent 
to sequential ports in under 5 seconds. This pattern is a clear indicator of reconnaissance 
activity and would trigger an IDS alert on a real network.

### Finding 3 — HTTP Plaintext Exposure (Critical)
Made HTTP request to Metasploitable web server. Wireshark captured the full response 
in plaintext including:
- **Server version:** Apache/2.2.8 (Ubuntu) — exposed to any network observer
- **PHP version:** PHP/5.2.4-2ubuntu5.10 — exposed to any network observer  
- **Session cookie:** PHPSESSID visible in plaintext — susceptible to session hijacking
- **Page content:** Full HTML including sensitive comments visible in transit

**Risk:** Any user submitting credentials over HTTP would have their username and 
password captured in plaintext by anyone on the same network segment.

**Remediation:** Enforce HTTPS with TLS 1.2+, set Secure and HttpOnly flags on 
cookies, suppress server version headers.

## Summary
Traffic analysis confirmed three distinct security issues on the target: active host 
responsive to ICMP, all ports accessible with no firewall filtering, and web application 
transmitting sensitive data over unencrypted HTTP. In a real SOC environment the port 
scan signature alone would constitute an alert requiring immediate investigation.

## Screenshots
*Screenshots and capture file stored in /screenshots folder*

## References
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [CVE-2007-6750 Slowloris](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750)
- [OWASP Transport Layer Protection](https://owasp.org/www-project-transport-layer-protection-cheat-sheet/)
- [NIST SP 800-41 Firewall Guidelines](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final)
