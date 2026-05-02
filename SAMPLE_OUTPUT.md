# TawasolPay — AI Cyber Risk Assistant
## Top 5 Prioritized Risks
_Generated 2026-05-02 09:53 UTC_

### Pipeline status
- **CISA KEV catalog:** loaded from cache (1587 entries)
- **NIST 800-53 index:** keyword fallback (sentence-transformers missing: The sentence_transformers python package is not installed. Please install it with `pip install sentence_transformers`; 19 chunks); network unavailable; using bundled NIST control subset (19 controls). For full coverage, ensure the host has network access to NIST.

### Data ingest summary
- Assets ingested: **60** (internet-exposed: 21)
- Open vulnerabilities: **114**
- Threat-intel records: **40** (matched to our vulns: 45)
- Vulnerabilities in CISA KEV: **29** (ransomware-tagged: 21)
- Business services: **20**

---

## #1 — load-balancer-prod-02  `CVE-2023-4966`
**Risk score: 82.4**  •  CVSS 9.4  •  Citrix ADC Session Token Leak (CitrixBleed)

> Ranks #1 because it combines technical severity (CVSS 9.4) with business impact. The load-balancer-prod-02 is internet-exposed. It is targeted by IronVeil's 'CitrixBleed Exploitation' campaign with ransomware association. Compromise impacts Payment Processing (revenue impact: Critical). EDR is not installed, removing a key compensating control.

**Asset & exposure**
- Asset: `A-1022` (Load Balancer, Production)
- Owner team: Network Team
- Internet-exposed: Yes
- EDR installed: No
- Vulnerability open for: 180 days
- Patch available: Yes
- CISA KEV: **listed** (ransomware-tagged: Yes)

**Business service at risk**
- Service: **Payment Processing**
- Revenue impact: Critical
- Customer-facing: Yes
- Compliance scope: PCI DSS

**Matched threat intel**
- Actor: **IronVeil**
- Campaign: **CitrixBleed Exploitation**
- Ransomware-associated: Yes
- Region / sector: Global / Financial Services
- Summary: _IronVeil group actively exploiting Citrix NetScaler CitrixBleed CVE-2023-4966 to harvest session tokens from load balancers protecting financial portals. Tokens used to bypass MFA._

**Recommended NIST 800-53 control: `SI-2` — Flaw Remediation**

NIST SI-2 (Flaw Remediation): Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c.

<details><summary>Show full NIST control text (verbatim)</summary>

a. Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c. Install security-relevant software and firmware updates within [Assignment: organization-defined time period] of the release of the updates; and d. Incorporate flaw remediation into the organizational configuration management process.

_Discussion:_ The need to remediate system flaws applies to all types of software and firmware. Organizations identify systems affected by software flaws, including potential vulnerabilities resulting from those flaws, and report this information to designated organizational personnel with information security and privacy responsibilities. Security-relevant updates include patches, service packs, and malicious code signatures. Organizations also address flaws discovered during assessments, continuous monitoring, incident response activities, and system error handling. By incorporating flaw remediation into configuration management processes, required remediation actions can be tracked and verified.

</details>

<details><summary>Why this score (factor breakdown)</summary>

| Factor | Value | Contribution |
|---|---|---|
| Internet exposed | Yes | +12.0 |
| KEV: known ransomware use | Yes | +10.0 |
| CVSS base | 9.4 | +9.4 |
| Exploit available | Yes | +8.0 |
| TI campaign: ransomware-associated | Yes | +8.0 |
| In CISA KEV catalog | Yes | +6.0 |
| Business service revenue impact | Critical | +6.0 |
| Threat-intel campaign match | IronVeil / CitrixBleed Exploitation | +5.0 |
| TI targets our region/sector | Global / Financial Services | +4.0 |
| EDR not installed | Missing | +4.0 |
| Customer-facing service | Yes | +2.0 |
| Regulated compliance scope | PCI DSS | +2.0 |
| Asset criticality | High | +2.0 |
| Vuln open > 90 days | 180 | +2.0 |
| Production environment | Yes | +2.0 |

</details>

---

## #2 — load-balancer-prod-01  `CVE-2023-4966`
**Risk score: 82.4**  •  CVSS 9.4  •  Citrix ADC Session Token Leak (CitrixBleed)

> Ranks #2 because it combines technical severity (CVSS 9.4) with business impact. The load-balancer-prod-01 is internet-exposed. It is targeted by IronVeil's 'CitrixBleed Exploitation' campaign with ransomware association. Compromise impacts Customer Login (revenue impact: Critical). EDR is not installed, removing a key compensating control.

**Asset & exposure**
- Asset: `A-1021` (Load Balancer, Production)
- Owner team: Network Team
- Internet-exposed: Yes
- EDR installed: No
- Vulnerability open for: 180 days
- Patch available: Yes
- CISA KEV: **listed** (ransomware-tagged: Yes)

**Business service at risk**
- Service: **Customer Login**
- Revenue impact: Critical
- Customer-facing: Yes
- Compliance scope: GDPR

**Matched threat intel**
- Actor: **IronVeil**
- Campaign: **CitrixBleed Exploitation**
- Ransomware-associated: Yes
- Region / sector: Global / Financial Services
- Summary: _IronVeil group actively exploiting Citrix NetScaler CitrixBleed CVE-2023-4966 to harvest session tokens from load balancers protecting financial portals. Tokens used to bypass MFA._

**Recommended NIST 800-53 control: `SI-2` — Flaw Remediation**

NIST SI-2 (Flaw Remediation): Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c.

<details><summary>Show full NIST control text (verbatim)</summary>

a. Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c. Install security-relevant software and firmware updates within [Assignment: organization-defined time period] of the release of the updates; and d. Incorporate flaw remediation into the organizational configuration management process.

_Discussion:_ The need to remediate system flaws applies to all types of software and firmware. Organizations identify systems affected by software flaws, including potential vulnerabilities resulting from those flaws, and report this information to designated organizational personnel with information security and privacy responsibilities. Security-relevant updates include patches, service packs, and malicious code signatures. Organizations also address flaws discovered during assessments, continuous monitoring, incident response activities, and system error handling. By incorporating flaw remediation into configuration management processes, required remediation actions can be tracked and verified.

</details>

<details><summary>Why this score (factor breakdown)</summary>

| Factor | Value | Contribution |
|---|---|---|
| Internet exposed | Yes | +12.0 |
| KEV: known ransomware use | Yes | +10.0 |
| CVSS base | 9.4 | +9.4 |
| Exploit available | Yes | +8.0 |
| TI campaign: ransomware-associated | Yes | +8.0 |
| In CISA KEV catalog | Yes | +6.0 |
| Business service revenue impact | Critical | +6.0 |
| Threat-intel campaign match | IronVeil / CitrixBleed Exploitation | +5.0 |
| TI targets our region/sector | Global / Financial Services | +4.0 |
| EDR not installed | Missing | +4.0 |
| Customer-facing service | Yes | +2.0 |
| Regulated compliance scope | GDPR | +2.0 |
| Asset criticality | High | +2.0 |
| Vuln open > 90 days | 180 | +2.0 |
| Production environment | Yes | +2.0 |

</details>

---

## #3 — vpn-edge-02  `CVE-2024-55591`
**Risk score: 77.8**  •  CVSS 9.8  •  Fortinet FortiOS Authentication Bypass

> Ranks #3 because it combines technical severity (CVSS 9.8) with business impact. The vpn-edge-02 is internet-exposed. It is targeted by CrimsonJackal's 'Gateway Breaker' campaign with ransomware association. Compromise impacts Remote Access (revenue impact: High). EDR is not installed, removing a key compensating control.

**Asset & exposure**
- Asset: `A-1006` (VPN Gateway, Production)
- Owner team: Network Team
- Internet-exposed: Yes
- EDR installed: No
- Vulnerability open for: 14 days
- Patch available: Yes
- CISA KEV: **listed** (ransomware-tagged: Yes)

**Business service at risk**
- Service: **Remote Access**
- Revenue impact: High
- Customer-facing: No
- Compliance scope: ISO 27001

**Matched threat intel**
- Actor: **CrimsonJackal**
- Campaign: **Gateway Breaker**
- Ransomware-associated: Yes
- Region / sector: Middle East / Financial Services
- Summary: _Same CrimsonJackal campaign also exploiting Fortinet authentication bypass CVE-2024-55591 in parallel with CVE-2024-21762 for redundant access._

**Recommended NIST 800-53 control: `SI-2` — Flaw Remediation**

NIST SI-2 (Flaw Remediation): Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c.

<details><summary>Show full NIST control text (verbatim)</summary>

a. Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c. Install security-relevant software and firmware updates within [Assignment: organization-defined time period] of the release of the updates; and d. Incorporate flaw remediation into the organizational configuration management process.

_Discussion:_ The need to remediate system flaws applies to all types of software and firmware. Organizations identify systems affected by software flaws, including potential vulnerabilities resulting from those flaws, and report this information to designated organizational personnel with information security and privacy responsibilities. Security-relevant updates include patches, service packs, and malicious code signatures. Organizations also address flaws discovered during assessments, continuous monitoring, incident response activities, and system error handling. By incorporating flaw remediation into configuration management processes, required remediation actions can be tracked and verified.

</details>

<details><summary>Why this score (factor breakdown)</summary>

| Factor | Value | Contribution |
|---|---|---|
| Internet exposed | Yes | +12.0 |
| KEV: known ransomware use | Yes | +10.0 |
| CVSS base | 9.8 | +9.8 |
| Exploit available | Yes | +8.0 |
| TI campaign: ransomware-associated | Yes | +8.0 |
| In CISA KEV catalog | Yes | +6.0 |
| Threat-intel campaign match | CrimsonJackal / Gateway Breaker | +5.0 |
| TI targets our region/sector | Middle East / Financial Services | +4.0 |
| Asset criticality | Critical | +4.0 |
| EDR not installed | Missing | +4.0 |
| Business service revenue impact | High | +3.0 |
| Regulated compliance scope | ISO 27001 | +2.0 |
| Production environment | Yes | +2.0 |

</details>

---

## #4 — vpn-edge-01  `CVE-2024-55591`
**Risk score: 77.8**  •  CVSS 9.8  •  Fortinet FortiOS Authentication Bypass

> Ranks #4 because it combines technical severity (CVSS 9.8) with business impact. The vpn-edge-01 is internet-exposed. It is targeted by CrimsonJackal's 'Gateway Breaker' campaign with ransomware association. Compromise impacts Remote Access (revenue impact: High). EDR is not installed, removing a key compensating control.

**Asset & exposure**
- Asset: `A-1005` (VPN Gateway, Production)
- Owner team: Network Team
- Internet-exposed: Yes
- EDR installed: No
- Vulnerability open for: 14 days
- Patch available: Yes
- CISA KEV: **listed** (ransomware-tagged: Yes)

**Business service at risk**
- Service: **Remote Access**
- Revenue impact: High
- Customer-facing: No
- Compliance scope: ISO 27001

**Matched threat intel**
- Actor: **CrimsonJackal**
- Campaign: **Gateway Breaker**
- Ransomware-associated: Yes
- Region / sector: Middle East / Financial Services
- Summary: _Same CrimsonJackal campaign also exploiting Fortinet authentication bypass CVE-2024-55591 in parallel with CVE-2024-21762 for redundant access._

**Recommended NIST 800-53 control: `SI-2` — Flaw Remediation**

NIST SI-2 (Flaw Remediation): Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c.

<details><summary>Show full NIST control text (verbatim)</summary>

a. Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c. Install security-relevant software and firmware updates within [Assignment: organization-defined time period] of the release of the updates; and d. Incorporate flaw remediation into the organizational configuration management process.

_Discussion:_ The need to remediate system flaws applies to all types of software and firmware. Organizations identify systems affected by software flaws, including potential vulnerabilities resulting from those flaws, and report this information to designated organizational personnel with information security and privacy responsibilities. Security-relevant updates include patches, service packs, and malicious code signatures. Organizations also address flaws discovered during assessments, continuous monitoring, incident response activities, and system error handling. By incorporating flaw remediation into configuration management processes, required remediation actions can be tracked and verified.

</details>

<details><summary>Why this score (factor breakdown)</summary>

| Factor | Value | Contribution |
|---|---|---|
| Internet exposed | Yes | +12.0 |
| KEV: known ransomware use | Yes | +10.0 |
| CVSS base | 9.8 | +9.8 |
| Exploit available | Yes | +8.0 |
| TI campaign: ransomware-associated | Yes | +8.0 |
| In CISA KEV catalog | Yes | +6.0 |
| Threat-intel campaign match | CrimsonJackal / Gateway Breaker | +5.0 |
| TI targets our region/sector | Middle East / Financial Services | +4.0 |
| Asset criticality | Critical | +4.0 |
| EDR not installed | Missing | +4.0 |
| Business service revenue impact | High | +3.0 |
| Regulated compliance scope | ISO 27001 | +2.0 |
| Production environment | Yes | +2.0 |

</details>

---

## #5 — vpn-edge-01  `CVE-2024-21762`
**Risk score: 77.8**  •  CVSS 9.8  •  Fortinet SSL-VPN Heap Buffer Overflow RCE

> Ranks #5 because it combines technical severity (CVSS 9.8) with business impact. The vpn-edge-01 is internet-exposed. It is targeted by CrimsonJackal's 'Gateway Breaker' campaign with ransomware association. Compromise impacts Remote Access (revenue impact: High). EDR is not installed, removing a key compensating control.

**Asset & exposure**
- Asset: `A-1005` (VPN Gateway, Production)
- Owner team: Network Team
- Internet-exposed: Yes
- EDR installed: No
- Vulnerability open for: 27 days
- Patch available: Yes
- CISA KEV: **listed** (ransomware-tagged: Yes)

**Business service at risk**
- Service: **Remote Access**
- Revenue impact: High
- Customer-facing: No
- Compliance scope: ISO 27001

**Matched threat intel**
- Actor: **CrimsonJackal**
- Campaign: **Gateway Breaker**
- Ransomware-associated: Yes
- Region / sector: Middle East / Financial Services
- Summary: _Active exploitation of Fortinet SSL-VPN CVE-2024-21762 observed against financial services and fintech firms in the Gulf region. Initial access leads to internal lateral movement and ransomware staging._

**Recommended NIST 800-53 control: `SI-2` — Flaw Remediation**

NIST SI-2 (Flaw Remediation): Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c.

<details><summary>Show full NIST control text (verbatim)</summary>

a. Identify, report, and correct system flaws; b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; c. Install security-relevant software and firmware updates within [Assignment: organization-defined time period] of the release of the updates; and d. Incorporate flaw remediation into the organizational configuration management process.

_Discussion:_ The need to remediate system flaws applies to all types of software and firmware. Organizations identify systems affected by software flaws, including potential vulnerabilities resulting from those flaws, and report this information to designated organizational personnel with information security and privacy responsibilities. Security-relevant updates include patches, service packs, and malicious code signatures. Organizations also address flaws discovered during assessments, continuous monitoring, incident response activities, and system error handling. By incorporating flaw remediation into configuration management processes, required remediation actions can be tracked and verified.

</details>

<details><summary>Why this score (factor breakdown)</summary>

| Factor | Value | Contribution |
|---|---|---|
| Internet exposed | Yes | +12.0 |
| KEV: known ransomware use | Yes | +10.0 |
| CVSS base | 9.8 | +9.8 |
| Exploit available | Yes | +8.0 |
| TI campaign: ransomware-associated | Yes | +8.0 |
| In CISA KEV catalog | Yes | +6.0 |
| Threat-intel campaign match | CrimsonJackal / Gateway Breaker | +5.0 |
| TI targets our region/sector | Middle East / Financial Services | +4.0 |
| Asset criticality | Critical | +4.0 |
| EDR not installed | Missing | +4.0 |
| Business service revenue impact | High | +3.0 |
| Regulated compliance scope | ISO 27001 | +2.0 |
| Production environment | Yes | +2.0 |

</details>

---
