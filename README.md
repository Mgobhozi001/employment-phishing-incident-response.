# 🛡️ SOC Case Study — Employment Phishing & Identity Harvesting (South Africa)

## Overview

This case study documents a real-world employment phishing attempt targeting a job seeker.  
The attacker impersonated a recruitment consultancy and attempted to harvest sensitive personal documents (ID, police clearance, ITC report) using social engineering and WhatsApp onboarding.

The investigation covers:

- Email header analysis
- Infrastructure attribution
- Social engineering indicators
- MITRE mapping
- Indicators of Compromise (IOCs)
- Detection engineering
- Incident response recommendations

No personal data was shared.

---

## Executive Summary

An unsolicited job offer email was received claiming to originate from a recruitment consultancy.  
The email requested highly sensitive documentation via WhatsApp under artificial urgency.

Header analysis confirmed the message originated from consumer Gmail infrastructure rather than a corporate mail system.  
Content analysis revealed multiple employment-scam indicators including pre-interview job offering, urgency pressure, and document harvesting.

The incident was classified as:

> **Employment Phishing with Identity Harvesting Intent**

---

## Business Impact

If successful, the attacker would likely have obtained:

- Government ID
- Credit profile (ITC)
- Qualifications
- Police clearance

This enables:

- Identity fraud  
- Loan / SIM swap fraud  
- Account takeover  
- Synthetic identity creation  

---

## Kill Chain Mapping

Framework used: MITRE ATT&CK

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence in This Incident |
|--------|-------------|----------------|--------------------------|
| Resource Development | T1585.002 | Establish Accounts: Email Accounts | Attacker created `attainingconsultancyportia@gmail.com` using free consumer Gmail to avoid corporate domain costs and traceability |
| Resource Development | T1586.002 | Compromise Accounts: Email Accounts | Attacker leveraged freerecruit.co.za job portal to identify and target active job seekers |
| Initial Access | T1566.001 | Phishing: Spearphishing via Service | Email subject included victim's full name scraped from freerecruit.co.za — targeted spearphish, not mass spam |
| Defense Evasion | T1036 | Masquerading | Impersonated legitimate recruitment consultancy "Attaining Consultancy" with no verifiable registration |
| Defense Evasion | T1656 | Impersonation | Posed as "Miss Portia Tshabalala" — recruiter persona with name inconsistency (signed as "Porta") suggesting template reuse |
| Defense Evasion | T1665 | Hide Infrastructure | Used Gmail infrastructure (mail-sor-f41.google.com / 209.85.220.41) — all authentication checks pass, hiding malicious intent behind trusted provider |
| Collection | T1119 | Automated Collection | Systematic document harvesting: ID, qualifications, police clearance, ITC report requested via WhatsApp |
| Collection | T1213 | Data from Information Repositories | CV data scraped from freerecruit.co.za to personalise the lure and increase legitimacy |
| Credential Access | T1528 | Steal Application Access Token | Secondary hook: offered to "assist" victim in obtaining clearance/ITC — likely leads to fraudulent document service capturing additional credentials |
| Impact | T1565 | Data Manipulation | Intended use of harvested documents: identity fraud, SIM swap, loan fraud, synthetic identity creation |

---

## Authentication Analysis

| Control | Result | Analyst Note |
|---------|--------|--------------|
| SPF | ✅ PASS | Confirms sending IP 209.85.220.41 is authorised for gmail.com — does NOT validate sender identity |
| DKIM | ✅ PASS | Cryptographic signature valid for gmail.com — confirms message integrity only |
| DMARC | ✅ PASS (p=NONE) | **Critical weakness:** gmail.com DMARC policy is `p=NONE` — monitoring only, no enforcement. Even a DMARC fail would trigger zero automated action. Attacker exploited this deliberately. |
| ARC | ✅ PASS (i=1, i=2) | Two-hop Gmail-to-Gmail delivery chain — no tampering in transit, no intermediary relay |
| DARA | ✅ PASS | Google's internal domain authentication — consistent with direct Gmail send |

> ⚠️ **SOC Key Takeaway:** All 5 authentication controls passed. This email would bypass most automated phishing filters. Detection requires content correlation + sender reputation analysis, NOT authentication results.

## Header Forensics

### Delivery Time Analysis
The message was sent at `2026-02-13T10:21:27+0200` and delivered at 
`2026-02-13T00:21:40-0800 (PST)` — a total transit time of **13 seconds**.
This confirms direct Gmail-to-Gmail delivery with no intermediate relay or 
forwarding infrastructure. The 10:21 AM Friday send time is deliberate — 
start of a work day with a Saturday 10:00 AM deadline creates a sub-24-hour 
pressure window.

### ARC Chain Analysis
The header shows two ARC seals (`i=1` and `i=2`), representing two Google 
mail handling hops during delivery. Both seals pass, confirming the message 
was not tampered with in transit. ARC chains become critical when 
investigating forwarded emails where DMARC alignment might fail — in this 
case the clean chain ironically increases perceived legitimacy to automated filters.

### DMARC p=NONE Exploitation
The DMARC record for `gmail.com` is set to `p=NONE` with `sp=QUARANTINE`.
This means receiving mail servers are instructed to **take no enforcement 
action** — the policy is monitoring-only. Even if a DMARC check had failed, 
no automatic quarantine or rejection would have occurred. The attacker 
deliberately chose Gmail because this weakness ensures delivery regardless 
of authentication anomalies.

### Message-ID Browser Fingerprint
```
Message-ID: CABj7Te-dJ7-4k-E6-3QDcFrKVuzvBGC2NMVXx9qcBDbzip989A@mail.gmail.com
```
The `CA` prefix in Gmail Message-IDs indicates composition via **Gmail web 
browser interface** (not mobile app or third-party client). This suggests 
the attacker used a desktop or laptop to compose and send — a deliberate, 
planned attack rather than a mobile opportunistic one.

### No Intermediary Relay
The received chain shows a single hop from `mail-sor-f41.google.com` 
(`209.85.220.41`) directly to `mx.google.com`. The `sor` designation stands 
for **Sender Outbound Relay** — Gmail's standard outbound infrastructure. 
No VPN, proxy, or third-party relay was used. This means Google retains 
full logs of this account including registration details, linked phone 
number, and device fingerprint — making this attackers reportable and 
potentially traceable.

## Technical Analysis

### Sender
attainingconsultancyportia@gmail.com

Consumer webmail account (not corporate).

---

### Source Infrastructure
mail-sor-f41.google.com IP: 209.85.220.41

Confirms message originated directly from Gmail infrastructure.

---

### Email Authentication

| Control | Result |
|--------|--------|
| SPF | PASS |
| DKIM | PASS |
| DMARC | PASS |

Important SOC note:

These results only confirm that Gmail authenticated itself.  
They do **not** validate the legitimacy of the human sender or organization.

---

## Social Engineering Indicators

- Job offer issued before interview
- WhatsApp onboarding
- Request for ID + ITC + police clearance
- Unrealistic “3–6 hour” clearance turnaround
- Artificial urgency deadline
- No corporate domain
- No company registration details
- Generic greeting (“Dear Applicant”)
- name inconsistency (Porta vs Portia)
- This is a two-stage attack: Stage 1 is document harvesting, Stage 2 is document fraud facilitation

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Sender Email | attainingconsultancyportia@gmail.com |
| WhatsApp Number | 065 515 0058 |
| Source IP | 209.85.220.41 |
| Sending Host | mail-sor-f41.google.com |
| Message-ID | CABj7Te-dJ7-4k-E6-3QDcFrKVuzvBGC2NMVXx9qcBDbzip989A@mail.gmail.com |
| Sent Timestamp | 2026-02-13T10:21:27+0200 |
| Delivery Time | 13 seconds (direct Gmail-to-Gmail) |
| Sender Interface | Gmail Web Browser (CA prefix) |
| Claimed Company | Attaining Consultancy |
| Claimed Address | Eastland Office Park, Bentel Ave, Boksburg, 1459 |
| Subject Line | Contact via the resume for "Sphamandla Mgobhozi" |
```

---## Email Flow Diagram

​```
Attacker Gmail Account (attainingconsultancyportia@gmail.com)
          |
          ▼
  Google SMTP Outbound Relay
  (mail-sor-f41.google.com / 209.85.220.41)
          |
          ▼
    Gmail MX Servers (mx.google.com)
          |
          ▼
     Victim Inbox (sphah001@gmail.com)
          |
          ▼
  WhatsApp Data Harvesting Attempt
  (065 515 0058 — document collection)
          |
          ▼
  [Secondary Stage] Document Fraud Facilitation
  (ITC/Clearance "assistance" hook)

---

## Detection Engineering

### Splunk SPL
```spl
```
index=email
| where like(sender, "%@gmail.com")
| search subject="*resume*" OR subject="*cv*" OR subject="*job*"
| search body="*WhatsApp*" OR body="*identity document*" OR body="*clearance*" OR body="*ITC*"
| search body="*forward*" OR body="*send documents*" OR body="*today*" OR body="*urgently*"
| eval RiskScore=case(
    match(body, "ITC") AND match(body, "WhatsApp"), "HIGH",
    match(body, "identity document"), "MEDIUM",
    true(), "LOW"
  )
| where RiskScore="HIGH"
| stats count by sender, subject, recipient, RiskScore
| sort -count
```
```
```
```
Sender Email: attainingconsultancyportia@gmail.com WhatsApp Number: 065 515 0058 Subject: Contact via...

Microsoft Sentinel (kql)
EmailEvents
| where SenderFromAddress endswith "@gmail.com"
| where SenderMailFromDomain != RecipientEmailAddress split('@')[1]
| where Subject contains "resume" or Subject contains "cv"
| where EmailBody has_any (
    "WhatsApp",
    "identity document",
    "clearance certificate",
    "ITC report",
    "police clearance",
    "compulsory",
    "compassary"
  )
| where EmailBody has_any (
    "forward",
    "send documents",
    "today",
    "before 10:00",
    "urgently"
  )
| extend RiskScore = case(
    EmailBody has "ITC" and EmailBody has "WhatsApp", "HIGH",
    EmailBody has "identity document", "MEDIUM",
    "LOW"
  )
| where RiskScore == "HIGH"
| summarize count() by SenderFromAddress, Subject, RiskScore

Incident Response Actions
1.Block sender address
2.Block WhatsApp number
3.Report Gmail account
4.Educate user on employment scams
5.Recommend credit bureau fraud alert (preventive)

Key SOC Takeaways
•TrustedM/DMARC passing does NOT equal legitimacy.
•Trusted webmail infrastructure is frequently abused.
•Employment scams often avoid malicious links and rely purely on human manipulation.
•Detection requires content correlation + sender reputation

## Tools Used

| Tool | Purpose |
|------|---------|
| Gmail Header Analyzer | Email header parsing and timeline forensics |
| MXToolbox | SPF/DKIM/DMARC record lookup and validation |
| AbuseIPDB | Source IP reputation check (209.85.220.41) |
| VirusTotal | IP and domain reputation analysis |
| MITRE ATT&CK Navigator | Technique mapping and tactic identification |
| Microsoft Sentinel (KQL) | Detection rule development |
| Splunk (SPL) | Detection rule development |
| GitHub | Case study documentation and version control |

## Lessons Learned

- Employment scams increasingly avoid malicious links entirely, relying on 
  pure social engineering to bypass technical controls
- Standard email authentication (SPF/DKIM/DMARC) is insufficient to detect 
  human-impersonation attacks — all 5 controls passed on a fraudulent email
- DMARC `p=NONE` is a systemic weakness exploited by attackers who 
  specifically target consumer webmail providers
- Job portal scraping enables targeted spearphishing at scale — attackers 
  can personalise hundreds of emails using publicly available CV data
- Detection rules must correlate multiple signals: sender reputation + 
  content keywords + urgency indicators, not authentication results alone
- Security awareness training remains the highest-impact control against 
  this attack vector — no technical control stopped this email
  
Author
Sphamandla Mgobhozi
Aspiring SOC Analyst
South Africa
