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

| Stage | Technique |
|------|-----------|
| Initial Access | Phishing (Employment lure) |
| Execution | Manual Gmail sending |
| Collection | Sensitive Personal Data |
| Defense Evasion | Trusted webmail infrastructure |
| Impact | Identity theft |

---

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

---

## Indicators of Compromise (IOCs)
Sender Email: attainingconsultancyportia@gmail.com WhatsApp Number: 065 515 0058 Subject: Contact via the resume for "Sphamandla Mgobhozi" Source IP: 209.85.220.41Message-ID:     CABj7Te-dJ7-4k-E6-3QDcFrKVuzvBGC2NMVXx9qcBDbzip989A@mail.gmail.com
Sending IP:     209.85.220.41
Sending Host:   mail-sor-f41.google.com
Sent timestamp: 2026-02-13T10:21:27+0200
Delivery time:  13 seconds (direct Gmail-to-Gmail, no relay)
Interface used: Gmail Web (CA prefix in Message-ID)
Claimed address: Eastland Office Park, Bentel Ave, Boksburg, 1459
Claimed company: Attaining Consultancy

---

## Email Flow Diagram
Attacker Gmail Account | v Google SMTP (209.85.220.41) | v Gmail MX Servers | v Victim Inbox | v WhatsApp Data Harvesting Attempt

---

## Detection Engineering

### Splunk SPL

```spl
index=email
| where like(sender,"%@gmail.com")
| search ("job offer" OR "employment" OR "resume" OR "interview")
| search ("whatsapp" OR "identity document" OR "clearance" OR "ITC")
| stats count by sender, subject, recipient58

Microsoft Sentinel (KQL)

EmailEvents
| where SenderFromAddress endswith "@gmail.com"
| where Subject contains "resume" or Subject contains "job"
| where Body has_any ("WhatsApp","Identity document","clearance","ITC")
| summarize count() by SenderFromAddress, Subject

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
•Detection requires content correlation + sender reputation.

Author
Sphamandla Mgobhozi
Aspiring SOC Analyst
South Africa
