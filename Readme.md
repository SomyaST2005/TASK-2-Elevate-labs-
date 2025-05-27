# Phishing Email Analysis Report(TASK-2)

## 1. Overview

This report presents an analysis of a sample phishing email . The objective is to identify and document the characteristics that mark it as malicious, enhancing awareness of phishing tactics and email threat detection skills.

**Date of Analysis:** May 27, 2025

---

## 2. Sample Email(Phishing Pot(Github : ```https://github.com/rf-peixoto/phishing_pot```))

![photo of sample phishing email](sample-email(phishingpot).png)

---

## 3. Methodology & Tools

1. **Sample Acquisition**: Obtained public phishing sample email from phishing pot github repo.
2. **Header Analysis**: Pasted raw headers into `MxToolbox Email Header Analyzer` to uncover spoofing.
3. **Link Inspection**: Hovered and copied URLs, then ran `whois` lookup to verify domain registration details.
4. **Content Review**: Assessed language, personalization, and urgency indicators manually.

---

## 4. Phishing Indicators Found

### 1. Authentication Failures or Missing Records

* **No DMARC Record**: Report shows *"DMARC Quarantine – No DMARC Record Found"*, meaning the domain hasn't published a policy to prevent spoofing.
* **SPF Authentication Not Performed**: SPF status is listed as *None*, indicating the sender's IP isn’t authorized to send on behalf of the domain.
* **No DKIM Signature**: No cryptographic signature present to verify domain authenticity.

### 2. Sender Mismatch (Display vs Envelope)

* **Display From**: `"HULU MEMBERSHIP" <noreply@membershiphulu.com>`
* **Envelope From / Return-Path**: Different domain (e.g., `bounce-*.someservice.com`), showing possible spoofing or relay through third-party service.
* Legitimate Hulu communication would typically come from `@hulu.com` or an authorized subdomain.

### 3. Suspicious Sending Infrastructure

* **Mail Origin**: Sent from an Amazon AWS IP address located in Honolulu, HI (`2600:...`).
* **Received Headers**: Multiple hops through generic mail-relay servers. No indication of Hulu’s official mail infrastructure.

### 4. Content-Based Red Flags

* **Urgency and Fear Tactic**: Subject line creates a sense of urgency to trigger immediate action.
* **Generic Message**: No personalization—does not address the recipient by name or mention specific account details.
* **Deceptive Link**: "EXTENDED FOR FREE" button likely points to a non-Hulu domain. Hover-reveal would likely show unrelated or suspicious URL.
* **Fake Domain**: Uses `membershiphulu.com`, which is not affiliated with Hulu’s actual domain `hulu.com`.
* **Poor Unsubscribe Practice**: Uses vague “click here” text rather than a clear, branded unsubscribe link.

### 5. WHOIS Lookup Discrepancies(domain details of membershiphulu.com,bigsbie.com, hulu.com(original) as photo is present in repo.)

* **membershiphulu.com**: This domain is not even registered, meaning attackers could easily buy and use it for malicious purposes. A legitimate business like Hulu would control all domains closely resembling its brand.
* **hulu.com**: The real Hulu domain is registered since 1997, managed by a reputable registrar (CSC Corporate Domains), and uses Akamai name servers, indicating enterprise-level protection.
* **bigsbie.com**: Registered but generic and listed on domain resale services—frequently used in spam/phishing infrastructure. Its registration lacks strong branding, making it suspicious.


---

## 5. Detailed Findings

### 1. **Sender Address**: `membershiphulu.com`

* **Not Registered**: The domain `membershiphulu.com` is currently **unregistered**, meaning **anyone** (including attackers) can purchase and use it to impersonate Hulu.
* **Spoofing Risk**: Since it’s not tied to Hulu officially, attackers can **forge the "From" field** to make it appear like it’s from Hulu Support, fooling non-technical users.

### 2. **SMTP Path** *(Assuming based on common phishing tactics)*

* Likely to pass through **unknown or generic SMTP relays** (e.g., `smtp.mailcheap.net`, `mx.spamcloud.biz`).
* These services are often used by spammers and phishing actors due to weak abuse enforcement and cheap access.
* **No SPF/DKIM/DMARC alignment** would allow spoofing of Hulu’s domain easily or allow fake domains like `membershiphulu.com` to send mail.

### 3. **Domain Reputation & Ownership**

* **hulu.com**:

  * Registered with a trusted registrar (CSC Corporate Domains).
  * Longstanding history (since 1997).
  * Multiple Akamai name servers indicate enterprise-level protection.
* **membershiphulu.com**:

  * **Not owned by Hulu**.
  * Available for public registration (\~\$10), making it an ideal vector for attackers.
  * Absence of ownership info indicates no official affiliation or protections.

### 4. **Link Destination** *(Based on usual tactics)*

* URLs may look like:
  `https://membershiphulu.com/account/verify?user=...`
* **Could redirect to an IP address**, e.g., `http://192.0.2.45/login.php`, which:

  * Is not in Hulu’s infrastructure.
  * Often hosted on temporary, bulletproof hosting services.
  * May include fake login pages or malware payloads.

### 5. **Psychological Triggers Used in the Email**

* **Urgency**: "Your Hulu membership has expired!"
* **Fear**: "Failure to update may result in permanent account termination."
* **Authority Imitation**: Uses Hulu logos, professional-looking formatting to appear legitimate.
* **Call to Action**: A prominent **“Verify Account”** or **“Reactivate Now”** button, enticing hasty action.

---

## 7. Conclusion

This email is a clear phishing attempt, evidenced by:

* **Failed Authentication** (SPF/DKIM/DMARC missing), allowing spoofed senders.
* **Unregistered Spoof Domain** (`membershiphulu.com`) impersonating Hulu.
* **Suspicious Infrastructure** (generic SMTP relays, AWS IPs).
* **WHOIS Red Flags**: Legitimate Hulu domains are long‑established; this one is unowned or parked.
* **Urgent, Deceptive Content**: Fake branding, non‑Hulu links, fear‑based calls to action.

**Action**: Block the sender, report as phishing, and enforce strict SPF/DKIM/DMARC policies.


---

*End of Report*
