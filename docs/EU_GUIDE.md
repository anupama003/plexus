# The EU rules behind plexus, in plain words

You don't need to know anything about EU law to understand plexus. This page explains the few rules, words and organisations that show up in the app.

*This is a simple summary, not legal advice.*

---

## The short version

Almost every app or device is built from pieces of free, open-source code written by other people. When someone finds a security hole in one of those pieces, every product that uses it is at risk, often without the company that made the product even knowing.

The EU decided that's not good enough. Under a law called the **Cyber Resilience Act**, if you sell a product in the EU and you find out attackers are using a hole in it, you have to tell the authorities, and fast:

| When | What you send |
|---|---|
| Within **24 hours** of finding out | A short warning: "this is happening, and here's where our product is sold" |
| Within **72 hours** | More detail: which products, what the problem is, what you've done, what customers should do |
| Within **14 days** of a fix being ready | A final report on what happened and how it was fixed |

This applies from **11 September 2026**. Fines go up to **€15 million or 2.5% of the company's worldwide yearly revenue**, whichever is higher.

The clock starts when the company *finds out*. That's why plexus records the exact moment, and who it was.

---

## The laws

**Cyber Resilience Act (CRA).** This is the one plexus is built around. It covers *products*: anything with software in it that's sold in the EU, like apps, desktop programs, routers, smart devices and card terminals. It doesn't matter where the company is based. If it sells in the EU, the rule applies.

**DORA.** A separate EU law for banks, payment companies, insurers and other financial firms. It covers the *services* they run themselves, like an online banking system. These have their own reporting rules, handled by financial regulators.

**NIS2.** A law for important organisations like energy, hospitals, transport and cloud providers. It's about how they protect their own systems, not the products they sell. A company can fall under both NIS2 and the CRA.

**GDPR.** The privacy law. If personal data leaks, that's a separate report to a different authority, also within 72 hours.

**Why this matters in the demo.** Fernwave, the made-up company in plexus, is a fintech. Its card terminals and desktop app are *products* it sells, so the CRA applies and it must report. Its KYC service and banking platform are *services* it runs itself, so DORA applies instead. The bug still has to be fixed, but the compliance team decides what to report. plexus works this out for each product and shows it in every answer.

---

## Who's who

**Outside the company**

| Who | What they do |
|---|---|
| **ENISA** | The EU's cybersecurity agency. Every CRA report goes to it. |
| **CSIRT** | Each EU country's official cyber emergency team. It gets the report too. |
| **CISA** | The US cybersecurity agency. It keeps the best-known public list of bugs that attackers are actually using. plexus uses that list. |
| **Market regulators** | The national bodies that can fine a company, demand a fix, or pull a product off the shelves |

**Inside the company** (and who plays them in plexus)

| Who | What they do | In plexus |
|---|---|---|
| **Product security team** (often called a PSIRT) | Handles security holes in the products the company sells, and talks to the authorities | **Mei** (the lead, who sends reports) and **Lukas** (the analyst, who prepares them) |
| **Engineers** | Build the products and ship the fixes | **Priya**, **Arjun**, **Aisha** |
| **Engineering manager** | Runs a team | **Sofia** |
| **Compliance** | Makes sure the company follows the rules, including DORA | **Elena** |
| **CISO** | The person in charge of security overall | **Daniel** |
| **Auditor** | An outsider who checks that things were done properly | **Sam** |

---

## Words you'll see

| Word | What it means |
|---|---|
| **Vulnerability** or **bug** | A security hole that someone could use to cause harm |
| **Exploited** | Attackers are actually using it, not just "it's possible". This is what starts the 24-hour clock. |
| **CVE** | The worldwide ID number for one security hole, like `CVE-2023-4863` |
| **Severity (CVSS)** | How bad a hole could be, scored 0 to 10 |
| **Likelihood (EPSS)** | How likely it is to be used by attackers in the next 30 days, as a percentage |
| **CISA's exploited list (KEV)** | The public list of holes known to be in active use |
| **Library** or **part** | A ready-made piece of code a product is built from |
| **Hidden inside** | A library used by another library you use. Holes are often three or four layers down, which is why they're missed. |
| **Bundled copy** | A library baked inside another one. Upgrading your own copy doesn't fix the bundled one. |
| **SBOM** | A parts list for a product: every piece of code inside it. plexus can download one for any product. |
| **Patch** or **fix** | The update that closes the hole |
| **On the market** | Actually being sold. A product still in testing isn't, so the reporting rule doesn't apply yet. |
| **Member States** | The 27 EU countries. The first report has to say which of them the product is sold in. |

---

## Where you see all this in plexus

| The rule | In the app |
|---|---|
| "Attackers are using it" | The red line in the answer, and the date it appeared on CISA's list |
| "When you found out" | The moment the 24h and 72h bars start, and the first line of the report |
| Product or service? | Each product gets a clear outcome: **Must report**, **Finance rules (DORA)** for a service, **No EU report** if it's not on sale in the EU, or **No report** if no one is attacking it yet |
| Which EU countries | Filled into the report automatically |
| The three reports, in order | The report button walks you through them: 24h, then 72h, then final |
| Only the security lead reports | Lukas can only prepare; Mei approves and sends |

---

## What plexus keeps simple

- **The legal calls are rules of thumb.** Real borderline cases need a person (or a lawyer) to decide.
- **Reports aren't really sent.** ENISA's reporting system has no public connection yet, so plexus records each report and lets you download it.
- **"Found out" is when plexus confirmed it.** In real life it could be earlier, like when a researcher's email arrived.
