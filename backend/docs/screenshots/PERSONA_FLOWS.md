# A tour of plexus, one person at a time

plexus is used by a whole company, not one person. A security analyst spots the bug, the security lead signs off on the report, engineers ship the fixes, compliance handles the banking rules, and an auditor checks it all afterwards. The best way to see it is to be each of them in turn.

There are no passwords. Pick a person on the sign-in page, and use **Switch** (top right) to become someone else. You stay on the same incident when you switch, so the next person sees everything the last one did.

If you're on the shared live demo and things look busy from earlier visitors, click **New** in the top bar for a fresh incident.

---

## The people

| Person | Job | What they can do |
|---|---|---|
| **Lukas Berger** | Security analyst | Investigates bugs, assigns fixes, prepares EU reports |
| **Mei Tanaka** | Security lead | Everything Lukas can, plus approving and sending reports |
| **Priya Raman** | Engineer, Terminals | Gets fixes for the card terminals and marks them shipped |
| **Arjun Mehta** | Engineer, Desktop | Gets fixes for the desktop app |
| **Aisha Bello** | Engineer, Identity | Gets fixes for the KYC service |
| **Sofia Costa** | Engineering manager, Platform | Gets the banking-platform fixes, and can assign fixes within her own team only |
| **Elena Rossi** | Compliance | Records DORA assessments for the financial services, and owns the payroll supplier contract |
| **Daniel Weber** | CISO | Can see and ask anything, but changes nothing |
| **Sam Okafor** | External auditor | Read-only: the timeline, the risk list and SBOM downloads |

These permissions are checked on the server for every action, not just hidden in the interface. Everyone else at Fernwave (24 people in all) is under **Show everyone** on the sign-in page.

---

## One bug, start to finish

This is the main story. Do it in order on one incident.

**1. Lukas finds it.** Sign in as Lukas. The newest alert is waiting. Click **Check** on the libwebp one, or ask *"Are we affected by CVE-2023-4863?"*

You'll see **3 products**. The card terminal (FernPOS T2) and the desktop app must be reported to the EU within 24 hours. The KYC service is a banking service, so it falls under DORA instead. The map on the right shows exactly how the bug gets into each one. The terminal gets it four libraries deep, through Pillow. The 24h and 72h clocks at the top start counting.

**2. See how it knows.** Click **How we know** under the answer. Every step is listed, with the chain for each product and the public advisory behind each link.

**3. Hand out the work.** Click **Assign the fixes.** Three tasks go out, one to each owning team's on-call engineer: Arjun (desktop), Aisha (KYC) and Priya (terminal). Each is linked to the ticket that was already tracking the problem (DESK-88, ID-57, TERM-142). Click it again and nothing is duplicated.

**4. Prepare the report.** Click **Prepare 24h first alert** at the top. The form is already filled in: products, EU countries, when the team found out and who confirmed it. Lukas is an analyst, so he can't send it. He clicks **Send for approval**.

**5. Mei signs off.** Switch to Mei. Her button says **Approve report (1)**. Approve and send it. It goes out on time with a reference, and the 24-hour bar turns green and stops. She can then send the 72-hour report the same way.

**6. Priya ships the fix.** Switch to Priya. Her Inbox shows **1 task**. Open **My tasks**, write what shipped, and click **Mark shipped**. Her task and ticket TERM-142 both close. Arjun and Aisha can do the same for theirs.

**7. Elena handles the banking side.** Switch to Elena. Open **Incident → Decisions**, pick KYC Service, choose a DORA outcome and record it.

**8. Mei closes it out.** As Mei, open the sent reports and the **Final report**. The "security update" section is already written from what the engineers said when they shipped.

**9. Sam checks the record.** Switch to Sam and open **Incident → Timeline.** The whole story is there in order, in plain words: who found out first and when, who assigned what, who prepared and who sent each report, and who shipped which fix.

**Things that should be refused along the way:**
- Lukas can't send a report himself, only send it for approval.
- Priya can't mark the desktop app fixed. It isn't her team's product.
- Daniel (CISO) and Sam (auditor) can look at everything but can't assign or fix anything.

---

## Things to try as each person

**Mei or Lukas (security)**
- *"What should we fix first?"* ranks every open bug: ones being exploited first, then ones used by ransomware, then the likeliest to be exploited.
- *"Anything new on CISA's list this month?"* shows the latest exploited bugs and whether any reach Fernwave.
- *"Are we affected by Heartbleed?"* works by nickname. It's in the terminal firmware, through an old OpenSSL, and must be reported.
- *"What about Log4Shell?"* finds only the legacy US gateway, which needs fixing but doesn't need an EU report. Payments Core is already on the safe version.

**Priya, Arjun or Aisha (engineers)**
- Say *"hello"* and you'll get a greeting that tells you how many fix tasks you have.
- *"Who knows Pillow?"* ranks people by real evidence (who maintains it, tickets, chat, decisions) and says where each fact comes from.
- *"Assign the fixes"* is politely refused. Engineers don't assign work.

**Sofia (engineering manager)**
- *"Are we affected by Rapid Reset?"* finds three services: Open Banking API and Payments Core (her team's) and FernPOS Cloud (another team's). Each needs a different fix, because the same bug is in three different libraries.
- **Assign the fixes** assigns her two and skips the third: *"Assigned 2 fixes, skipped 1."* Managers can only assign work within their own team.

**Elena (compliance)**
- *"Are we affected by MOVEit?"* shows that nothing Fernwave sells has it, but the payroll supplier runs it. That's a supplier risk under DORA, and Elena owns that contract.
- *"Why is KYC Service out of CRA scope?"* finds the decision (DEC-007), who made it (Elena), when, and the memo it came from.

**Daniel (CISO)**
- He can ask anything and see the full risk list and timeline, but every button that changes something is off for him.

**Sam (auditor)**
- There's no chat for Sam. Open **Inbox → By product** and download an SBOM (a parts list in the CycloneDX format) for any product.

---

## Questions anyone can ask

| Ask | What comes back |
|---|---|
| *"Who owns what?"* | All 13 teams, their people, their products and who's on call |
| *"Who owns Legacy Merchant Gateway?"* | The Platform team, with Sofia on call |
| *"Any tickets or chat about Electron?"* | Ticket DESK-88 and Arjun's message in the desktop team's channel |
| *"Have we dealt with Log4Shell before?"* | Yes: how it was fixed in 2021 and 2022, and by whom |
| *"What are our most critical parts?"* | The libraries that the most products depend on (libwebp and Pillow come out on top) |
| *"How is Priya connected to CVE-2023-4863?"* | Priya maintains receipt-renderer, which uses Pillow, which bundles libwebp, which has the bug |
| *"What if we upgrade Pillow?"* | What that upgrade would and wouldn't fix (the desktop app stays exposed through Chromium) |
| *"Who should fix it?"* (after asking about a bug) | It remembers which bug you meant |
| A CVE that doesn't exist | It says it's not in Fernwave's data, and doesn't make anything up |

---

## On the landing page

Before signing in, scroll down to the **real cases**: ten real security incidents from 2021 to 2025. Swipe through them and tap one to flip it. The back shows what plexus finds when it runs that same bug against Fernwave, and **Replay it live** opens it in the app.

The libwebp card is the one to look at. A normal check of each product's package list finds **0 of the 3** affected products, because the bug sits inside other libraries.

---

## If something looks off

| What you see | Why |
|---|---|
| The first page load takes a minute | The free server was asleep. It stays awake after that. |
| Alerts already say "checked by" someone | Someone else explored before you. Click **New** for a clean incident. |
| The report button is greyed out | Reports only apply when the bug is being exploited **and** reaches a product sold in the EU. Try CVE-2023-4863 or Heartbleed. |
| "Assign the fixes" does nothing | Ask about a bug first, in the same incident. |
