"""
The graph agent: answers a question with fixed rules instead of a model.

It finds the CVE (ID or nickname), product, part or person in the question and the
intent ("who owns", "assign", "what if we upgrade"...), runs the matching tools through
run(), and writes the answer from their results. "Who fixes it?" refers to the CVE the
same person last asked about on this incident. The chat uses it when Gemini isn't available.
"""
import re

from core import db, memory, workflows

UPGRADE_WORDS = ("upgrade", "patch", "what if", "update", "bump")
OWNER_WORDS = ("who", "owner", "wake", "runbook", "on-call", "on call", "fix it", "fixes it")
REPORT_WORDS = ("draft", "early warning", "notification", "file the", "report it")
QUEUE_WORDS = ("fix first", "priorit", "queue", "top risk", "biggest risk", "overall exposure", "what should we fix")
NEW_WORDS = ("new on", "anything new", "recently added", "this week", "this month", "latest kev", "new kev")
PRODUCT_WORDS = ("wrong with", "vulnerab", "issues in", "issues with", "exposed in", "risks in", "risk for", "posture")


def _decision(verdict):
    if verdict.startswith("CRA REPORTABLE"):
        return "**Report to the EU within 24h**"
    if verdict.startswith("LIKELY OUT"):
        return "Not a CRA product (a service): fix it and tell Compliance (DORA)"
    if verdict.startswith("NOT REPORTABLE UNDER"):
        return "No EU report: not sold in the EU"
    return "No report: no known attacks yet"


def _chain(path):
    """'(Vulnerability:X)-[:AFFECTS]->(Component:libwebp@1.3.1)<-...(Product:P)' -> 'libwebp 1.3.1 → … → P'"""
    parts = re.split(r"<-\[:[A-Z_*]+\]-|-\[:[A-Z_*]+\]->", path)
    names = [p.strip("() ").split(":", 1)[-1].replace("@", " ") for p in parts]
    return " → ".join(names[1:])


def _component_in(text):
    names = sorted({r[0] for r in db.q("MATCH (c:Component) RETURN toLower(c.name)")}, key=len, reverse=True)
    return next((n for n in names if re.search(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])", text)), None)


def _product_in(text):
    names = sorted((r[0] for r in db.q("MATCH (p:Product) RETURN p.name")), key=len, reverse=True)
    return next((n for n in names if n.lower() in text), None)


KNOW_WORDS = ("who knows", "expert", "who understands", "who worked on", "who can help with", "who is familiar")
WHY_WORDS = ("why ", "why's", "decided", "decision", "reason we", "rationale")
CRITICAL_WORDS = ("critical", "most important part", "most important component", "riskiest part", "single point",
                  "chokepoint", "pagerank", "most depended", "load-bearing")
CONNECT_WORDS = ("connected to", "connection between", "linked to", "link between", "path from", "how does", "relate to")
PAST_WORDS = ("before", "last time", "previously", "past incident", "dealt with", "how did we fix", "history of")
ASSIGN_WORDS = ("assign", "hand off", "handoff", "hand it off", "create tasks", "create fix tasks", "get fixes started",
                "start the fixes", "dispatch")
MYTASK_WORDS = ("my tasks", "assigned to me", "my work", "what do i need to do", "my queue", "on my plate")
SEARCH_WORDS = ("ticket", "jira", "chat", "slack", "said", "in flight", "in progress", "search", "mentioned", "discussed")
PRODUCT_OWNER_WORDS = ("own", "who", "team", "responsible", "contact", "runbook", "maintain", "on call", "on-call")
TEAM_WORDS = ("how many teams", "which teams", "our teams", "who owns what", "owning what", "who's who", "org chart",
              "people in", "team members")


def _teams(run):
    d = run("team_directory", {})["data"]
    lines = [f"**Fernwave has {d['team_count']} teams and {d['people_count']} people**; "
             f"{d['products_owned']} products have an owning team.", "",
             "| Team | People (role) | Owns |", "|---|---|---|"]
    for t in d["teams"]:
        ppl = ", ".join(f"{m['name']} ({m['role_label']}{', on call' if m['oncall'] else ''})" for m in t["members"]) or "nobody"
        lines.append(f"| **{t['team']}** | {ppl} | {', '.join(t['owns_products']) or 'no products'} |")
    return "\n".join(lines)


def _pair(message):
    m = (re.search(r"between (.+?) and (.+?)[?.!]*$", message, re.I)
         or re.search(r"(?:is|are|does|how is|how are) (.+?) (?:connected|linked|related) to (.+?)[?.!]*$", message, re.I)
         or re.search(r"from (.+?) to (.+?)[?.!]*$", message, re.I))
    return (m[1].strip(" '\""), m[2].strip(" '\"")) if m else None


GREETING = re.compile(r"^\s*(hi|hello|hey|hiya|good (morning|afternoon|evening)|morning|yo)\b")
THANKS = re.compile(r"\b(thanks|thank you|thx|cheers|great|perfect|ok|okay|cool)\b")
HELP = ("help", "what can you do", "how do i use", "who are you", "what are you", "how does this work", "what can i ask")


def _smalltalk(text, user):
    """Greetings, thanks and 'what can you do?' get a short human reply, tailored to the person's job."""
    words = len(text.split())
    first = (user or {}).get("name", "").split(" ")[0]
    if THANKS.search(text) and words <= 4 and not GREETING.search(text):
        return "You're welcome. Ask me anything else about Fernwave's products, people or a bug."
    if not (GREETING.search(text) and words <= 6) and not any(h in text for h in HELP):
        return None
    access = (user or {}).get("access", "")
    owns = (user or {}).get("owns") or []
    if access in ("psirt_lead", "psirt_analyst"):
        intro, asks = "Want to start with the newest alert, or see what to fix first?", [
            "What should we fix first?", "Anything new on CISA's list this month?", "Are we affected by CVE-2023-4863?"]
    elif access in ("engineer", "eng_manager"):
        tasks = workflows.my_tasks(actor=user)["data"]["open"] if user else 0
        intro = (f"You have {tasks} open fix task{'s' if tasks != 1 else ''} in your Inbox." if tasks
                 else "Nothing is assigned to you right now.")
        asks = ([f"What's wrong with {owns[0]}?"] if owns else []) + ["Who knows Pillow?", "My tasks"]
    elif access == "compliance":
        intro, asks = "I can help with DORA and CRA questions.", [
            "Why is KYC Service out of CRA scope?", "Are we affected by CVE-2023-34362?", "Who owns what?"]
    else:
        intro, asks = "Here's where to start.", ["What should we fix first?", "Who owns what?", "What are our most critical parts?"]
    return f"Hi {first}! {intro}\n\nTry: " + " · ".join(f"*\"{a}\"*" for a in asks)


def _product_owner(run, product):
    out = run("product_context", {"product_name": product})
    if out["status"] != "ok":
        return out["data"]["message"]
    d = out["data"]
    oncall = [m["name"] for m in d["team_members"] if m.get("oncall")]
    people = ", ".join(f"{m['name']} ({m['role']})" for m in d["team_members"]) or "nobody listed"
    lines = [f"**{d['product']} is owned by the {d['owner_team']} team** ({d['team_channel']})."
             + (f" On call: **{', '.join(oncall)}**." if oncall else ""), "",
             f"- **People:** {people}"]
    if d["top_committers"]:
        lines.append("- **Knows the code best:** " + ", ".join(f"{c['name']} ({c['commits']} commits)" for c in d["top_committers"][:3]))
    if d["docs"]:
        lines.append("- **Docs:** " + "; ".join(x["title"] for x in d["docs"]))
    if d["markets"]:
        lines.append(f"- **Sold in:** {', '.join(d['markets'])}")
    return "\n".join(lines)


def _who_knows(run, topic):
    out = run("who_knows", {"topic": topic})
    if out["status"] != "ok":
        return out["data"]["message"]
    d = out["data"]
    lines = [f"**Who knows {topic}:** {d['experts'][0]['person']} is the strongest match"
             f" ({d['experts'][0]['team']}{', on call' if d['experts'][0]['oncall'] else ''}).", ""]
    for e in d["experts"][:4]:
        facts = "; ".join(x["fact"] for x in e["evidence"][:3])
        lines.append(f"- **{e['person']}** ({e['role']}, {e['team']}): {facts}")
    return "\n".join(lines)


def _why(run, message):
    out = run("decision_trace", {"subject": message[:100]})
    if out["status"] != "ok":
        return None
    lines = []
    for d in out["data"]["decisions"][:2]:
        src = d["source"]
        lines += [f"**{d['title']}** ({d['decision']}, decided {d['date']} by {d['decided_by']}, {d['decided_by_role']})", "",
                  d["rationale"], "", f"_Source: {src['type'].lower()} \"{src['title']}\"{' · ' + src['url'] if src['url'] else ''}_", ""]
    return "\n".join(lines).strip()


def _search(run, message):
    out = run("search_knowledge", {"query": message[:100]})
    if out["status"] != "ok":
        return out["data"]["message"]
    lines = ["**What the team has on record:**", "", "| Source | What it says | When · who |", "|---|---|---|"]
    for h in out["data"]["hits"][:6]:
        where = {"ticket": f"Ticket {h['id']} ({h['status']})", "chat": f"Chat {h['where']}",
                 "doc": "Doc", "decision": f"Decision {h['id']}"}[h["type"]]
        stale = " · **stale**" if h["stale"] else ""
        lines.append(f"| {where}{stale} | {h['text'][:110]} | {h['date'] or 'n/a'} · {h['author'] or 'n/a'} |")
    return "\n".join(lines)


def _critical(run):
    d = run("critical_components", {"limit": 12})["data"]
    lines = ["**The parts that matter most**: the ones the most products depend on.", "",
             "| Part | Products that depend on it | Bugs attackers are using |", "|---|---|---|"]
    for r in [r for r in d["critical"] if r["open_vulnerabilities"]][:6]:
        lines.append(f"| **{r['component'].replace('@', ' ')}** | {', '.join(r['products_reached'])} | {r['actively_exploited'] or '–'} |")
    top = d["critical"][0]
    lines += ["", f"_Patching **{top['component'].replace('@', ' ')}** protects {top['product_count']} products at once._"]
    return "\n".join(lines)


def _connection(run, a, b):
    out = run("connection", {"from_name": a, "to_name": b})
    if out["status"] != "ok":
        return out["data"]["message"]
    d = out["data"]
    words = {"MEMBER_OF": "is in", "OWNS": "owns", "MAINTAINS": "maintains", "DEPENDS_ON": "depends on",
             "SHIPS": "ships", "AFFECTS": "affects", "ASSIGNED_TO": "is assigned to", "ABOUT": "is about",
             "MENTIONS": "mentions", "POSTED_BY": "was posted by", "DECIDED_BY": "was decided by",
             "COMMITTED_TO": "commits to", "BUILDS": "builds", "DOCUMENTS": "documents", "SOLD_IN": "is sold in",
             "AUTHORED_BY": "was written by", "REPORTED_BY": "was reported by", "SOURCE": "comes from"}
    steps = []
    for st in d["steps"]:
        x, y = (st["from"], st["to"]) if st["forward"] else (st["to"], st["from"])
        steps.append(f"{x.split(':', 1)[1]} **{words.get(st['rel'], st['rel'].lower())}** {y.split(':', 1)[1]}")
    return (f"**How {d['from'].split(':', 1)[1]} is connected to {d['to'].split(':', 1)[1]}:**\n\n"
            + "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1)))


def _past(run, subject):
    out = run("past_fixes", {"subject": subject})
    if out["status"] != "ok":
        return f"**No earlier incident on record** for {subject}. This one will become the playbook."
    lines = ["**Yes, we've fixed this before.** How it went last time:", ""]
    for r in out["data"]["past_fixes"][:4]:
        lines.append(f"- **{r['when']} · {r['product']}** ({r['incident']}, {r['cve']}): {r['how']} _({r['fixed_by']})_")
    return "\n".join(lines)


def _assign(run, cve):
    out = run("create_fix_tasks", {"cve_id": cve})
    if out["status"] == "denied":
        return f"**You can't assign fixes.** {out['data']['message']}"
    if out["status"] != "ok":
        return out["data"]["message"]
    d = out["data"]
    lines = [f"**{d['message']}**", ""]
    for t in d["created"] + d["already_open"]:
        tk = f" Already tracked in {', '.join(x['ticket'] for x in t['existing_tickets'])}." if t["existing_tickets"] else ""
        lines.append(f"- **{t['product']}** → {t['assigned_to']} ({t['team']}): {t['task']}.{tk}")
    for sk in d["skipped"]:
        lines.append(f"- {sk['product']}: skipped, {sk['why']}.")
    return "\n".join(lines)


def _my_tasks(run):
    d = run("my_tasks", {})["data"]
    if not d["tasks"]:
        return "**Nothing assigned to you.** When security assigns a fix, it shows up here."
    lines = [f"**You have {d['open']} open task{'s' if d['open'] != 1 else ''}:**", ""]
    for t in d["tasks"][:8]:
        mark = "✅" if t["status"] == "done" else "⏳"
        lines.append(f"- {mark} {t['task']} · from {t['assigned_by']} · incident {t['incident']}")
    return "\n".join(lines)


def _sev(v):
    return f" (severity {v['cvss']}/10)" if v.get("cvss") else ""


def _pct(x):
    return f"{round(100 * x)}%" if x is not None else "n/a"


def _queue(run):
    d = run("fix_queue", {"limit": 8})["data"]
    lines = [f"**Fix first:** {d['actively_exploited']} of {d['open_vulnerabilities']} open vulnerabilities are being "
             f"used by attackers ({d['exposures']} product exposures in total).", "",
             "| # | Vulnerability | Products | Why it's high |", "|---|---|---|---|"]
    for i, q in enumerate(d["queue"], 1):
        prods = ", ".join(p["product"] + (" (EU report)" if p["eu_report_required"] else "") for p in q["products"])
        lines.append(f"| {i} | **{q['cve']}** {q['title'][:60]} | {prods} | {'; '.join(q['why'][:3])} |")
    return "\n".join(lines)


def _product(run, name):
    out = run("product_vulnerabilities", {"product_name": name})
    if out["status"] != "ok":
        return out["data"]["message"]
    d = out["data"]
    lines = [f"**{d['product']} has {d['total_vulnerabilities']} known vulnerabilities**, "
             f"{d['actively_exploited']} actively exploited, {d['critical_cvss_9_plus']} rated critical (CVSS 9+).", "",
             "| Vulnerability | In | Fix | Exploited? | EPSS |", "|---|---|---|---|---|"]
    for r in d["top"][:8]:
        lines.append(f"| **{r['cve']}** {r['title'][:55]} | {r['component'].replace('@', ' ')} | {r['fixed_in'] or 'n/a'} | "
                     f"{'**yes**' + (' · ransomware' if r['known_ransomware_use'] else '') if r['actively_exploited'] else 'no'} | {_pct(r['epss'])} |")
    return "\n".join(lines)


def _kev_watch(run, days):
    d = run("kev_watch", {"days": days})["data"]
    hit = d["affecting_fernwave"]
    head = (f"**{len(hit)} of them affect Fernwave:** " + ", ".join(f"{h['cve']} ({', '.join(h['products'])})" for h in hit)
            if hit else "**None of them affect anything Fernwave ships.**")
    lines = [f"CISA added **{d['new_entries']} vulnerabilities** to its exploited list since {d['since']}. {head}", "",
             "Latest additions:"]
    lines += [f"- {r['added']} · **{r['cve']}** {r['vendor_product']}{' · ransomware' if r['known_ransomware_use'] else ''}"
              for r in d["latest"][:6]]
    return "\n".join(lines)


# Famous bugs people name instead of numbering. Only used when the question is about exposure,
# so "who knows libwebp?" or "what if we upgrade xz?" still go to the right intent.
NICKNAMES = {"log4shell": "CVE-2021-44228", "log4j": "CVE-2021-44228", "heartbleed": "CVE-2014-0160",
             "libwebp": "CVE-2023-4863", "webp": "CVE-2023-4863", "rapid reset": "CVE-2023-44487",
             "moveit": "CVE-2023-34362", "xz backdoor": "CVE-2024-3094", "xz-utils": "CVE-2024-3094",
             "react2shell": "CVE-2025-55182", "citrix bleed": "CVE-2023-4966", "toolshell": "CVE-2025-53770",
             "activemq": "CVE-2023-46604", "pan-os": "CVE-2024-3400", "globalprotect": "CVE-2024-3400"}
EXPOSURE_WORDS = ("affected", "exposed", "vulnerable", "impact", "hit by", "what about", "are we", "do we have", "check",
                  "report", "must we", "do we need")


def _nickname_any(text):
    return next((c for n, c in NICKNAMES.items() if re.search(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])", text)), None)


def _nickname(text):
    if not any(w in text for w in EXPOSURE_WORDS) or any(w in text for w in UPGRADE_WORDS + ("who knows", "before")):
        return None
    return _nickname_any(text)


def _last_cve(incident_id, user=None):
    """'Assign the fixes' / 'who fixes it?' mean the CVE this person was just talking about."""
    if user:
        for t in reversed(memory.load_turns(incident_id, user["name"], pane="agent")):
            m = db.CVE_RE.search(t["text"])
            if m:
                return f"CVE-{m[1]}-{m[2]}"
    inv = memory.recall_session(incident_id)["data"].get("investigated", [])
    return inv[-1]["cve"] if inv else None


def answer(message, incident_id, user, run):
    """`run(tool, args)` executes a tool and records it in the trace. Returns markdown."""
    text = message.lower()
    try:
        cve = db.norm_cve(message)
    except db.ToolInputError:
        cve = _nickname(text)   # "are we affected by Log4Shell?" works without the CVE number
    target = cve or _last_cve(incident_id, user)
    component = _component_in(text)

    product = _product_in(text)
    if not (cve or product or component):
        small = _smalltalk(text, user)
        if small:
            return small
    if any(w in text for w in MYTASK_WORDS):
        return _my_tasks(run)
    if any(w in text for w in ASSIGN_WORDS) and target:
        return _assign(run, target)
    if any(w in text for w in TEAM_WORDS) and not cve:
        return _teams(run)
    if any(w in text for w in KNOW_WORDS) and (component or product):
        return _who_knows(run, component or product)
    if any(w in text for w in CONNECT_WORDS) and not any(w in text for w in UPGRADE_WORDS):
        pair = _pair(message)
        if pair:
            return _connection(run, *pair)
    if any(w in text for w in CRITICAL_WORDS) and not cve:
        return _critical(run)
    if any(w in text for w in PAST_WORDS) and (cve or _nickname_any(text) or component or product):
        return _past(run, cve or _nickname_any(text) or component or product)
    if any(w in text for w in WHY_WORDS) and not cve:
        out = _why(run, message)
        if out:
            return out
    if any(w in text for w in SEARCH_WORDS) and not cve:
        return _search(run, message)
    if any(w in text for w in NEW_WORDS):
        return _kev_watch(run, 7 if "week" in text else 30)
    if any(w in text for w in QUEUE_WORDS) and not cve:
        return _queue(run)
    if product and not cve and any(w in text for w in PRODUCT_WORDS):
        return _product(run, product)
    if product and not cve and any(w in text for w in PRODUCT_OWNER_WORDS):
        return _product_owner(run, product)
    if any(w in text for w in UPGRADE_WORDS) and component and target:
        return _what_if(run, target, component)
    if any(w in text for w in REPORT_WORDS) and target and not cve:
        return _report(run, target)
    if any(w in text for w in OWNER_WORDS) and target and not cve:
        return _owners(run, target)
    if cve and any(w in text for w in REPORT_WORDS) and "affected" not in text:
        return _report(run, cve)
    if cve:
        return _blast(run, cve, user)
    if product or component:
        return _who_knows(run, component or product)
    return ("I didn't catch that one. Here's what I can answer:\n\n"
            "- **Exposure:** \"Are we affected by CVE-2023-4863?\" · \"What should we fix first?\" · \"What's wrong with FernPOS T2?\"\n"
            "- **Company:** \"Who owns what?\" · \"Who knows Pillow?\" · \"Why is KYC out of CRA scope?\" · \"Any tickets about Electron?\"\n"
            "- **Graph:** \"What are our most critical parts?\" · \"How is Priya connected to CVE-2023-4863?\"\n"
            "- **Work:** \"Assign the fixes\" · \"My tasks\" · \"Have we dealt with Log4Shell before?\"")


def _blast(run, cve, user):
    look = run("lookup_vulnerability", {"cve_id": cve})
    if look["status"] != "ok":
        return (f"**Not in Fernwave's data.** {cve} isn't on CISA's exploited list and no advisory matches anything "
                "Fernwave ships, so I can't say whether you're affected. Check the CVE number, or add the data first.")
    v = look["data"]
    blast = run("blast_radius", {"cve_id": cve})
    attacked = (f"Attackers are already using it (on CISA's exploited list since {v['cisa_kev_added']}"
                f"{', including ransomware groups' if v.get('known_ransomware_use') else ''})."
                if v["actively_exploited"] else "No known attacks yet, so the EU 24-hour clock does not start.")
    if v.get("epss_probability_next_30_days") is not None:
        attacked += f" EPSS: {_pct(v['epss_probability_next_30_days'])} chance of exploitation in the next 30 days."
    products = blast["data"].get("affected_products", [])
    suppliers = blast["data"].get("affected_suppliers", [])
    sup_lines = [f"**Supplier exposed: {s['supplier']}** runs {s['vulnerable_component'].replace('@', ' ')} "
                 f"({s['service']}; holds {s['data_at_risk']}). Under DORA this is third-party ICT risk: "
                 f"{s['contract_owner']} should contact {s['contact']} today." for s in suppliers]
    if not products:
        about = f" It concerns **{v['vendor_product']}**." if v.get("vendor_product") else ""
        if sup_lines:
            return (f"**Nothing Fernwave ships is affected** by {cve} ({v['title']}), **but a supplier is.** {attacked}\n\n"
                    + "\n\n".join(sup_lines))
        return f"**No, nothing Fernwave ships is affected** by {cve} ({v['title']}).{about} {attacked}"
    lines = [f"**Yes, {len(products)} product{'s' if len(products) > 1 else ''} affected** by {cve}, "
             f"{v['title']}{_sev(v)}. {attacked}", "",
             "| Product | How it gets in | Owner · on call | Decision |", "|---|---|---|---|"]
    for p in products:
        path = next((x for x in blast["paths"] if x.endswith(f"(Product:{p['product']})")), "")
        mine = " (yours)" if p["owned_by_asking_user"] else ""
        oncall = ", ".join(o.split(" <")[0] for o in p["oncall"]) or "n/a"
        lines.append(f"| **{p['product']}**{mine} | {_chain(path)} | {p['owner_team']} · {oncall} | "
                     f"{_decision(p['cra_verdict'])} |")
    safe = _patched_copies(cve, v["directly_affects"], {p["product"] for p in products})
    if safe:
        lines += ["", "**Already safe:** " + "; ".join(safe) + "."]
    if sup_lines:
        lines += [""] + sup_lines
    return "\n".join(lines)


def _patched_copies(cve, affected_keys, hit_products):
    """Other versions of the same library that products ship, which this CVE does not affect."""
    names = sorted({k.split("@")[0] for k in affected_keys})
    rows = db.q("""
        MATCH (c:Component) WHERE any(n IN $names WHERE c.key STARTS WITH n + '@') AND NOT c.key IN $affected
        WITH c
        MATCH (c)<-[:DEPENDS_ON*0..10]-(:Component)<-[:SHIPS]-(p:Product)
        RETURN DISTINCT p.name, c.name, c.version ORDER BY p.name""", {"names": names, "affected": list(affected_keys)})
    return [f"{p} uses {n} {ver} (patched)" for p, n, ver in rows if p not in hit_products] + \
           [f"{p} also has {n} {ver}, which is patched, but it is exposed another way" for p, n, ver in rows if p in hit_products]


def _owners(run, cve):
    blast = run("blast_radius", {"cve_id": cve})
    products = blast["data"].get("affected_products", [])
    if not products:
        return f"Nothing we sell is affected by {cve}, so there's no one to wake up."
    lines = [f"**Who fixes {cve}:**", ""]
    for p in products[:4]:
        ctx = run("product_context", {"product_name": p["product"]})["data"]
        runbook = next((d["title"] for d in ctx.get("docs", []) if d.get("type") == "runbook"), "no runbook on file")
        oncall = ", ".join(o.split(" <")[0] for o in p["oncall"]) or "nobody on call"
        lines.append(f"- **{p['product']}**: wake **{oncall}** ({p['owner_team']} team, {p['team_channel']}). "
                     f"Runbook: *{runbook}*.")
    return "\n".join(lines)


def _what_if(run, cve, component):
    # If the CVE we were talking about doesn't touch this part, use the worst bug that does.
    rows = db.q("""MATCH (v:Vulnerability)-[:AFFECTS]->(c:Component)
                             WHERE toLower(c.name) = $n AND (v.id = $cve OR true)
                             RETURN v.id, v.id = $cve AS current ORDER BY current DESC, v.exploited DESC, v.cvss DESC LIMIT 1""",
                          {"n": component, "cve": cve})
    if rows and not rows[0][1]:
        cve = rows[0][0]
    out = run("simulate_patch", {"cve_id": cve, "component_name": component})
    if out["status"] != "ok":
        return out["data"]["message"]
    d = out["data"]
    fixed = ", ".join(d["products_fixed_by_this_upgrade"]) or "nothing"
    lines = [f"**Upgrading {component} fixes: {fixed}.** (Simulation only, nothing was changed.)"]
    for p in d["products_still_exposed"]:
        path = next((x for x in d["remaining_paths"] if x.endswith(f"(Product:{p['product']})")), "")
        lines.append(f"\n**Still exposed: {p['product']}**, via {_chain(path)}. "
                     f"That path doesn't go through {component}, so it needs its own fix.")
    if not d["products_still_exposed"]:
        lines.append("\nNothing else stays exposed to this vulnerability.")
    return "\n".join(lines)


def _report(run, cve):
    out = run("draft_report_facts", {"cve_id": cve})
    if out["status"] == "denied":
        return (f"**Only the security lead (PSIRT) can prepare regulator reports.** {out['data']['message']}\n\n"
                f"Hand-off: {cve} affects products sold in the EU; please open the EU report from the button at the top.")
    if out["status"] != "ok":
        return out["data"]["message"]
    d = out["data"]
    v = d["vulnerability"]
    products = "\n".join(f"- {p['product']} {p['version']} (owner: {p['owner_team']})" for p in d["reportable_products"]) or "- none"
    countries = sorted({c for p in d["reportable_products"] for c in p["eu_member_states"]})
    contact = d["psirt_contact"][0] if d["psirt_contact"] else {}
    return (f"## DRAFT - requires PSIRT review\n**24-hour early warning · {v['id']}**\n\n"
            f"**Vulnerability:** {v['title']}{_sev(v)}. Actively exploited: on CISA's exploited list since {v['cisa_kev_added']}.\n\n"
            f"**Affected products:**\n{products}\n\n"
            f"**EU countries where they are sold:** {', '.join(countries) or 'none'}\n\n"
            f"**Became aware:** {d['awareness_time_utc']} (UTC), confirmed by {d.get('awareness_recorded_by') or 'unknown'}.\n\n"
            f"**Deadline:** {d['deadlines_utc']['early_warning_24h']} (UTC). **Contact:** {contact.get('name')} <{contact.get('email')}>\n\n"
            "To send it, use the report button at the top. The form is already filled in.")
