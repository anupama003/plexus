"""EU reports, fixes, DORA assessments, SBOM export and fix tasks."""
import ast
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

from .access import can, who_can
from .db import MAX_DEPTH, ToolInputError, clean_name, fail, norm_cve, plain_chain, plural, q, utcnow
from .exposure import CYPHER_BLAST, blast_radius, lookup_vulnerability, resolve_product
from .memory import CYPHER_RECALL, recall_session, remember


def draft_report_facts(cve_id, session_id="mcp-default", actor=None, **_):
    cve = norm_cve(cve_id)
    vuln = lookup_vulnerability(cve)
    if not vuln["found"]:
        return vuln
    blast = blast_radius(cve, actor=actor)
    memory = recall_session(session_id)["data"]
    seen = next((i for i in memory.get("investigated", []) if i["cve"] == cve), None)
    aware = datetime.fromisoformat(seen["first_seen"]) if seen else datetime.now(timezone.utc)
    products = blast["data"].get("affected_products", [])
    reportable = [p for p in products if p["cra_verdict"].startswith("CRA REPORTABLE")]
    psirt = q("MATCH (p:Person)-[:MEMBER_OF]->(:Team {name:'PSIRT'}) RETURN p.name, p.email, p.role")
    events = memory.get("events", [])
    return {
        "found": True, "cypher": CYPHER_BLAST + "\n-- plus --\n" + CYPHER_RECALL,
        "paths": blast["paths"], "touched": blast["touched"],
        "data": {
            "vulnerability": vuln["data"],
            "awareness_time_utc": aware.isoformat(),
            "awareness_recorded_by": seen["by"] if seen else None,
            "deadlines_utc": {
                "early_warning_24h": (aware + timedelta(hours=24)).isoformat(),
                "vulnerability_notification_72h": (aware + timedelta(hours=72)).isoformat(),
                "final_report": "within 14 days after a corrective measure is available",
            },
            "reportable_products": reportable,
            "not_reportable": [p for p in products if p not in reportable],
            "psirt_contact": [{"name": n, "email": e, "role": r} for n, e, r in psirt],
            "prepared_by": (actor or {}).get("name"),
            "investigated_by": sorted({e["actor"] for e in events if e.get("actor")}),
            "session_evidence": events[-15:],
            "submit_to": "ENISA Single Reporting Platform (routed to the CSIRT coordinator of the main establishment)",
        },
    }


MANUFACTURER = "Fernwave B.V. (fictional) · main establishment: Amsterdam, Netherlands (NL)"


EU_NAMES = {"AT": "Austria", "BE": "Belgium", "BG": "Bulgaria", "HR": "Croatia", "CY": "Cyprus", "CZ": "Czechia",
            "DK": "Denmark", "EE": "Estonia", "FI": "Finland", "FR": "France", "DE": "Germany", "GR": "Greece",
            "HU": "Hungary", "IE": "Ireland", "IT": "Italy", "LV": "Latvia", "LT": "Lithuania", "LU": "Luxembourg",
            "MT": "Malta", "NL": "Netherlands", "PL": "Poland", "PT": "Portugal", "RO": "Romania", "SK": "Slovakia",
            "SI": "Slovenia", "ES": "Spain", "SE": "Sweden"}


STAGES = ["early_warning", "notification", "final_report"]


SENSITIVITY = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]


def _field(key, label, value, source, required=True, kind="text", options=None):
    return {"key": key, "label": label, "value": value, "source": source, "required": required,
            "kind": kind, "options": options}


def _shortest_path_to(product, paths):
    mine = [p for p in paths if p.endswith(f"(Product:{product})")]
    return min(mine, key=len) if mine else None


def reports(session_id, cve=None, include_pending=False):
    rows = q("""MATCH (:Session {id:$sid})-[:SUBMITTED]->(r:Report)
                 WHERE ($cve IS NULL OR r.cve = $cve)
                 RETURN r.stage, r.cve, r.ref, r.ts, r.by, r.on_time, r.minutes_after_awareness, r.fields,
                        r.status, r.prepared_by, r.prepared_ts
                 ORDER BY r.prepared_ts, CASE r.stage WHEN 'early_warning' THEN 0 WHEN 'notification' THEN 1 ELSE 2 END""",
              {"sid": session_id, "cve": cve})
    out = [{"stage": st, "cve": c, "ref": ref, "ts": ts, "by": by, "on_time": ok, "minutes_after_awareness": mins,
            "fields": json.loads(f or "{}"), "status": status or "sent", "prepared_by": pb, "prepared_ts": pts}
           for st, c, ref, ts, by, ok, mins, f, status, pb, pts in rows]
    return out if include_pending else [r for r in out if r["status"] == "sent"]


def report_package(cve_id, session_id, actor=None):
    """Pre-fill all three CRA stages from verified graph facts + incident memory."""
    try:
        cve = norm_cve(cve_id)
    except ToolInputError as e:
        return fail("invalid", str(e))
    seen = [i for i in recall_session(session_id)["data"].get("investigated", []) if i["cve"] == cve]
    if not seen:
        return fail("not_found", f"{cve} hasn't been investigated in this incident yet. Ask the agent first.")
    facts = draft_report_facts(cve, session_id=session_id, actor=actor)["data"]
    v = facts["vulnerability"]
    if not v["actively_exploited"]:
        return fail("not_reportable", f"{cve} is not known to be actively exploited, so CRA Art. 14 "
                                       "reporting does not apply. Keep monitoring.")
    products = facts["reportable_products"]
    if not products:
        return fail("not_reportable", f"No CRA-reportable product is affected by {cve}. "
                                       "Services fall under DORA: hand over to Compliance.")
    blast = blast_radius(cve, actor=actor)
    fixes = [r for r in recall_session(session_id)["data"].get("remediated", []) if r["cve"] == cve]
    states = sorted({c for p in products for c in p["eu_member_states"]})
    psirt = facts["psirt_contact"][0] if facts["psirt_contact"] else {}
    by = facts.get("awareness_recorded_by")
    docs = {r[0]: r[1] for r in q("""MATCH (d:Doc {type:'runbook'})-[:DOCUMENTS]->(p:Product)
                                      WHERE p.name IN $names RETURN p.name, d.title""",
                                   {"names": [p["product"] for p in products]})}
    per_product, measures = [], []
    for p in products:
        path = _shortest_path_to(p["product"], blast["paths"]) or ""
        comps = [c.split(")")[0] for c in path.split("(Component:")[1:]]
        vulnerable, shipped = (comps[0], comps[-1]) if comps else ("?", "?")
        per_product.append(f"{p['product']} {p['version']} ({p['category']}), "
                           f"{p['hops_from_cve']} steps from the vulnerable code ({plain_chain(path)})")
        fix = (f"upgrade {shipped} so it no longer bundles {vulnerable} (fixed in {v['fixed_in']})"
               if shipped != vulnerable else f"upgrade {vulnerable} ({v['fixed_in']})")
        measures.append(f"{p['product']}: {fix}. Owner: {p['owner_team']} "
                        f"team, on-call {', '.join(o.split(' <')[0] for o in p['oncall']) or 'n/a'}. "
                        f"Runbook: {docs.get(p['product'], 'none on file')}.")
    stages = {
        "early_warning": {
            "title": "24h early warning", "article": "CRA Art. 14(2)(a)",
            "deadline": facts["deadlines_utc"]["early_warning_24h"],
            "fields": [
                _field("manufacturer", "Manufacturer", MANUFACTURER, "company profile"),
                _field("contact", "Contact point", f"{psirt.get('name')} <{psirt.get('email')}>, {psirt.get('role')}",
                       "graph: (Person)-[:MEMBER_OF]->(Team:PSIRT)"),
                _field("vulnerability", "Vulnerability", f"{v['id']}: {v['title']} (CVSS {v['cvss']})",
                       "graph: Vulnerability node"),
                _field("exploitation", "Evidence of active exploitation",
                       f"Listed in the CISA Known Exploited Vulnerabilities catalog on {v['cisa_kev_added']}.",
                       "graph: Vulnerability.kev_added"),
                _field("products", "Affected products",
                       "; ".join(f"{p['product']} {p['version']}" for p in products), "graph: blast_radius"),
                _field("member_states", "EU countries where the products are sold",
                       ", ".join(f"{EU_NAMES.get(c, c)} ({c})" for c in states),
                       "graph: (Product)-[:SOLD_IN {countries}]->(Market:EU)"),
                _field("awareness", "Time the manufacturer became aware",
                       f"{datetime.fromisoformat(facts['awareness_time_utc']).strftime('%d %b %Y, %H:%M UTC')} (confirmed by {by or 'unknown'})",
                       "graph: (Session)-[:INVESTIGATED {first_seen, by}]->(Vulnerability)"),
            ]},
        "notification": {
            "title": "72h vulnerability notification", "article": "CRA Art. 14(2)(b)",
            "deadline": facts["deadlines_utc"]["vulnerability_notification_72h"],
            "fields": [
                _field("product_info", "General information about the affected products", "\n".join(per_product),
                       "graph: blast_radius paths", kind="textarea"),
                _field("nature", "General nature of the exploit and the vulnerability", v["summary"],
                       "graph: Vulnerability.summary", kind="textarea"),
                _field("measures_taken", "Corrective or mitigating measures taken", "\n".join(measures),
                       "graph: owners, on-call, runbooks", kind="textarea"),
                _field("user_measures", "Measures users can take", v["user_mitigation"] or "",
                       "graph: Vulnerability.user_mitigation", kind="textarea"),
                _field("sensitivity", "Who may see this report? (traffic-light label)", "TLP:AMBER",
                       "your judgement", kind="select", options=SENSITIVITY),
            ]},
        "final_report": {
            "title": "Final report", "article": "CRA Art. 14(2)(c)",
            "deadline": "within 14 days after a corrective or mitigating measure is available",
            "fields": [
                _field("description", "Description of the vulnerability, severity and impact",
                       f"{v['title']}. CVSS {v['cvss']}. {v['summary']} Affects {plural(len(products), 'product')} "
                       f"sold in {len(states)} EU countries.", "graph", kind="textarea"),
                _field("threat_actor", "Information about the malicious actor (if available)",
                       "No information about the threat actor is available to the manufacturer.",
                       "your judgement", required=False, kind="textarea"),
                _field("security_update", "Security update or other corrective measures",
                       "\n".join(f"{r['product']}: {r['note']} (marked shipped by {r['by']}, {r['ts'][:16].replace('T', ' ')} UTC)"
                                 for r in fixes),
                       "graph: (Session)-[:REMEDIATED]->(Product)" if fixes else "fill in once the fix has shipped",
                       kind="textarea"),
            ]},
    }
    return {"found": True, "status": "ok", "cypher": CYPHER_BLAST, "paths": blast["paths"],
            "touched": blast["touched"],
            "data": {"cve": cve, "awareness_time_utc": facts["awareness_time_utc"], "awareness_by": by,
                     "stages": stages, "submitted": reports(session_id, cve),
                     "pending": [r for r in reports(session_id, cve, include_pending=True) if r["status"] != "sent"],
                     "submit_to": facts["submit_to"],
                     "max_fine": "up to EUR 15 million or 2.5% of worldwide annual turnover (CRA Art. 64)"}}


def submit_report(cve_id, stage, fields, session_id, actor=None):
    """Security analysts prepare (-> awaiting approval); the security lead sends."""
    if not can(actor, "prepare_report"):
        return fail("denied", "Only the security team (PSIRT) can prepare EU reports. "
                     f"Ask {', '.join(who_can('prepare_report'))}.")
    if stage not in STAGES:
        return fail("invalid", f"Unknown stage '{stage}'. Use one of {STAGES}.")
    pkg = report_package(cve_id, session_id, actor)
    if pkg["status"] != "ok":
        return pkg
    d = pkg["data"]
    sent = {r["stage"]: r for r in d["submitted"]}
    pending = {r["stage"]: r for r in d["pending"]}
    title = d["stages"][stage]["title"]
    if stage in sent:
        return fail("conflict", f"The {title} was already sent ({sent[stage]['ref']}).")
    if stage in pending:
        return fail("conflict", f"The {title} is already waiting for approval from the security lead.")
    missing_prev = [s for s in STAGES[:STAGES.index(stage)] if s not in sent]
    if missing_prev:
        return fail("conflict", f"Send the {d['stages'][missing_prev[0]]['title']} first.")
    final = {}
    for f in d["stages"][stage]["fields"]:
        val = str((fields or {}).get(f["key"], f["value"]) or "").strip()
        if len(val) > 4000:
            return fail("invalid", f"'{f['label']}' is too long (max 4000 characters).")
        if f["required"] and not val:
            return fail("invalid", f"'{f['label']}' is required.")
        if f["kind"] == "select" and val not in f["options"]:
            return fail("invalid", f"'{f['label']}' must be one of {f['options']}.")
        final[f["key"]] = val
    now = utcnow()
    rid = uuid.uuid4().hex
    q("""MATCH (s:Session {id:$sid}) MATCH (p:Person {name:$by})
          CREATE (s)-[:SUBMITTED]->(r:Report {id:$id, stage:$stage, cve:$cve, status:'awaiting_approval',
                  prepared_by:$by, prepared_ts:$ts, fields:$fields})-[:PREPARED_BY]->(p)""",
       {"sid": session_id, "by": actor["name"], "id": rid, "stage": stage, "cve": d["cve"], "ts": now,
        "fields": json.dumps(final)})
    if can(actor, "send_report"):
        return _send(rid, d, stage, session_id, actor)
    lead = who_can("send_report")
    result = {"found": True, "status": "ok", "cypher": "", "paths": [], "touched": [],
              "data": {"stage": stage, "title": title, "cve": d["cve"], "state": "awaiting_approval",
                       "message": f"{title} prepared and sent to {', '.join(lead)} for approval."}}
    remember(session_id, "prepare_report", {"cve_id": d["cve"], "stage": stage}, result, actor)
    return result


def approve_report(cve_id, stage, session_id, actor=None):
    if not can(actor, "send_report"):
        return fail("denied", f"Only the security lead can approve and send EU reports. Ask {', '.join(who_can('send_report'))}.")
    pkg = report_package(cve_id, session_id, actor)
    if pkg["status"] != "ok":
        return pkg
    d = pkg["data"]
    pending = {r["stage"]: r for r in d["pending"]}
    if stage not in pending:
        return fail("not_found", f"There is no {stage.replace('_', ' ')} waiting for approval.")
    rid = q("""MATCH (:Session {id:$sid})-[:SUBMITTED]->(r:Report {cve:$cve, stage:$stage, status:'awaiting_approval'})
                RETURN r.id""", {"sid": session_id, "cve": d["cve"], "stage": stage})[0][0]
    return _send(rid, d, stage, session_id, actor)


def _send(rid, d, stage, session_id, actor):
    now = datetime.now(timezone.utc)
    aware = datetime.fromisoformat(d["awareness_time_utc"])
    deadline = d["stages"][stage]["deadline"]
    on_time = now <= datetime.fromisoformat(deadline) if stage != "final_report" else True
    ref = f"DEMO-SRP-{d['cve']}-{stage.split('_')[0].upper()}-{uuid.uuid4().hex[:4].upper()}"
    minutes = int((now - aware).total_seconds() // 60)
    q("""MATCH (r:Report {id:$id}) MATCH (p:Person {name:$by})
          SET r.status = 'sent', r.ref = $ref, r.ts = $ts, r.by = $by, r.on_time = $on_time,
              r.minutes_after_awareness = $mins
          CREATE (r)-[:BY]->(p)""",
       {"id": rid, "by": actor["name"], "ref": ref, "ts": now.isoformat(timespec="seconds"),
        "on_time": on_time, "mins": minutes})
    title = d["stages"][stage]["title"]
    result = {"found": True, "status": "ok", "cypher": "", "paths": [], "touched": [],
              "data": {"ref": ref, "stage": stage, "title": title, "cve": d["cve"], "state": "sent",
                       "submitted_at": now.isoformat(timespec="seconds"), "on_time": on_time,
                       "minutes_after_awareness": minutes, "deadline": deadline,
                       "message": f"{title} sent ({ref}). SIMULATED: not sent to ENISA."}}
    remember(session_id, "submit_report", {"cve_id": d["cve"], "stage": stage}, result, actor)
    return result


DORA_OUTCOMES = ["Major ICT incident: report to the financial supervisor", "Not a major incident: track internally"]


def _affected_product(cve, product_name, actor):
    name, err = resolve_product(product_name)
    if err:
        return None, None, err
    blast = blast_radius(cve, actor=actor)
    match = next((p for p in blast["data"].get("affected_products", []) if p["product"] == name), None)
    if not match:
        return None, None, fail("invalid", f"{name} is not affected by {cve}, so there is nothing to record.")
    return name, match, None


def remediate(cve_id, product_name, note, session_id, actor=None):
    """Mark that the fix for this CVE has shipped for a product."""
    cve = norm_cve(cve_id)
    name, prod, err = _affected_product(cve, product_name, actor)
    if err:
        return err
    if not (can(actor, "remediate_any") or (can(actor, "remediate_team") and prod["owner_team"] == actor.get("team"))):
        return fail("denied", f"Only the {prod['owner_team']} team or the security lead can mark {name} fixed.")
    note = clean_name(note, "note")
    if q("MATCH (:Session {id:$sid})-[r:REMEDIATED {cve:$cve}]->(:Product {name:$p}) RETURN r.by",
          {"sid": session_id, "cve": cve, "p": name}):
        return fail("conflict", f"{name} is already marked fixed for {cve}.")
    q("""MERGE (s:Session {id:$sid}) ON CREATE SET s.started = $ts
          WITH s MATCH (p:Product {name:$p})
          CREATE (s)-[:REMEDIATED {cve:$cve, by:$by, ts:$ts, note:$note}]->(p)""",
       {"sid": session_id, "p": name, "cve": cve, "by": actor["name"], "ts": utcnow(), "note": note})
    tasks, tickets = _close_work(session_id, cve, name, prod.get("vulnerable_component"), actor)
    parts = (["the task" if len(tasks) == 1 else plural(len(tasks), "task")] if tasks else []) + \
            ([f"ticket{'s' if len(tickets) > 1 else ''} {', '.join(tickets)}"] if tickets else [])
    closed = f" Closed {' and '.join(parts)}." if parts else ""
    result = {"found": True, "status": "ok", "cypher": "", "paths": [], "touched": [f"Product:{name}"],
              "data": {"cve": cve, "product": name, "closed_tasks": tasks, "closed_tickets": tickets,
                       "message": f"{name} marked fixed for {cve}.{closed}"}}
    remember(session_id, "remediate", {"cve_id": cve, "product": name}, result, actor)
    return result


def dora_assess(cve_id, product_name, outcome, note, session_id, actor=None):
    cve = norm_cve(cve_id)
    if not can(actor, "dora_assess"):
        return fail("denied", f"Only Compliance can record DORA assessments. Ask {', '.join(who_can('dora_assess'))}.")
    name, prod, err = _affected_product(cve, product_name, actor)
    if err:
        return err
    if not prod["cra_verdict"].startswith("LIKELY OUT"):
        return fail("invalid", f"{name} is a CRA product, not a financial service. Use the EU report instead.")
    if outcome not in DORA_OUTCOMES:
        return fail("invalid", f"Outcome must be one of: {DORA_OUTCOMES}")
    q("""MERGE (s:Session {id:$sid}) ON CREATE SET s.started = $ts
          WITH s MATCH (p:Product {name:$p})
          MERGE (s)-[r:DORA_ASSESSED {cve:$cve}]->(p) SET r.by = $by, r.ts = $ts, r.outcome = $outcome, r.note = $note""",
       {"sid": session_id, "p": name, "cve": cve, "by": actor["name"], "ts": utcnow(), "outcome": outcome,
        "note": (note or "")[:500]})
    result = {"found": True, "status": "ok", "cypher": "", "paths": [], "touched": [f"Product:{name}"],
              "data": {"cve": cve, "product": name, "outcome": outcome, "message": f"DORA assessment recorded for {name}."}}
    remember(session_id, "dora_assess", {"cve_id": cve, "product": name}, result, actor)
    return result


STAGE_LABEL = {"early_warning": "24h first alert", "notification": "72h full report", "final_report": "final report"}
ACTIVITY = {
    "lookup_vulnerability": "Looked up {cve_id}",
    "blast_radius": "Checked which products {cve_id} reaches",
    "simulate_patch": "Checked what upgrading {component_name} would fix",
    "product_context": "Looked up who owns {product_name}",
    "component_experts": "Looked up who knows {component_name}",
    "recall_session": "Reviewed the incident so far",
    "draft_report_facts": "Gathered the report facts for {cve_id}",
    "product_vulnerabilities": "Reviewed everything affecting {product_name}",
    "fix_queue": "Reviewed what to fix first",
    "kev_watch": "Checked CISA's latest additions",
    "team_directory": "Looked up the teams",
    "who_knows": "Looked up who knows {topic}",
    "decision_trace": "Looked up a past decision",
    "search_knowledge": "Searched tickets and chat for \"{query}\"",
    "critical_components": "Reviewed the most critical parts",
    "connection": "Looked up how {from_name} connects to {to_name}",
    "past_fixes": "Looked up past fixes for {subject}",
    "create_fix_tasks": "Assigned the fixes for {cve_id}",
    "my_tasks": "Checked their tasks",
}
VERB = {"Looked": "look", "Checked": "check", "Assigned": "assign", "Searched": "search", "Reviewed": "review",
        "Gathered": "gather"}
OUTCOME = {"not_found": " (nothing found)", "error": " (failed)", "invalid": " (not understood)"}


def _activity(event):
    try:
        args = ast.literal_eval(event["args"] or "{}")
    except (ValueError, SyntaxError):
        args = {}
    template = ACTIVITY.get(event["tool"], event["tool"].replace("_", " ").capitalize())
    try:
        text = template.format(**args)
    except KeyError:
        text = re.sub(r" ?(for|of|who owns|who knows|upgrading)? ?\{\w+\}", "", template).strip()
    if event["status"] == "denied":
        verb, rest = text.split(" ", 1)
        return f"Tried to {VERB.get(verb, verb.lower())} {rest} (not allowed for their role)"
    return text + OUTCOME.get(event["status"], "")


def timeline(session_id):
    """Everything that happened on an incident, in order, in plain words."""
    mem = recall_session(session_id)["data"]
    workflow = {"prepare_report", "submit_report", "remediate", "dora_assess"}   # listed below from their own records
    items = [{"ts": e["ts"], "actor": e["actor"], "kind": "tool", "status": e["status"], "text": _activity(e)}
             for e in mem.get("events", []) if e["tool"] not in workflow]
    items += [{"ts": i["first_seen"], "actor": i["by"], "kind": "aware", "status": "ok",
               "text": f"Became aware of {i['cve']}{' (attackers are using it)' if i['exploited'] else ''}"}
              for i in mem.get("investigated", [])]
    items += [{"ts": r["ts"], "actor": r["by"], "kind": "fix", "status": "ok",
               "text": f"Marked {r['product']} fixed for {r['cve']}: {r['note']}"} for r in mem.get("remediated", [])]
    items += [{"ts": r["ts"], "actor": r["by"], "kind": "dora", "status": "ok",
               "text": f"DORA assessment for {r['product']} ({r['cve']}): {r['outcome']}"} for r in mem.get("dora_assessments", [])]
    for r in reports(session_id, include_pending=True):
        stage = STAGE_LABEL.get(r["stage"], r["stage"])
        items.append({"ts": r["prepared_ts"], "actor": r["prepared_by"], "kind": "report", "status": "ok",
                      "text": f"Prepared the {stage} for {r['cve']}"})
        if r["status"] == "sent":
            items.append({"ts": r["ts"], "actor": r["by"], "kind": "report", "status": "ok",
                          "text": f"Sent the {stage} for {r['cve']} (reference {r['ref']}, {'on time' if r['on_time'] else 'late'})"})
    return sorted([i for i in items if i["ts"]], key=lambda i: (i["ts"], i["kind"] != "aware"))


PURL = {"pillow": "pkg:pypi/pillow@{v}", "requests": "pkg:pypi/requests@{v}", "urllib3": "pkg:pypi/urllib3@{v}",
        "electron": "pkg:npm/electron@{v}", "sharp": "pkg:npm/sharp@{v}", "axios": "pkg:npm/axios@{v}",
        "golang.org/x/net": "pkg:golang/golang.org/x/net@v{v}", "golang.org/x/crypto": "pkg:golang/golang.org/x/crypto@v{v}",
        "spring-boot": "pkg:maven/org.springframework.boot/spring-boot@{v}",
        "netty-codec-http2": "pkg:maven/io.netty/netty-codec-http2@{v}",
        "jackson-databind": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@{v}",
        "activemq-client": "pkg:maven/org.apache.activemq/activemq-client@{v}",
        "log4j-core": "pkg:maven/org.apache.logging.log4j/log4j-core@{v}",
        "libwebp": "pkg:generic/libwebp@{v}", "openssl": "pkg:generic/openssl@{v}", "libvips": "pkg:generic/libvips@{v}",
        "chromium": "pkg:generic/chromium@{v}", "xz-utils": "pkg:deb/debian/xz-utils@{v}",
        "okhttp": "pkg:maven/com.squareup.okhttp3/okhttp@{v}", "protobuf-java": "pkg:maven/com.google.protobuf/protobuf-java@{v}",
        "tomcat-embed-core": "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@{v}", "snakeyaml": "pkg:maven/org.yaml/snakeyaml@{v}",
        "guava": "pkg:maven/com.google.guava/guava@{v}", "jquery": "pkg:npm/jquery@{v}", "lodash": "pkg:npm/lodash@{v}",
        "moment": "pkg:npm/moment@{v}", "express": "pkg:npm/express@{v}", "jsonwebtoken": "pkg:npm/jsonwebtoken@{v}",
        "ws": "pkg:npm/ws@{v}", "node-fetch": "pkg:npm/node-fetch@{v}", "flask": "pkg:pypi/flask@{v}",
        "werkzeug": "pkg:pypi/werkzeug@{v}", "jinja2": "pkg:pypi/jinja2@{v}", "numpy": "pkg:pypi/numpy@{v}",
        "pyyaml": "pkg:pypi/pyyaml@{v}", "cryptography": "pkg:pypi/cryptography@{v}", "sqlalchemy": "pkg:pypi/sqlalchemy@{v}",
        "react-server-dom-webpack": "pkg:npm/react-server-dom-webpack@{v}", "next": "pkg:npm/next@{v}"}


def sbom(product_name):
    name, err = resolve_product(product_name)
    if err:
        return None, err
    prod = q("MATCH (p:Product {name:$p}) RETURN p.version, p.category", {"p": name})[0]
    comps = q(f"""MATCH (:Product {{name:$p}})-[:SHIPS]->(:Component)-[:DEPENDS_ON*0..{MAX_DEPTH}]->(c:Component)
                   RETURN DISTINCT c.key, c.name, c.version, c.ecosystem ORDER BY c.key""", {"p": name})
    ships = [r[0] for r in q("MATCH (:Product {name:$p})-[:SHIPS]->(c:Component) RETURN c.key", {"p": name})]
    deps = {}
    for a, b in q(f"""MATCH (:Product {{name:$p}})-[:SHIPS]->(:Component)-[:DEPENDS_ON*0..{MAX_DEPTH}]->(a:Component)-[:DEPENDS_ON]->(b:Component)
                       RETURN DISTINCT a.key, b.key""", {"p": name}):
        deps.setdefault(a, []).append(b)
    vulns = q(f"""MATCH (:Product {{name:$p}})-[:SHIPS]->(:Component)-[:DEPENDS_ON*0..{MAX_DEPTH}]->(c:Component)<-[a:AFFECTS]-(v:Vulnerability)
                   RETURN v.id, v.cvss, v.exploited, a.source, collect(DISTINCT c.key)""", {"p": name})
    root = f"product:{name}"
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'plexus/' + name)}",
        "metadata": {"timestamp": utcnow(), "tools": [{"name": "plexus"}],
                     "component": {"type": "device" if "hardware" in prod[1] else "application", "bom-ref": root,
                                   "name": name, "version": prod[0], "supplier": {"name": "Fernwave B.V. (fictional)"}}},
        "components": [dict({"type": "library" if eco != "internal" else "application", "bom-ref": key, "name": n,
                             "version": v}, **({"purl": PURL[n.lower()].format(v=v)} if n.lower() in PURL else {}))
                       for key, n, v, eco in comps],
        "dependencies": [{"ref": root, "dependsOn": ships}] + [{"ref": a, "dependsOn": b} for a, b in deps.items()],
        "vulnerabilities": [{"id": vid, "source": {"name": "OSV" if (src or "").startswith("OSV") else "NVD"},
                             "ratings": [{"score": cvss, "method": "CVSSv3"}] if cvss else [],
                             "properties": [{"name": "cisa:kev", "value": str(bool(ex)).lower()}],
                             "affects": [{"ref": k} for k in keys]} for vid, cvss, ex, src, keys in vulns],
    }
    return bom, None


CYPHER_TICKETS_FOR = f"""
MATCH (t:Ticket)-[:ABOUT]->(:Product {{name: $p}}) WHERE t.status <> 'done'
MATCH (t)-[:ABOUT]->(c:Component)-[:DEPENDS_ON*0..{MAX_DEPTH}]->(:Component {{key: $vc}})
RETURN DISTINCT t.key, t.title, t.status
"""


def create_fix_tasks(cve_id, session_id="mcp-default", actor=None, **_):
    """For every product a CVE reaches, hand a fix task to that team's on-call engineer."""
    cve = norm_cve(cve_id)
    blast = blast_radius(cve, actor=actor)
    if not blast["found"]:
        return blast
    all_teams = can(actor, "draft_report")
    done = {r[0] for r in q("MATCH (:Session {id:$sid})-[r:REMEDIATED {cve:$cve}]->(p:Product) RETURN p.name",
                             {"sid": session_id, "cve": cve})}
    created, existing, skipped, paths = [], [], [], []
    for p in blast["data"]["affected_products"]:
        name = p["product"]
        if name in done:
            skipped.append({"product": name, "why": "fix already shipped"})
            continue
        if not all_teams and p["owner_team"] != actor.get("team"):
            skipped.append({"product": name, "why": f"owned by {p['owner_team']}; only security can assign other teams"})
            continue
        assignee = (p["oncall"][0].split(" <")[0] if p["oncall"] else None)
        if not assignee:
            skipped.append({"product": name, "why": "nobody on call for the owning team"})
            continue
        tid = f"{session_id}:{cve}:{name}"
        tickets = [{"ticket": k, "title": t, "status": s} for k, t, s in
                   q(CYPHER_TICKETS_FOR, {"p": name, "vc": p["vulnerable_component"]})]
        title = f"Fix {cve} in {name}: upgrade {p['vulnerable_component'].replace('@', ' ')}" + \
                (f" to {p['fixed_in']}" if p["fixed_in"] else "")
        new = q("""MERGE (s:Session {id:$sid}) ON CREATE SET s.started = $ts
                    MERGE (t:Task {id:$id})
                    ON CREATE SET t.created = $ts, t.status = 'open', t.cve = $cve, t.product = $p, t.title = $title,
                                  t.assignee = $asg, t.created_by = $by, t.session = $sid, t.fresh = true
                    ON MATCH SET t.fresh = false
                    MERGE (s)-[:HAS_TASK]->(t)
                    WITH t MATCH (a:Person {name:$asg}), (pr:Product {name:$p}), (v:Vulnerability {id:$cve})
                    MERGE (t)-[:ASSIGNED_TO]->(a) MERGE (t)-[:FOR]->(pr) MERGE (t)-[:FIXES]->(v)
                    RETURN t.fresh, t.status""",
                 {"sid": session_id, "id": tid, "ts": utcnow(), "cve": cve, "p": name, "title": title, "asg": assignee,
                  "by": actor["name"]})
        for tk in tickets:
            q("MATCH (t:Task {id:$id}), (k:Ticket {key:$k}) MERGE (t)-[:TRACKED_IN]->(k)", {"id": tid, "k": tk["ticket"]})
        item = {"product": name, "assigned_to": assignee, "team": p["owner_team"], "task": title,
                "existing_tickets": tickets, "status": new[0][1] if new else "open"}
        (created if new and new[0][0] else existing).append(item)
        paths.append(f"(Task:{title})-[:ASSIGNED_TO]->(Person:{assignee})")
    skip = f", skipped {len(skipped)}" if skipped else ""
    if created:
        msg = (f"Assigned {plural(len(created), 'fix', 'fixes')}"
               + (f" ({len(existing)} {'was' if len(existing) == 1 else 'were'} already assigned)" if existing else "") + skip + ".")
    elif existing:
        n = len(existing)
        msg = (("This fix is" if n == 1 else "Both fixes are" if n == 2 else f"All {n} fixes are") + " already assigned."
               + (f" Skipped {len(skipped)}." if skipped else ""))
    else:
        msg = "Nothing to assign" + skip + "."
    return {"found": True, "status": "ok", "cypher": "", "paths": paths,
            "touched": [f"Person:{c['assigned_to']}" for c in created + existing] +
                       [f"Product:{c['product']}" for c in created + existing],
            "data": {"cve": cve, "created": created, "already_open": existing, "skipped": skipped, "message": msg}}


CYPHER_TASKS = """
MATCH (t:Task)-[:ASSIGNED_TO]->(a:Person)-[:MEMBER_OF]->(team:Team)
WHERE ($me IS NOT NULL AND a.name = $me) OR ($team IS NOT NULL AND team.name = $team)
OPTIONAL MATCH (t)-[:TRACKED_IN]->(k:Ticket)
RETURN t.id, t.title, t.status, t.cve, t.product, t.session, t.created, t.created_by, a.name, collect(k.key)
ORDER BY t.status DESC, t.created DESC
"""


def my_tasks(actor=None, **_):
    """The handoff inbox: fix tasks assigned to me (managers also see their team's)."""
    me = (actor or {}).get("name")
    team = actor.get("team") if actor and actor.get("access") == "eng_manager" else None
    rows = q(CYPHER_TASKS, {"me": me, "team": team})
    tasks = [{"id": i, "task": ti, "status": st, "cve": c, "product": p, "incident": s, "created": cr,
              "assigned_by": by, "assigned_to": a, "tickets": ks} for i, ti, st, c, p, s, cr, by, a, ks in rows]
    return {"found": True, "status": "ok", "cypher": CYPHER_TASKS,
            "paths": [f"(Task:{t['task']})-[:ASSIGNED_TO]->(Person:{t['assigned_to']})" for t in tasks[:5]],
            "touched": [f"Product:{t['product']}" for t in tasks],
            "data": {"tasks": tasks, "open": sum(t["status"] == "open" for t in tasks),
                     "message": None if tasks else "No fix tasks assigned to you."}}


def _close_work(session_id, cve, product, vuln_component, actor):
    """A shipped fix closes its tasks and the tickets that tracked it: knowledge stays current."""
    tasks = [r[0] for r in q("""MATCH (:Session {id:$sid})-[:HAS_TASK]->(t:Task {cve:$cve, product:$p, status:'open'})
                                SET t.status = 'done', t.closed = $ts, t.closed_by = $by RETURN t.id""",
                              {"sid": session_id, "cve": cve, "p": product, "ts": utcnow(), "by": actor["name"]})]
    keys = [r[0] for r in q(CYPHER_TICKETS_FOR, {"p": product, "vc": vuln_component})] if vuln_component else []
    if keys:
        q("""MATCH (k:Ticket) WHERE k.key IN $keys
              SET k.status = 'done', k.updated = $day, k.resolution = $why""",
           {"keys": keys, "day": utcnow()[:10], "why": f"Fix shipped for {cve} ({actor['name']}, via plexus)"})
    return tasks, keys
