"""Incident memory, chat history and the watcher agent's alerts."""
import time
import uuid

from .db import MAX_DEPTH, fail, utcnow, q


def remember(session_id, tool, args, result, actor=None):
    """Called by the backend after every tool run. The model never calls this."""
    now, by, eid = utcnow(), (actor or {}).get("name"), uuid.uuid4().hex
    summary = result["data"].get("message") or ""
    q("""MERGE (s:Session {id: $sid}) ON CREATE SET s.started = $now
          CREATE (s)-[:LOGGED]->(:Event {id: $eid, ts: $now, tool: $tool, args: $args, actor: $by,
                                         status: $status, found: $found, summary: $summary})""",
       {"sid": session_id, "now": now, "eid": eid, "tool": tool, "args": str(args),
        "by": by, "status": result["status"], "found": result["found"], "summary": summary[:300]})
    if by:
        q("MATCH (e:Event {id:$eid}), (p:Person {name:$by}) CREATE (e)-[:BY]->(p)",
           {"eid": eid, "by": by})
    if result["status"] != "ok" or tool not in ("lookup_vulnerability", "blast_radius"):
        return  # failed lookups and what-ifs never change the incident's facts
    cve = result["data"].get("cve") or result["data"].get("id")
    q("""MATCH (a:Alert {cve:$cve}) WHERE a.status = 'new'
          SET a.status = 'triaged', a.triaged_by = $by, a.incident = $sid, a.triaged = $now""",
       {"cve": cve, "by": by, "sid": session_id, "now": now})
    q("""MATCH (s:Session {id: $sid}), (v:Vulnerability {id: $cve})
          MERGE (s)-[i:INVESTIGATED]->(v) ON CREATE SET i.first_seen = $now, i.by = $by""",
       {"sid": session_id, "cve": cve, "now": now, "by": by})
    for p in result["data"].get("affected_products", []):
        q("""MATCH (s:Session {id: $sid}), (p:Product {name: $p})
              MERGE (s)-[a:ASSESSED {cve: $cve}]->(p) SET a.verdict = $v, a.by = $by, a.ts = $now""",
           {"sid": session_id, "p": p["product"], "cve": cve, "v": p["cra_verdict"], "by": by, "now": now})
        if p["cra_verdict"].startswith("CRA REPORTABLE"):
            q("""MATCH (s:Session {id: $sid}), (p:Product {name: $p})
                  MERGE (s)-[f:FLAGGED {cve: $cve}]->(p) ON CREATE SET f.by = $by""",
               {"sid": session_id, "p": p["product"], "cve": cve, "by": by})


CYPHER_RECALL = """
MATCH (s:Session {id: $sid})
OPTIONAL MATCH (s)-[:LOGGED]->(e:Event)
WITH s, e ORDER BY e.ts
WITH s, collect({ts: e.ts, tool: e.tool, args: e.args, actor: e.actor, status: e.status,
                 summary: e.summary}) AS events
OPTIONAL MATCH (s)-[i:INVESTIGATED]->(v:Vulnerability)
WITH s, events, collect(DISTINCT {cve: v.id, first_seen: i.first_seen, by: i.by, exploited: v.exploited}) AS investigated
OPTIONAL MATCH (s)-[a:ASSESSED]->(p:Product)
WITH s, events, investigated,
     collect(DISTINCT {product: p.name, cve: a.cve, verdict: a.verdict, by: a.by, ts: a.ts}) AS assessed
OPTIONAL MATCH (s)-[f:FLAGGED]->(fp:Product)
RETURN s.started, events, investigated, assessed,
       collect(DISTINCT {product: fp.name, cve: f.cve, by: f.by}) AS flagged
"""


def recall_session(session_id="mcp-default", **_):
    rows = q(CYPHER_RECALL, {"sid": session_id})
    if not rows:
        return fail("not_found", "Nothing remembered yet for this incident.", CYPHER_RECALL,
                     investigated=[], assessed=[], flagged_products=[], events=[])
    started, events, investigated, assessed, flagged = rows[0]
    remediated = [{"product": p, "cve": c, "by": b, "ts": t, "note": n} for p, c, b, t, n in q(
        """MATCH (:Session {id:$sid})-[r:REMEDIATED]->(p:Product) RETURN p.name, r.cve, r.by, r.ts, r.note ORDER BY r.ts""",
        {"sid": session_id})]
    dora = [{"product": p, "cve": c, "by": b, "ts": t, "outcome": o, "note": n} for p, c, b, t, o, n in q(
        """MATCH (:Session {id:$sid})-[r:DORA_ASSESSED]->(p:Product) RETURN p.name, r.cve, r.by, r.ts, r.outcome, r.note ORDER BY r.ts""",
        {"sid": session_id})]
    investigated = sorted([i for i in investigated if i.get("cve")], key=lambda i: i["first_seen"])
    assessed = [a for a in assessed if a.get("product")]
    flagged = [f for f in flagged if f.get("product")]
    return {"found": True, "cypher": CYPHER_RECALL,
            "paths": [f"(Session)-[:FLAGGED]->(Product:{f['product']})" for f in flagged],
            "touched": [f"Product:{f['product']}" for f in flagged] +
                       [f"Vulnerability:{i['cve']}" for i in investigated],
            "data": {"session_started": started, "investigated": investigated, "assessed": assessed,
                     "flagged_products": flagged, "remediated": remediated, "dora_assessments": dora,
                     "events": [e for e in events if e.get("tool")]}}


CYPHER_WATCH = f"""
MATCH (v:Vulnerability {{exploited: true}})-[:AFFECTS]->(:Component)<-[:DEPENDS_ON*0..{MAX_DEPTH}]-(:Component)<-[:SHIPS]-(p:Product)
OPTIONAL MATCH (p)-[:SOLD_IN]->(m:Market {{code: 'EU'}})
RETURN v.id, v.title, v.kev_added, v.ransomware, collect(DISTINCT p.name), count(DISTINCT m) > 0
"""


def watch_kev():
    """Runs on startup and on demand. Creates one Alert per exploited CVE that reaches something we ship."""
    now, created = utcnow(), []
    for cve, title, added, ransom, products, eu in q(CYPHER_WATCH):
        new = q("""MERGE (a:Alert {cve:$cve})
                    ON CREATE SET a.created = $now, a.status = 'new', a.fresh = true, a.by = 'watcher-agent'
                    ON MATCH SET a.fresh = false
                    SET a.title = $title, a.kev_added = $added, a.ransomware = $ransom, a.products = $products, a.eu = $eu
                    WITH a MATCH (v:Vulnerability {id:$cve}) MERGE (a)-[:ABOUT]->(v)
                    RETURN a.fresh""",
                 {"cve": cve, "now": now, "title": title, "added": added, "ransom": ransom == "Known",
                  "products": sorted(products), "eu": eu})
        if new and new[0][0]:
            created.append(cve)
            # Someone may already be on it: pick that up from the incident memory.
            q("""MATCH (a:Alert {cve:$cve}), (s:Session)-[i:INVESTIGATED]->(:Vulnerability {id:$cve})
                  WHERE NOT coalesce(s.closed, false)
                  WITH a, s, i ORDER BY i.first_seen DESC LIMIT 1
                  SET a.status = 'triaged', a.triaged_by = i.by, a.incident = s.id, a.triaged = i.first_seen""",
               {"cve": cve})
    return {"scanned_at": now, "new_alerts": created}


def alerts():
    rows = q("""MATCH (a:Alert) RETURN a.cve, a.title, a.kev_added, a.ransomware, a.products, a.eu, a.status,
                                      a.triaged_by, a.incident, a.created
                 ORDER BY a.eu DESC, a.kev_added DESC""")
    return [{"cve": c, "title": t, "kev_added": k, "ransomware": r, "products": p, "eu": e, "status": s,
             "triaged_by": tb, "incident": inc, "created": cr} for c, t, k, r, p, e, s, tb, inc, cr in rows]


def save_turn(session_id, person, pane, role, text):
    q("""MERGE (s:Session {id:$sid}) ON CREATE SET s.started = $ts
          CREATE (s)-[:HAS_TURN]->(:Turn {id:$id, person:$person, pane:$pane, role:$role, text:$text, ts:$ts,
                                          seq:$seq})""",
       {"sid": session_id, "ts": utcnow(), "id": uuid.uuid4().hex, "person": person, "pane": pane, "role": role,
        "text": text[:8000], "seq": time.time_ns()})


def load_turns(session_id, person, pane=None, limit=60):
    rows = q("""MATCH (:Session {id:$sid})-[:HAS_TURN]->(t:Turn {person:$person})
                 WHERE $pane IS NULL OR t.pane = $pane
                 RETURN t.pane, t.role, t.text, t.ts ORDER BY t.seq DESC LIMIT $limit""",
              {"sid": session_id, "person": person, "pane": pane, "limit": limit})
    return [{"pane": p, "role": r, "text": x, "ts": ts} for p, r, x, ts in reversed(rows)]
