"""Company knowledge (teams, tickets, chat, decisions) and graph-algorithm tools."""
import json
import re
import uuid
from datetime import datetime, timezone

from .access import ROLE_LABEL, can, people
from .db import MAX_DEPTH, ToolInputError, clean_name, fail, norm_cve, utcnow, q


CYPHER_TEAMS = """
MATCH (t:Team) WHERE $team IS NULL OR toLower(t.name) CONTAINS toLower($team)
OPTIONAL MATCH (p:Person)-[:MEMBER_OF]->(t)
WITH t, collect(DISTINCT {name: p.name, role: p.role, access: p.access, oncall: p.oncall, email: p.email}) AS members
OPTIONAL MATCH (t)-[:OWNS]->(pr:Product)
RETURN t.name, t.slack, members, collect(DISTINCT pr.name) AS products
ORDER BY size(products) DESC, t.name
"""


def team_directory(team_name=None, **_):
    team = clean_name(team_name, "team_name") if team_name else None
    rows = q(CYPHER_TEAMS, {"team": team})
    if not rows:
        return fail("not_found", f"No team called '{team}'.", CYPHER_TEAMS)
    teams, paths, touched = [], [], []
    for name, slack, members, products in rows:
        members = sorted([dict(m, role_label=ROLE_LABEL.get(m["access"], m["access"])) for m in members if m.get("name")],
                         key=lambda m: (not m["oncall"], m["name"]))
        teams.append({"team": name, "channel": slack, "owns_products": products, "members": members,
                      "on_call": [m["name"] for m in members if m["oncall"]]})
        touched.append(f"Team:{name}")
        touched += [f"Product:{p}" for p in products] + [f"Person:{m['name']}" for m in members]
        paths += [f"(Team:{name})-[:OWNS]->(Product:{p})" for p in products]
        paths += [f"(Person:{m['name']})-[:MEMBER_OF]->(Team:{name})" for m in members]
    return {"found": True, "cypher": CYPHER_TEAMS, "paths": paths, "touched": touched,
            "data": {"teams": teams, "team_count": len(teams),
                     "people_count": sum(len(t["members"]) for t in teams),
                     "products_owned": sum(len(t["owns_products"]) for t in teams)}}


CYPHER_TOPIC = """
MATCH (x) WHERE (x:Component AND (toLower(x.name) CONTAINS toLower($t) OR toLower(x.key) = toLower($t)))
             OR (x:Product AND toLower(x.name) CONTAINS toLower($t))
RETURN id(x), labels(x)[0], coalesce(x.key, x.name)
"""


# (evidence query, weight, how to say it). Each runs over the matched topic nodes.
_KNOW = [
    ("MATCH (p:Person)-[:MAINTAINS]->(x) WHERE id(x) IN $ids RETURN p.name, 'maintains ' + coalesce(x.key, x.name), null",
     5, "MAINTAINS"),
    ("""MATCH (p:Person)-[c:COMMITTED_TO]->(r:Repo)-[:BUILDS]->(x) WHERE id(x) IN $ids
        RETURN p.name, toString(c.commits) + ' commits to ' + r.name, null""", 3, "COMMITTED_TO"),
    ("""MATCH (d:Doc)-[:DOCUMENTS]->(x) WHERE id(x) IN $ids MATCH (d)-[:AUTHORED_BY]->(p:Person)
        RETURN p.name, 'wrote "' + d.title + '"', d.url""", 3, "AUTHORED_BY"),
    ("""MATCH (t:Ticket)-[:ABOUT]->(x) WHERE id(x) IN $ids MATCH (t)-[:ASSIGNED_TO]->(p:Person)
        RETURN DISTINCT p.name, 'assigned ' + t.key + ' (' + t.status + '): ' + t.title, t.url""", 3, "ASSIGNED_TO"),
    ("""MATCH (m:ChatMessage)-[:MENTIONS]->(x) WHERE id(x) IN $ids MATCH (m)-[:POSTED_BY]->(p:Person)
        RETURN DISTINCT p.name, 'posted in ' + m.channel + ' on ' + left(m.ts, 10) + ': \"' + left(m.text, 90) + '\"', null""",
     2, "POSTED_BY"),
    ("""MATCH (d:Decision)-[:ABOUT]->(x) WHERE id(x) IN $ids MATCH (d)-[:DECIDED_BY]->(p:Person)
        RETURN DISTINCT p.name, 'decided ' + d.id + ': ' + d.title, null""", 3, "DECIDED_BY"),
    ("""MATCH (t:Team)-[:OWNS]->(x) WHERE id(x) IN $ids MATCH (p:Person)-[:MEMBER_OF]->(t)
        RETURN p.name, 'on ' + t.name + ', which owns ' + x.name, null""", 1, "MEMBER_OF"),
]


def who_knows(topic, **_):
    """Rank people by evidence in the graph: code, docs, tickets, chat and decisions."""
    t = clean_name(topic, "topic")
    hits = q(CYPHER_TOPIC, {"t": t})
    if not hits:
        return fail("not_found", f"No product or software part called '{t}'.", CYPHER_TOPIC)
    ids = [h[0] for h in hits]

    def gather(node_ids, note=""):
        found = {}
        for cypher, weight, rel in _KNOW:
            for name, why, url in q(cypher, {"ids": node_ids}):
                p = found.setdefault(name, {"person": name, "score": 0, "evidence": []})
                p["score"] += weight
                p["evidence"].append({"fact": why + note, "via": rel, "url": url})
        return found
    people_ = gather(ids)
    if not people_:
        # Nobody owns a bundled C library directly: the people who maintain what wraps it know it best.
        up = q("""MATCH (x:Component)<-[:DEPENDS_ON*1..3]-(u:Component) WHERE id(x) IN $ids
                    RETURN DISTINCT id(u), u.key""", {"ids": ids})
        if up:
            people_ = gather([i for i, _ in up], f" (which uses {hits[0][2].split('@')[0]})")
    ranked = sorted(people_.values(), key=lambda p: -p["score"])
    info = {p["name"]: p for p in people()}
    for p in ranked:
        me = info.get(p["person"], {})
        p.update(team=me.get("team"), role=me.get("role"), oncall=me.get("oncall"), email=me.get("email"))
    topics = [f"{label}:{key}" for _, label, key in hits]
    return {"found": bool(ranked), "status": "ok" if ranked else "not_found", "cypher": CYPHER_TOPIC,
            "paths": [f"(Person:{p['person']})-[:{e['via']}]->({topics[0]})" for p in ranked[:5] for e in p["evidence"][:1]],
            "touched": topics + [f"Person:{p['person']}" for p in ranked[:6]],
            "data": {"topic": t, "matched": topics, "experts": ranked[:6],
                     "message": None if ranked else f"Nobody is linked to '{t}' yet."}}


CYPHER_DECISIONS = """
MATCH (d:Decision)-[:DECIDED_BY]->(p:Person)
OPTIONAL MATCH (d)-[:ABOUT]->(x)
OPTIONAL MATCH (d)-[:SOURCE]->(s)
RETURN d.id, d.title, d.date, d.rationale, p.name, p.role, collect(DISTINCT coalesce(x.key, x.name)) AS about,
       labels(s)[0], coalesce(s.title, s.key, s.id), coalesce(s.url, '')
"""


def _terms(text):
    stop = {"the", "and", "why", "what", "was", "were", "who", "for", "out", "how", "did", "does", "are", "this", "that",
            "with", "from", "our", "decided", "decision", "decide", "made", "about", "is", "of", "we", "any",
            "there", "ticket", "tickets", "chat", "chats", "said", "anyone", "someone", "something", "search",
            "mentioned", "discussed", "know", "knows", "flight", "progress", "slack", "jira", "has", "have", "been"}
    return [w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) > 2 and w not in stop]


def decision_trace(subject, **_):
    """Why is something the way it is? Decision -> who decided -> the source it came from."""
    s = clean_name(subject, "subject")
    terms = _terms(s)
    found = []
    for did, title, date, why, by, role, about, src_label, src, src_url in q(CYPHER_DECISIONS):
        hay = " ".join([did, title, why, *about]).lower()
        score = sum(hay.count(w) for w in terms) + (5 if did.lower() in s.lower() else 0)
        if score:
            found.append((score, {"decision": did, "title": title, "date": date, "rationale": why,
                                  "decided_by": by, "decided_by_role": role, "about": about,
                                  "source": {"type": src_label, "title": src, "url": src_url or None}}))
    found = [f for _, f in sorted(found, key=lambda x: -x[0])][:3]
    if not found:
        return fail("not_found", f"No recorded decision about '{s}'.", CYPHER_DECISIONS)
    paths = []
    for d in found:
        paths.append(f"(Decision:{d['decision']})-[:DECIDED_BY]->(Person:{d['decided_by']})")
        paths.append(f"(Decision:{d['decision']})-[:SOURCE]->({d['source']['type']}:{d['source']['title']})")
        paths += [f"(Decision:{d['decision']})-[:ABOUT]->({a})" for a in d["about"]]
    return {"found": True, "cypher": CYPHER_DECISIONS, "paths": paths,
            "touched": [f"Decision:{d['decision']}" for d in found] + [f"Person:{d['decided_by']}" for d in found],
            "data": {"subject": s, "decisions": found}}


CYPHER_KNOWLEDGE = """
MATCH (t:Ticket)-[:ASSIGNED_TO]->(a:Person)
RETURN 'ticket' AS kind, t.key AS ident, t.title AS text, t.status AS status, t.updated AS date, a.name AS author, t.url AS url, t.key AS src
UNION ALL
MATCH (m:ChatMessage)-[:POSTED_BY]->(a:Person)
RETURN 'chat' AS kind, m.id AS ident, m.text AS text, '' AS status, left(m.ts, 10) AS date, a.name AS author, '' AS url, m.channel AS src
UNION ALL
MATCH (d:Doc) OPTIONAL MATCH (d)-[:AUTHORED_BY]->(a:Person)
RETURN 'doc' AS kind, d.title AS ident, d.title AS text, d.type AS status, '' AS date, a.name AS author, d.url AS url, d.type AS src
UNION ALL
MATCH (d:Decision)-[:DECIDED_BY]->(a:Person)
RETURN 'decision' AS kind, d.id AS ident, d.title + '. ' + d.rationale AS text, '' AS status, d.date AS date, a.name AS author, '' AS url, d.id AS src
"""


STALE_DAYS = 30


def _age_days(date):
    try:
        return (datetime.now(timezone.utc).date() - datetime.fromisoformat(date[:10]).date()).days
    except (TypeError, ValueError):
        return None


def search_knowledge(query, **_):
    """Search tickets, team chat, docs and decisions. Each hit comes with where it came from and how fresh it is."""
    qtext = clean_name(query, "query")
    terms = _terms(qtext)
    if not terms:
        return fail("invalid", "Give me a few words to search for, e.g. 'pillow upgrade'.")
    hits = []
    for kind, ident, text, status, date, author, url, where in q(CYPHER_KNOWLEDGE):
        hay = (text or "").lower() + " " + (ident or "").lower()
        score = sum(1 for w in terms if w in hay)
        if not score:
            continue
        age = _age_days(date)
        hits.append({"type": kind, "id": ident, "text": text[:240], "status": status or None, "date": date or None,
                     "author": author, "url": url or None, "where": where, "age_days": age,
                     "stale": bool(kind == "ticket" and status != "done" and age is not None and age > STALE_DAYS),
                     "_score": score})
    hits.sort(key=lambda h: (-h["_score"], h["age_days"] if h["age_days"] is not None else 9999))
    for h in hits:
        h.pop("_score")
    hits = hits[:8]
    if not hits:
        return fail("not_found", f"Nothing in tickets, chat, docs or decisions matches '{qtext}'.", CYPHER_KNOWLEDGE)
    label = {"ticket": "Ticket", "chat": "ChatMessage", "doc": "Doc", "decision": "Decision"}
    return {"found": True, "cypher": CYPHER_KNOWLEDGE,
            "paths": [f"({label[h['type']]}:{h['id']})" for h in hits],
            "touched": [f"Person:{h['author']}" for h in hits if h["author"]],
            "data": {"query": qtext, "hits": hits}}


def knowledge_status():
    """How current is what the graph knows? Freshness per source, and stale tickets."""
    rows = q(CYPHER_KNOWLEDGE)
    out = {}
    for kind, ident, text, status, date, *_rest in rows:
        o = out.setdefault(kind, {"count": 0, "newest": None, "stale": []})
        o["count"] += 1
        if date and (o["newest"] is None or date > o["newest"]):
            o["newest"] = date
        age = _age_days(date)
        if kind == "ticket" and status != "done" and age is not None and age > STALE_DAYS:
            o["stale"].append({"ticket": ident, "title": text, "days_since_update": age})
    return out


def add_knowledge(channel, text, actor=None):
    """Ingest a chat message (e.g. from a Slack webhook). Products and parts it mentions get linked."""
    if not can(actor, "investigate"):
        return fail("denied", "Only people working incidents can add notes.")
    channel = " ".join(str(channel or "").split())[:40]
    text = " ".join(str(text or "").split())[:1000]
    if not re.fullmatch(r"#[a-z0-9-]{2,40}", channel) or len(text) < 3:
        return fail("invalid", "A note needs a channel like #team-terminals and some text.")
    mid, low = f"m-{uuid.uuid4().hex[:10]}", text.lower()
    q("""MATCH (p:Person {name:$by}) CREATE (:ChatMessage {id:$id, channel:$ch, ts:$ts, text:$text})-[:POSTED_BY]->(p)""",
       {"id": mid, "ch": channel, "ts": utcnow(), "text": text, "by": actor["name"]})
    linked = []
    for label, prop, name, key in q("""MATCH (x) WHERE x:Product OR x:Component
                                        RETURN labels(x)[0], CASE WHEN x:Component THEN 'key' ELSE 'name' END, x.name, coalesce(x.key, x.name)"""):
        if name and re.search(r"(?<![\w-])" + re.escape(name.lower()) + r"(?![\w-])", low):
            q(f"MATCH (m:ChatMessage {{id:$m}}), (x:{label} {{{prop}:$k}}) MERGE (m)-[:MENTIONS]->(x)", {"m": mid, "k": key})
            linked.append(f"{label}:{key}")
    return {"found": True, "status": "ok", "cypher": "", "paths": [f"(ChatMessage:{mid})-[:MENTIONS]->({x})" for x in linked],
            "touched": linked, "data": {"id": mid, "linked": linked,
                                        "message": f"Saved to {channel}." + (f" Linked to {', '.join(x.split(':', 1)[1] for x in linked)}." if linked else "")}}


CYPHER_PAGERANK = "CALL algo.pageRank('Component', 'DEPENDS_ON') YIELD node, score RETURN node.key, score"


CYPHER_BETWEENNESS = """CALL algo.betweenness({nodeLabels: ['Component', 'Product'], relationshipTypes: ['DEPENDS_ON', 'SHIPS']})
YIELD node, score RETURN coalesce(node.key, node.name), score"""


CYPHER_FANIN = f"""
MATCH (c:Component)
OPTIONAL MATCH (c)<-[:DEPENDS_ON*0..{MAX_DEPTH}]-(:Component)<-[:SHIPS]-(p:Product)
WITH c, collect(DISTINCT p.name) AS products
OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS]->(c)
RETURN c.key, products, count(DISTINCT v) AS vulns, count(DISTINCT CASE WHEN v.exploited THEN v END) AS exploited
"""


def critical_components(limit=8, **_):
    """PageRank (what everything leans on) + betweenness (chokepoints) + how many products reach each part."""
    limit = max(1, min(int(limit or 8), 25))
    pr = dict(q(CYPHER_PAGERANK))
    bc = dict(q(CYPHER_BETWEENNESS))
    rows = []
    for key, products, vulns, exploited in q(CYPHER_FANIN):
        if not products:
            continue
        rows.append({"component": key, "products_reached": products, "product_count": len(products),
                     "pagerank": round(pr.get(key, 0), 4), "betweenness": round(bc.get(key, 0), 2),
                     "open_vulnerabilities": vulns, "actively_exploited": exploited})
    rows.sort(key=lambda r: (-r["product_count"], -r["pagerank"], -r["actively_exploited"]))
    top = rows[:limit]
    return {"found": bool(top), "cypher": "\n".join([CYPHER_PAGERANK, CYPHER_BETWEENNESS, CYPHER_FANIN]),
            "paths": [f"(Component:{r['component']})<-[:DEPENDS_ON*]-(...)<-[:SHIPS]-(Product:{p})"
                      for r in top[:3] for p in r["products_reached"]],
            "touched": [f"Component:{r['component']}" for r in top],
            "data": {"ranking": "products reached, then PageRank over DEPENDS_ON (FalkorDB algo.pageRank); "
                                "betweenness (algo.betweenness) shows chokepoints",
                     "critical": top}}


LINK_TYPES = ("DEPENDS_ON|AFFECTS|SHIPS|OWNS|MEMBER_OF|MAINTAINS|BUILDS|COMMITTED_TO|DOCUMENTS|SOLD_IN|"
              "ABOUT|MENTIONS|POSTED_BY|ASSIGNED_TO|REPORTED_BY|DECIDED_BY|AUTHORED_BY|SOURCE")


CYPHER_FIND_ANY = """
MATCH (n) WHERE (n:Person OR n:Product OR n:Team OR n:Component OR n:Vulnerability OR n:Ticket OR n:Decision OR n:Doc)
  AND (toLower(coalesce(n.name, '')) = toLower($x) OR toLower(coalesce(n.key, '')) = toLower($x)
       OR toLower(coalesce(n.id, '')) = toLower($x)
       OR (NOT n:Vulnerability AND toLower(coalesce(n.name, n.title, '')) CONTAINS toLower($x)))
WITH n, coalesce(n.id, n.key, n.name, n.title) AS k,
     toLower(coalesce(n.name, '')) = toLower($x) OR toLower(coalesce(n.key, '')) = toLower($x)
       OR toLower(coalesce(n.id, '')) = toLower($x) AS exact
RETURN id(n), labels(n)[0], k ORDER BY exact DESC, size(k) LIMIT 1
"""


STRUCTURAL = {"DEPENDS_ON", "AFFECTS", "SHIPS", "OWNS", "MEMBER_OF", "MAINTAINS", "BUILDS", "COMMITTED_TO", "SOLD_IN"}
# algo.SPpaths rather than shortestPath(): older FalkorDB releases (e.g. FalkorDB Cloud) reject undirected shortestPath
CYPHER_CONNECTION = f"""
MATCH (a), (b) WHERE id(a) = $a AND id(b) = $b
CALL algo.SPpaths({{sourceNode: a, targetNode: b, relTypes: {json.dumps(LINK_TYPES.split("|"))},
                   relDirection: 'both', maxLen: 8, pathCount: 20}}) YIELD path
RETURN [n IN nodes(path) | [id(n), labels(n)[0], coalesce(n.id, n.key, n.name, n.title)]],
       [r IN relationships(path) | [type(r), id(startNode(r))]]
"""


def connection(from_name, to_name, **_):
    """Shortest chain of relationships between any two things: people, products, parts, CVEs, tickets."""
    ends = []
    for raw in (from_name, to_name):
        x = clean_name(raw, "name")
        try:
            x = norm_cve(x)
        except ToolInputError:
            pass
        row = q(CYPHER_FIND_ANY, {"x": x})
        if not row:
            return fail("not_found", f"Nothing called '{x}'.", CYPHER_FIND_ANY)
        ends.append(row[0])
    if ends[0][0] == ends[1][0]:
        return fail("invalid", "Those are the same thing.")
    rows = q(CYPHER_CONNECTION, {"a": ends[0][0], "b": ends[1][0]})
    if not rows or not rows[0][0]:
        return fail("not_found", f"No chain of up to 8 links connects {ends[0][2]} and {ends[1][2]}.", CYPHER_CONNECTION)
    # among equally short chains, prefer ones made of code and ownership over ticket or chat mentions
    nodes, rels = min(rows, key=lambda r: (len(r[1]), sum(t not in STRUCTURAL for t, _ in r[1])))
    steps, path = [], f"({nodes[0][1]}:{nodes[0][2]})"
    for (rtype, start), (nid, label, key), (pid, plabel, pkey) in zip(rels, nodes[1:], nodes[:-1]):
        forward = start == pid
        steps.append({"from": f"{plabel}:{pkey}", "rel": rtype, "to": f"{label}:{key}", "forward": forward})
        path += (f"-[:{rtype}]->" if forward else f"<-[:{rtype}]-") + f"({label}:{key})"
    return {"found": True, "cypher": CYPHER_CONNECTION, "paths": [path],
            "touched": [f"{l}:{k}" for _, l, k in nodes],
            "data": {"from": f"{ends[0][1]}:{ends[0][2]}", "to": f"{ends[1][1]}:{ends[1][2]}",
                     "hops": len(rels), "steps": steps}}


CYPHER_PAST = """
MATCH (s:Session)-[r:REMEDIATED]->(p:Product) WHERE s.id <> $sid
OPTIONAL MATCH (v:Vulnerability {id: r.cve})
RETURN s.id, r.cve, coalesce(v.title, ''), p.name, r.by, r.ts, r.note ORDER BY r.ts DESC
"""


def past_fixes(subject, session_id="mcp-default", **_):
    s = clean_name(subject, "subject")
    try:
        cves = {norm_cve(s)}
        # same library, other CVEs: e.g. an earlier log4j fix is still the playbook
        cves |= {r[0] for r in q("""MATCH (:Vulnerability {id:$cve})-[:AFFECTS]->(c:Component)
                                     MATCH (c2:Component {name: c.name})<-[:AFFECTS]-(v2:Vulnerability) RETURN DISTINCT v2.id""",
                                  {"cve": next(iter(cves))})}
        terms = []
    except ToolInputError:
        cves, terms = set(), _terms(s)
    rows = []
    for inc, cve, title, product, by, ts, note in q(CYPHER_PAST, {"sid": session_id}):
        hay = f"{cve} {title} {product} {note}".lower()
        if cve in cves or (terms and any(w in hay for w in terms)):
            rows.append({"incident": inc, "cve": cve, "title": title, "product": product, "fixed_by": by,
                         "when": ts[:10], "how": note})
    if not rows:
        return fail("not_found", f"No earlier incident fixed anything matching '{s}'.", CYPHER_PAST)
    return {"found": True, "cypher": CYPHER_PAST,
            "paths": [f"(Session:{r['incident']})-[:REMEDIATED {{cve:{r['cve']}}}]->(Product:{r['product']})" for r in rows],
            "touched": [f"Product:{r['product']}" for r in rows] + [f"Person:{r['fixed_by']}" for r in rows],
            "data": {"subject": s, "past_fixes": rows[:6]}}
