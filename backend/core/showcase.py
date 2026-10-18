"""Data for the landing page and the map."""
import time

from .db import MAX_DEPTH, norm_cve, plain_chain, q
from .exposure import blast_radius
from .knowledge import past_fixes
from .workflows import CYPHER_TICKETS_FOR


_CASES = None


CYPHER_CASES = """
MATCH (k:Case) OPTIONAL MATCH (k)-[:ABOUT]->(v:Vulnerability)
RETURN k.id, k.name, k.date, k.pattern, k.stat, k.stat_label, k.happened, k.hard_part, k.sources,
       collect(v.id), max(v.kev_added), max(v.epss)
ORDER BY k.date DESC
"""


def replay_cases():
    global _CASES
    if _CASES is not None:
        return _CASES
    estate = q("MATCH (c:Component) WITH count(c) AS c MATCH (p:Product) WITH c, count(p) AS p "
                "MATCH (s:Supplier) RETURN c, p, count(s)")[0]
    out = []
    for cid, name, date, pattern, stat, stat_label, happened, hard, sources, cves, kev, epss in q(CYPHER_CASES):
        t0 = time.perf_counter()
        products, suppliers, paths = {}, {}, []
        for cve in cves:
            b = blast_radius(cve)
            for pr in b["data"].get("affected_products", []):
                if pr["product"] not in products:
                    path = next((x for x in b["paths"] if x.endswith(f"(Product:{pr['product']})")), "")
                    products[pr["product"]] = {
                        "product": pr["product"], "cve": cve, "owner_team": pr["owner_team"],
                        "oncall": [o.split(" <")[0] for o in pr["oncall"]], "chain": plain_chain(path),
                        "hops": pr["hops_from_cve"], "verdict": pr["cra_verdict"].split(":")[0],
                        "fixed_in": pr["fixed_in"], "component": pr["vulnerable_component"],
                        "eu_countries": pr["eu_member_states"],
                        "tickets": [k for k, _, _ in q(CYPHER_TICKETS_FOR, {"p": pr["product"], "vc": pr["vulnerable_component"]})]}
            for sp in b["data"].get("affected_suppliers", []):
                suppliers.setdefault(sp["supplier"], {**sp, "cve": cve})
            paths += b["paths"]
        ms = round((time.perf_counter() - t0) * 1000, 1)
        past = []
        for cve in cves:
            pf = past_fixes(cve, session_id="case-replay")
            past += pf["data"].get("past_fixes", []) if pf["found"] else []
        out.append({"id": cid, "name": name, "date": date, "pattern": pattern, "stat": stat, "stat_label": stat_label,
                    "happened": happened, "hard_part": hard, "sources": sources, "cves": cves,
                    "kev_added": kev, "epss": epss, "ms": ms,
                    "affected": sorted(products.values(), key=lambda x: x["hops"]),
                    "suppliers": list(suppliers.values()),
                    "must_report": sum(p["verdict"] == "CRA REPORTABLE" for p in products.values()),
                    "past_fixes": past[:2], "paths": paths[:6],
                    "package_list_finds": len({p for cve in cves for p in flat_lookup(cve).get("flat_products", [])}),
                    "checked": {"components": estate[0], "products": estate[1], "suppliers": estate[2]}})
    _CASES = out
    return out


def company_overview():
    products = [{"product": n, "version": v, "category": c, "cra_in_scope": inscope, "owner_team": t,
                 "markets": sorted(m for m in markets if m), "parts": parts}
                for n, v, c, inscope, t, markets, parts in q(f"""
        MATCH (p:Product) OPTIONAL MATCH (t:Team)-[:OWNS]->(p)
        OPTIONAL MATCH (p)-[:SOLD_IN]->(m:Market)
        WITH p, t, collect(DISTINCT m.code) AS markets
        OPTIONAL MATCH (p)-[:SHIPS]->(:Component)-[:DEPENDS_ON*0..{MAX_DEPTH}]->(c:Component)
        RETURN p.name, p.version, p.category, p.cra_in_scope, t.name, markets, count(DISTINCT c)
        ORDER BY p.cra_in_scope DESC, p.name""")]
    countries = sorted({c for row in q("MATCH (:Product)-[s:SOLD_IN]->(:Market {code:'EU'}) RETURN s.countries")
                        for c in (row[0] or [])})
    counts = dict(q("""
        MATCH (n) WHERE n:Team OR n:Person OR n:Component OR n:Supplier OR n:Ticket OR n:ChatMessage OR n:Doc
                     OR n:Decision OR n:Repo OR n:Vulnerability
        RETURN labels(n)[0], count(n)"""))
    counts["Exploited"] = q("MATCH (v:Vulnerability {exploited:true}) RETURN count(v)")[0][0]
    return {"name": "Fernwave B.V.", "hq": "Amsterdam, Netherlands", "products": products,
            "eu_countries": countries, "counts": counts}


def flat_lookup(cve_id):
    cve = norm_cve(cve_id)
    title = q("MATCH (v:Vulnerability {id:$cve}) RETURN v.title", {"cve": cve})
    if not title:
        return {"cve": cve, "in_catalog": False}
    affected = [r[0] for r in q("MATCH (:Vulnerability {id:$cve})-[:AFFECTS]->(c:Component) RETURN c.key", {"cve": cve})]
    flat = sorted({r[0] for r in q("MATCH (p:Product)-[:SHIPS]->(c:Component) WHERE c.key IN $keys RETURN DISTINCT p.name",
                                    {"keys": affected})})
    b = blast_radius(cve)
    graph = []
    for pr in b["data"].get("affected_products", []):
        path = next((x for x in b["paths"] if x.endswith(f"(Product:{pr['product']})")), "")
        graph.append({"product": pr["product"], "chain": plain_chain(path), "hops": pr["hops_from_cve"],
                      "owner": ", ".join(o.split(" <")[0] for o in pr["oncall"]) or pr["owner_team"],
                      "verdict": pr["cra_verdict"].split(":")[0]})
    return {"cve": cve, "in_catalog": True, "title": title[0][0], "affected_packages": affected,
            "flat_products": flat, "graph_products": graph,
            "missed": [g for g in graph if g["product"] not in flat],
            "suppliers": [x["supplier"] for x in b["data"].get("affected_suppliers", [])],
            "paths": len(b["paths"])}


def full_graph():
    """The map shows every product, part and person, plus the vulnerabilities that both
    reach a product and matter most (exploited, or curated). The full catalog stays queryable."""
    nodes = q("""MATCH (n) WHERE NOT n:Session AND NOT n:Event AND NOT n:Report AND NOT n:Turn AND NOT n:Task AND NOT n:Alert AND NOT n:Case
                  AND (NOT n:Vulnerability OR ((n)-[:AFFECTS]->() AND (n.exploited OR 'curated' IN n.sources)))
                  RETURN labels(n)[0], coalesce(n.id, n.key, n.name, n.title)""")
    keep = {f"{l}:{k}" for l, k in nodes}
    edges = q("""MATCH (a)-[r]->(b) WHERE NOT a:Session AND NOT a:Event AND NOT a:Report AND NOT a:Task AND NOT a:Alert AND NOT a:Case AND NOT b:Event
                  RETURN labels(a)[0] + ':' + coalesce(a.id, a.key, a.name, a.title),
                         type(r),
                         labels(b)[0] + ':' + coalesce(b.id, b.key, b.name, b.title)""")
    return {"nodes": [{"id": f"{l}:{k}", "label": k, "group": l} for l, k in nodes],
            "edges": [{"from": a, "to": b, "label": t} for a, t, b in edges if a in keep and b in keep]}
