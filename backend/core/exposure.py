"""Tools that trace a vulnerability to the products, markets and people it reaches."""
from datetime import datetime, timedelta

from .db import MAX_DEPTH, PATH_PROJECTION, ToolInputError, clean_name, fail, fmt_path, norm_cve, q


CYPHER_LOOKUP = """
MATCH (v:Vulnerability {id: $cve})
OPTIONAL MATCH (v)-[a:AFFECTS]->(c:Component)
RETURN v.id, v.title, v.cvss, v.exploited, v.kev_added, v.fixed_in, v.summary, v.user_mitigation,
       v.vendor, v.kev_product, v.ransomware, v.kev_due, v.required_action, v.epss, v.epss_pct, v.sources, v.url,
       collect(c.key) AS components, collect(a.source) AS link_sources
"""


def lookup_vulnerability(cve_id, **_):
    cve = norm_cve(cve_id)
    rows = q(CYPHER_LOOKUP, {"cve": cve})
    if not rows:
        total = q("MATCH (v:Vulnerability) RETURN count(v), count(CASE WHEN v.exploited THEN 1 END)")[0]
        return fail("not_found", f"{cve} isn't in Fernwave's data: not on CISA's exploited list and no advisory for any "
                     "part Fernwave ships.", CYPHER_LOOKUP, vulnerabilities_in_graph=total[0], on_cisa_kev=total[1])
    (vid, title, cvss, exploited, kev, fixed, summary, mitigation, vendor, kev_product, ransomware, kev_due,
     action, epss, epss_pct, sources, url, comps, link_sources) = rows[0]
    return {
        "found": True, "cypher": CYPHER_LOOKUP,
        "paths": [f"(Vulnerability:{vid})-[:AFFECTS]->(Component:{c})" for c in comps],
        "touched": [f"Vulnerability:{vid}"] + [f"Component:{c}" for c in comps],
        "data": {"id": vid, "title": title, "cvss": cvss,
                 "actively_exploited": exploited, "cisa_kev_added": kev or None,
                 "known_ransomware_use": ransomware == "Known", "cisa_due_date": kev_due or None,
                 "cisa_required_action": action or None,
                 "vendor_product": f"{vendor} {kev_product}".strip() or None,
                 "epss_probability_next_30_days": epss, "epss_percentile": epss_pct,
                 "fixed_in": fixed, "summary": summary, "directly_affects": comps,
                 "evidence": sorted(set(link_sources)), "data_sources": sources, "reference": url,
                 "user_mitigation": mitigation},
    }


# DEPENDS_ON*0..10: zero to ten "uses" hops (0 = the product ships the part itself).
# $exclude is how simulate_patch asks "what if these versions were gone?"
CYPHER_BLAST = f"""
MATCH path = (v:Vulnerability {{id: $cve}})-[a:AFFECTS]->(c0:Component)
             <-[:DEPENDS_ON*0..{MAX_DEPTH}]-(:Component)<-[:SHIPS]-(p:Product)
WHERE none(n IN nodes(path) WHERE coalesce(n.key, "") IN $exclude)
OPTIONAL MATCH (p)-[s:SOLD_IN]->(m:Market)
OPTIONAL MATCH (t:Team)-[:OWNS]->(p)
OPTIONAL MATCH (oc:Person {{oncall: true}})-[:MEMBER_OF]->(t)
RETURN p.name, p.version, p.category, p.cra_in_scope, p.note,
       collect(DISTINCT m.code) AS markets, collect(CASE WHEN m.code = 'EU' THEN s.countries END) AS eu_lists,
       t.name, t.slack,
       collect(DISTINCT oc.name + ' <' + oc.email + '>') AS oncall, collect(DISTINCT oc.name) AS oncall_names,
       v.exploited, length(path) AS hops, c0.key, a.fixed_in, a.source, a.url, {PATH_PROJECTION}
ORDER BY hops
"""


CYPHER_SUPPLIERS = f"""
MATCH (:Vulnerability {{id: $cve}})-[:AFFECTS]->(c:Component)<-[:DEPENDS_ON*0..{MAX_DEPTH}]-(:Component)<-[:RUNS]-(s:Supplier)
OPTIONAL MATCH (owner:Person)-[:MANAGES_SUPPLIER]->(s)
RETURN DISTINCT s.name, s.service, s.data, s.contact, s.dora_critical, c.key, owner.name
"""


def _verdict(exploited, in_scope, note, markets):
    if not exploited:
        return "NOT REPORTABLE: vulnerability not known to be actively exploited"
    if not in_scope:
        return "LIKELY OUT OF CRA SCOPE: " + note
    if "EU" not in markets:
        return ("NOT REPORTABLE UNDER CRA: not on the EU market ("
                + (", ".join(markets) or "not on any market yet") + ")")
    return "CRA REPORTABLE: actively exploited + product on EU market"


def blast_radius(cve_id, actor=None, exclude=(), **_):
    cve = norm_cve(cve_id)
    vuln = q("MATCH (v:Vulnerability {id:$cve}) RETURN v.exploited", {"cve": cve})
    if not vuln:
        return fail("not_found", f"{cve} isn't in Fernwave's data.",
                     CYPHER_BLAST)

    my_team = (actor or {}).get("team")
    products, paths, touched = {}, [], {f"Vulnerability:{cve}"}
    for (name, version, category, in_scope, note, markets, eu_lists, team, slack, oncall, oncall_names,
         exploited, hops, vuln_comp, fix, source, url, names, rels, fwd) in q(CYPHER_BLAST, {"cve": cve, "exclude": list(exclude)}):
        paths.append(fmt_path(names, rels, fwd))
        touched.update(names)
        touched.update(f"Person:{n}" for n in oncall_names)  # owners came from the graph too
        if team:
            touched.add(f"Team:{team}")
        if name in products:
            continue  # rows are ORDER BY hops, so we keep the shortest path per product
        products[name] = {
            "product": name, "version": version, "category": category,
            "markets": markets, "eu_member_states": sorted({c for lst in eu_lists if lst for c in lst}),
            "owner_team": team, "team_channel": slack,
            "oncall": oncall, "hops_from_cve": hops,
            "cra_verdict": _verdict(exploited, in_scope, note, markets),
            "owned_by_asking_user": bool(my_team and team == my_team),
            "vulnerable_component": vuln_comp, "fixed_in": fix or None,
            "evidence": source, "evidence_url": url,
        }

    # suppliers running an affected part: not our product, but a DORA third-party risk
    suppliers = []
    for sname, service, data, contact, critical, comp, owner in q(CYPHER_SUPPLIERS, {"cve": cve}):
        suppliers.append({"supplier": sname, "service": service, "data_at_risk": data, "contact": contact,
                          "dora_critical": critical, "vulnerable_component": comp, "contract_owner": owner,
                          "verdict": "SUPPLIER EXPOSED: ask the supplier, assess under DORA (third-party ICT risk)"})
        paths.append(f"(Vulnerability:{cve})-[:AFFECTS]->(Component:{comp})<-[:RUNS]-(Supplier:{sname})")
        touched.update({f"Supplier:{sname}", f"Component:{comp}"} | ({f"Person:{owner}"} if owner else set()))

    # affected versions that nothing we ship or use runs
    orphan = [r[0] for r in q(
        f"MATCH (:Vulnerability {{id:$cve}})-[:AFFECTS]->(c:Component) "
        f"WHERE NOT (c)<-[:DEPENDS_ON*0..{MAX_DEPTH}]-(:Component)<-[:SHIPS]-(:Product) AND NOT (c)<-[:RUNS]-(:Supplier) "
        f"RETURN c.key", {"cve": cve})]
    hit = bool(products or suppliers)
    return {
        "found": hit, "cypher": CYPHER_BLAST, "paths": paths, "touched": sorted(touched),
        "status": "ok" if hit else "not_found",
        "data": {"cve": cve, "actively_exploited": vuln[0][0],
                 "affected_products": list(products.values()), "affected_suppliers": suppliers,
                 "affected_components_not_shipped": orphan,
                 "message": None if hit else f"Nothing Fernwave ships contains a part affected by {cve}, "
                                             f"and no supplier we use runs one."},
    }


CYPHER_MATCH_COMPONENT = """
MATCH (c:Component) WHERE toLower(c.name) CONTAINS toLower($name) OR toLower(c.key) = toLower($name)
RETURN c.key ORDER BY c.key
"""


def simulate_patch(cve_id, component_name, actor=None, **_):
    cve = norm_cve(cve_id)
    name = clean_name(component_name, "component_name")
    before = blast_radius(cve, actor=actor)
    if before["status"] != "ok":
        return before
    keys = [r[0] for r in q(CYPHER_MATCH_COMPONENT, {"name": name})]
    if not keys:
        return fail("not_found", f"No software part called '{name}'.", CYPHER_MATCH_COMPONENT)
    on_path = [k for k in keys if any(f"Component:{k})" in p for p in before["paths"])]
    if not on_path:
        return fail("not_found", f"'{name}' ({', '.join(keys)}) is not on any exposure path for {cve}. "
                     "Upgrading it changes nothing for this CVE.", CYPHER_BLAST, matched=keys)

    after = blast_radius(cve, actor=actor, exclude=on_path)
    still = {p["product"] for p in after["data"]["affected_products"]}
    fixed = [p["product"] for p in before["data"]["affected_products"] if p["product"] not in still]
    return {
        "found": True, "status": "ok", "cypher": CYPHER_BLAST + "\n-- run twice: $exclude = [] then $exclude = "
                                                  + str(on_path),
        "paths": after["paths"], "touched": before["touched"],
        "data": {"cve": cve, "simulated_upgrade_of": on_path,
                 "products_fixed_by_this_upgrade": fixed,
                 "products_still_exposed": after["data"]["affected_products"],
                 "remaining_paths": after["paths"],
                 "note": "Simulation only. The graph was not modified."},
    }


CYPHER_PRODUCT = """
MATCH (p:Product {name: $name})
OPTIONAL MATCH (t:Team)-[:OWNS]->(p)
OPTIONAL MATCH (person:Person)-[:MEMBER_OF]->(t)
OPTIONAL MATCH (repo:Repo)-[:BUILDS]->(p)
OPTIONAL MATCH (dev:Person)-[cm:COMMITTED_TO]->(repo)
OPTIONAL MATCH (doc:Doc)-[:DOCUMENTS]->(p)
OPTIONAL MATCH (doc)-[:AUTHORED_BY]->(author:Person)
OPTIONAL MATCH (p)-[:SOLD_IN]->(m:Market)
RETURN p.name, p.version, p.category, p.note, t.name, t.slack,
       collect(DISTINCT {name: person.name, role: person.role, email: person.email, oncall: person.oncall}) AS team,
       collect(DISTINCT repo.name) AS repos,
       collect(DISTINCT {name: dev.name, commits: cm.commits}) AS committers,
       collect(DISTINCT {title: doc.title, type: doc.type, url: doc.url, author: author.name}) AS docs,
       collect(DISTINCT m.code) AS markets
"""


CYPHER_FIND_PRODUCT = """
MATCH (p:Product) WHERE toLower(p.name) CONTAINS toLower($name) RETURN p.name ORDER BY p.name
"""


def product_context(product_name, **_):
    wanted = clean_name(product_name, "product_name")
    candidates = [r[0] for r in q(CYPHER_FIND_PRODUCT, {"name": wanted})]
    exact = [c for c in candidates if c.lower() == wanted.lower()]
    if exact:
        candidates = exact
    if not candidates:
        known = [r[0] for r in q("MATCH (p:Product) RETURN p.name ORDER BY p.name")]
        return fail("not_found", f"No product called '{wanted}'.", CYPHER_FIND_PRODUCT,
                     products_in_graph=known)
    if len(candidates) > 1:
        return fail("ambiguous", f"'{wanted}' matches {len(candidates)} products. Ask which one.",
                     CYPHER_FIND_PRODUCT, candidates=candidates)

    name, version, category, note, team, slack, members, repos, devs, docs, markets = \
        q(CYPHER_PRODUCT, {"name": candidates[0]})[0]
    members = [m for m in members if m.get("name")]
    devs = sorted([d for d in devs if d.get("name")], key=lambda d: -(d["commits"] or 0))
    docs = [d for d in docs if d.get("title")]
    paths = [f"(Team:{team})-[:OWNS]->(Product:{name})"] if team else []
    paths += [f"(Person:{m['name']})-[:MEMBER_OF]->(Team:{team})" for m in members]
    paths += [f"(Repo:{r})-[:BUILDS]->(Product:{name})" for r in repos]
    paths += [f"(Doc:{d['title']})-[:DOCUMENTS]->(Product:{name})" for d in docs]
    touched = [f"Product:{name}"] + ([f"Team:{team}"] if team else []) + \
              [f"Person:{m['name']}" for m in members] + [f"Repo:{r}" for r in repos] + \
              [f"Doc:{d['title']}" for d in docs]
    return {"found": True, "cypher": CYPHER_PRODUCT, "paths": paths, "touched": touched,
            "data": {"product": name, "version": version, "category": category, "note": note,
                     "markets": markets, "owner_team": team, "team_channel": slack,
                     "team_members": members, "repos": repos,
                     "top_committers": devs, "docs": docs}}


CYPHER_COMPONENT = f"""
MATCH (c:Component) WHERE toLower(c.name) CONTAINS toLower($name) OR toLower(c.key) = toLower($name)
OPTIONAL MATCH (maint:Person)-[:MAINTAINS]->(c)
OPTIONAL MATCH (repo:Repo)-[:BUILDS]->(c)
OPTIONAL MATCH (dev:Person)-[cm:COMMITTED_TO]->(repo)
OPTIONAL MATCH (doc:Doc)-[:DOCUMENTS]->(c)
OPTIONAL MATCH (up:Component)-[:DEPENDS_ON*1..{MAX_DEPTH}]->(c)
OPTIONAL MATCH (upmaint:Person)-[:MAINTAINS]->(up)
RETURN c.key, c.ecosystem,
       collect(DISTINCT maint.name) AS maintainers,
       collect(DISTINCT {{name: dev.name, commits: cm.commits}}) AS committers,
       collect(DISTINCT {{title: doc.title, url: doc.url}}) AS docs,
       collect(DISTINCT up.key) AS used_by,
       collect(DISTINCT upmaint.name + ' (maintains ' + up.key + ')') AS upstream_maintainers
"""


def component_experts(component_name, **_):
    name = clean_name(component_name, "component_name")
    rows = q(CYPHER_COMPONENT, {"name": name})
    if not rows:
        return fail("not_found", f"No software part called '{name}'.", CYPHER_COMPONENT)
    results, paths, touched = [], [], []
    for key, eco, maints, devs, docs, used_by, up_maints in rows:
        devs = sorted([d for d in devs if d.get("name")], key=lambda d: -(d["commits"] or 0))
        docs = [d for d in docs if d.get("title")]
        results.append({"component": key, "ecosystem": eco, "maintainers": maints,
                        "committers": devs, "docs": docs, "used_by": used_by,
                        "maintainers_of_dependents": up_maints})
        touched.append(f"Component:{key}")
        paths += [f"(Person:{m})-[:MAINTAINS]->(Component:{key})" for m in maints]
        paths += [f"(Component:{u})-[:DEPENDS_ON*]->(Component:{key})" for u in used_by]
        touched += [f"Person:{m}" for m in maints] + [f"Component:{u}" for u in used_by]
    return {"found": True, "cypher": CYPHER_COMPONENT, "paths": paths, "touched": touched,
            "data": {"matches": results,
                     "hint": "If a C library has no maintainer, the people who maintain the "
                             "components that depend on it are the right ones to patch it."}}


CYPHER_PRODUCT_VULNS = f"""
MATCH (p:Product {{name: $name}})-[:SHIPS]->(:Component)-[:DEPENDS_ON*0..{MAX_DEPTH}]->(c:Component)<-[a:AFFECTS]-(v:Vulnerability)
RETURN DISTINCT v.id, v.title, v.cvss, v.exploited, v.ransomware, v.epss, c.key, a.fixed_in, a.source
"""


def _rank(exploited, ransomware, epss, cvss):
    return (bool(exploited), ransomware == "Known", epss or 0, cvss or 0)


def resolve_product(product_name):
    wanted = clean_name(product_name, "product_name")
    cands = [r[0] for r in q(CYPHER_FIND_PRODUCT, {"name": wanted})]
    exact = [c for c in cands if c.lower() == wanted.lower()]
    cands = exact or cands
    if not cands:
        known = [r[0] for r in q("MATCH (p:Product) RETURN p.name ORDER BY p.name")]
        return None, fail("not_found", f"No product called '{wanted}'.", CYPHER_FIND_PRODUCT,
                           products_in_graph=known)
    if len(cands) > 1:
        return None, fail("ambiguous", f"'{wanted}' matches {len(cands)} products. Ask which one.",
                           CYPHER_FIND_PRODUCT, candidates=cands)
    return cands[0], None


def product_vulnerabilities(product_name, **_):
    name, err = resolve_product(product_name)
    if err:
        return err
    seen, rows = set(), []
    for vid, title, cvss, exploited, ransomware, epss, comp, fix, source in q(CYPHER_PRODUCT_VULNS, {"name": name}):
        if vid in seen:
            continue
        seen.add(vid)
        rows.append({"cve": vid, "title": title, "cvss": cvss, "actively_exploited": bool(exploited),
                     "known_ransomware_use": ransomware == "Known", "epss": epss, "component": comp,
                     "fixed_in": fix or None, "evidence": source})
    rows.sort(key=lambda r: _rank(r["actively_exploited"], "Known" if r["known_ransomware_use"] else "",
                                  r["epss"], r["cvss"]), reverse=True)
    top = rows[:15]
    return {"found": True, "cypher": CYPHER_PRODUCT_VULNS,
            "paths": [f"(Vulnerability:{r['cve']})-[:AFFECTS]->(Component:{r['component']})" for r in top[:8]],
            "touched": [f"Product:{name}"] + [f"Component:{r['component']}" for r in top] + [f"Vulnerability:{r['cve']}" for r in top[:8]],
            "data": {"product": name, "total_vulnerabilities": len(rows),
                     "actively_exploited": sum(r["actively_exploited"] for r in rows),
                     "critical_cvss_9_plus": sum(1 for r in rows if (r["cvss"] or 0) >= 9),
                     "top": top}}


CYPHER_QUEUE = f"""
MATCH path = (v:Vulnerability)-[a:AFFECTS]->(c:Component)<-[:DEPENDS_ON*0..{MAX_DEPTH}]-(:Component)<-[:SHIPS]-(p:Product)
OPTIONAL MATCH (p)-[:SOLD_IN]->(m:Market)
OPTIONAL MATCH (t:Team)-[:OWNS]->(p)
RETURN v.id, v.title, v.cvss, v.exploited, v.ransomware, v.epss, p.name, p.cra_in_scope,
       collect(DISTINCT m.code), t.name, c.key, a.fixed_in, min(length(path))
"""


def fix_queue(limit=10, **_):
    try:
        limit = max(1, min(int(limit), 25))
    except (TypeError, ValueError):
        raise ToolInputError("limit must be a number between 1 and 25.")
    items = {}
    for vid, title, cvss, exploited, ransomware, epss, prod, in_scope, markets, team, comp, fix, hops in q(CYPHER_QUEUE):
        it = items.setdefault(vid, {"cve": vid, "title": title, "cvss": cvss, "actively_exploited": bool(exploited),
                                    "known_ransomware_use": ransomware == "Known", "epss": epss, "products": {}})
        reportable = bool(exploited and in_scope and "EU" in markets)
        it["products"].setdefault(prod, {"product": prod, "owner_team": team, "component": comp,
                                         "fixed_in": fix or None, "hops": hops, "eu_report_required": reportable})
    queue = []
    for it in items.values():
        prods = list(it["products"].values())
        any_report = any(p["eu_report_required"] for p in prods)
        score = (1000 * it["actively_exploited"] + 300 * it["known_ransomware_use"] + 200 * any_report
                 + 100 * (it["epss"] or 0) + 10 * (it["cvss"] or 0) + len(prods))
        why = (["attackers are using it (CISA KEV)"] if it["actively_exploited"] else []) + \
              (["used in ransomware campaigns"] if it["known_ransomware_use"] else []) + \
              (["EU report required"] if any_report else []) + \
              ([f"EPSS {round(100 * it['epss'])}% chance of exploitation in 30 days"] if (it["epss"] or 0) >= .1 else []) + \
              ([f"CVSS {it['cvss']}"] if it["cvss"] else [])
        queue.append({**it, "products": prods, "score": round(score, 1), "why": why})
    queue.sort(key=lambda q: q["score"], reverse=True)
    top = queue[:limit]
    return {"found": bool(queue), "status": "ok" if queue else "not_found", "cypher": CYPHER_QUEUE,
            "paths": [f"(Vulnerability:{q['cve']})-[:AFFECTS]->(Component:{p['component']})" for q in top[:6] for p in q["products"][:1]],
            "touched": [f"Vulnerability:{q['cve']}" for q in top[:6]] + [f"Product:{p['product']}" for q in top[:6] for p in q["products"]],
            "data": {"open_vulnerabilities": len(queue),
                     "actively_exploited": sum(q["actively_exploited"] for q in queue),
                     "exposures": sum(len(q["products"]) for q in queue),
                     "queue": top,
                     "ranking": "exploited (CISA KEV) > ransomware use > EU report needed > EPSS > CVSS > products hit"}}


CYPHER_KEV_NEW = """
MATCH (v:Vulnerability) WHERE v.kev_added >= $since
OPTIONAL MATCH (v)-[:AFFECTS]->(:Component)<-[:DEPENDS_ON*0..10]-(:Component)<-[:SHIPS]-(p:Product)
RETURN v.id, v.title, v.vendor, v.kev_product, v.kev_added, v.ransomware, collect(DISTINCT p.name)
ORDER BY v.kev_added DESC
"""


def kev_watch(days=30, **_):
    try:
        days = max(1, min(int(days), 3650))
    except (TypeError, ValueError):
        raise ToolInputError("days must be a number.")
    latest = q("MATCH (v:Vulnerability) WHERE v.kev_added <> '' RETURN max(v.kev_added)")[0][0]
    if not latest:
        return fail("not_found", "The CISA KEV catalog isn't loaded. Run ingest_real.py and setup_db.py.")
    since = (datetime.fromisoformat(latest) - timedelta(days=days)).date().isoformat()
    rows = q(CYPHER_KEV_NEW, {"since": since})
    hits = [{"cve": r[0], "title": r[1], "added": r[4], "products": r[6]} for r in rows if r[6]]
    return {"found": True, "cypher": CYPHER_KEV_NEW,
            "paths": [f"(Vulnerability:{h['cve']})-[:AFFECTS]->(Product:{p})" for h in hits for p in h["products"]],
            "touched": [f"Vulnerability:{h['cve']}" for h in hits] + [f"Product:{p}" for h in hits for p in h["products"]],
            "data": {"catalog_latest_entry": latest, "since": since, "new_entries": len(rows),
                     "affecting_fernwave": hits,
                     "latest": [{"cve": r[0], "title": r[1], "vendor_product": f"{r[2]} {r[3]}", "added": r[4],
                                 "known_ransomware_use": r[5] == "Known"} for r in rows[:8]],
                     "message": None}}
