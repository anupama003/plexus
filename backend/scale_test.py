"""
scale_test.py - does the plexus graph model hold up at enterprise size?

Builds a synthetic company in a SEPARATE graph ("plexus_scale", the demo graph is
untouched) with the same schema, then times the same kinds of queries the app runs.

Shape of the synthetic company (defaults):
  * 2,000 products, 300 teams, 3,000 people
  * 40,000 component versions in 8 dependency layers. Low layers are shared
    open-source libraries; popular ones get many dependents (preferential
    attachment), like real ecosystems where a few libraries are everywhere.
  * ~110,000 DEPENDS_ON edges, 5,000 vulnerabilities, ~12,000 AFFECTS edges

    python scale_test.py                      # build + benchmark
    python scale_test.py --components 100000  # bigger
    python scale_test.py --keep               # leave the graph for the FalkorDB Browser
"""
import argparse
import random
import statistics
import time

from falkordb import FalkorDB

import setup_db

LAYERS = 8
ECOSYSTEMS = 6        # npm, PyPI, Maven, Go, NuGet, C: dependencies rarely cross them
MAX_DEPTH = 10


def build(g, n_products, n_components, n_people, n_teams, n_vulns, seed=7):
    rnd = random.Random(seed)
    q = g.query
    try:
        g.delete()
    except Exception:  # noqa: BLE001 - graph did not exist yet
        pass
    for label, prop in [("Component", "key"), ("Product", "name"), ("Vulnerability", "id"), ("Person", "name"), ("Team", "name")]:
        q(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")

    t0 = time.perf_counter()
    # Components in layers: layer 0 = shared low-level libraries, layer 7 = product-specific code.
    per_layer = [n_components // LAYERS] * LAYERS
    comps = [[f"c{layer}-{i}" for i in range(per_layer[layer])] for layer in range(LAYERS)]
    rows = [{"key": k, "layer": layer} for layer in range(LAYERS) for k in comps[layer]]
    for i in range(0, len(rows), 5000):
        q("UNWIND $rows AS r CREATE (:Component {key: r.key, layer: r.layer})", {"rows": rows[i:i + 5000]})

    # Dependencies: each component uses 1-3 parts from lower layers of its own ecosystem (rarely another),
    # popular parts more likely (a heavy tail, like npm/PyPI: a few libraries everywhere, most used rarely).
    eco = lambda layer: {e: [k for i, k in enumerate(comps[layer]) if i % ECOSYSTEMS == e] for e in range(ECOSYSTEMS)}
    by_eco = [eco(layer) for layer in range(LAYERS)]
    weights = {(layer, e): [1.0 / (1 + i) ** 1.2 for i in range(len(by_eco[layer][e]))]
               for layer in range(LAYERS) for e in range(ECOSYSTEMS)}
    deps = set()
    for layer in range(1, LAYERS):
        for i, k in enumerate(comps[layer]):
            for _ in range(rnd.randint(1, 3)):
                e = i % ECOSYSTEMS if rnd.random() > .03 else rnd.randrange(ECOSYSTEMS)
                low = rnd.randint(max(0, layer - 2), layer - 1)
                deps.add((k, rnd.choices(by_eco[low][e], weights[(low, e)])[0]))
    deps = [list(d) for d in deps]
    for i in range(0, len(deps), 10000):
        q("UNWIND $rows AS r MATCH (a:Component {key: r[0]}), (b:Component {key: r[1]}) CREATE (a)-[:DEPENDS_ON]->(b)",
          {"rows": deps[i:i + 10000]})

    # Teams, people, products: each product ships 3-8 top-layer parts and has an owning team.
    q("UNWIND range(0, $n - 1) AS i CREATE (:Team {name: 'team-' + toString(i)})", {"n": n_teams})
    q("""UNWIND range(0, $n - 1) AS i MATCH (t:Team {name: 'team-' + toString(i % $teams)})
         CREATE (:Person {name: 'person-' + toString(i), oncall: i < $teams})-[:MEMBER_OF]->(t)""",
      {"n": n_people, "teams": n_teams})
    q("""UNWIND range(0, $n - 1) AS i MATCH (t:Team {name: 'team-' + toString(i % $teams)})
         CREATE (t)-[:OWNS]->(:Product {name: 'product-' + toString(i)})""", {"n": n_products, "teams": n_teams})
    ships = []
    for p in range(n_products):     # a product is built mostly in one ecosystem
        home = p % ECOSYSTEMS
        for _ in range(rnd.randint(3, 8)):
            e = home if rnd.random() > .2 else rnd.randrange(ECOSYSTEMS)
            ships.append([f"product-{p}", rnd.choice(by_eco[rnd.choice((LAYERS - 1, LAYERS - 2))][e])])
    for i in range(0, len(ships), 10000):
        q("UNWIND $rows AS r MATCH (p:Product {name: r[0]}), (c:Component {key: r[1]}) MERGE (p)-[:SHIPS]->(c)",
          {"rows": ships[i:i + 10000]})

    # Vulnerabilities, mostly in shared low-level libraries (where the real ones live).
    q("UNWIND range(0, $n - 1) AS i CREATE (:Vulnerability {id: 'SCALE-' + toString(i), exploited: i % 20 = 0})", {"n": n_vulns})
    affects = []
    for v in range(n_vulns):
        for _ in range(rnd.randint(1, 4)):
            layer, e = min(int(rnd.expovariate(0.8)), LAYERS - 1), rnd.randrange(ECOSYSTEMS)
            affects.append([f"SCALE-{v}", rnd.choices(by_eco[layer][e], weights[(layer, e)])[0]])
    for i in range(0, len(affects), 10000):
        q("UNWIND $rows AS r MATCH (v:Vulnerability {id: r[0]}), (c:Component {key: r[1]}) CREATE (v)-[:AFFECTS]->(c)",
          {"rows": affects[i:i + 10000]})
    load_s = time.perf_counter() - t0
    nodes = q("MATCH (n) RETURN count(n)").result_set[0][0]
    edges = q("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
    return nodes, edges, load_s


# The same shape as the app's blast radius: reach every product a CVE touches through any
# depth of dependencies, and keep the owning team and on-call person.
BLAST_REACH = f"""
MATCH (:Vulnerability {{id: $id}})-[:AFFECTS]->(c:Component)
MATCH (c)<-[:DEPENDS_ON*0..{MAX_DEPTH}]-(:Component)<-[:SHIPS]-(p:Product)
WITH DISTINCT p
OPTIONAL MATCH (t:Team)-[:OWNS]->(p)
OPTIONAL MATCH (oc:Person {{oncall: true}})-[:MEMBER_OF]->(t)
RETURN count(DISTINCT p), count(DISTINCT oc)
"""


def blast_bfs(g, vid, max_depth=MAX_DEPTH):
    """Level-by-level search up the dependency graph: each component is visited once, so the
    cost grows with the size of the graph, not with the number of possible paths."""
    frontier = [r[0] for r in g.query("MATCH (:Vulnerability {id:$id})-[:AFFECTS]->(c) RETURN id(c)", {"id": vid}).result_set]
    seen = set(frontier)
    for _ in range(max_depth):
        if not frontier:
            break
        # UNWIND + id(c) = x lets FalkorDB seek each node directly instead of scanning every component
        nxt = [r[0] for r in g.query("""UNWIND $f AS x MATCH (c) WHERE id(c) = x WITH c
                                         MATCH (c)<-[:DEPENDS_ON]-(u:Component) RETURN DISTINCT id(u)""",
                                      {"f": frontier}).result_set]
        frontier = [n for n in nxt if n not in seen]
        seen.update(frontier)
    return g.query("""UNWIND $ids AS x MATCH (c) WHERE id(c) = x WITH c
                      MATCH (p:Product)-[:SHIPS]->(c)
                      WITH DISTINCT p
                      OPTIONAL MATCH (t:Team)-[:OWNS]->(p)
                      OPTIONAL MATCH (oc:Person {oncall: true})-[:MEMBER_OF]->(t)
                      RETURN count(DISTINCT p), count(DISTINCT oc)""", {"ids": list(seen)}).result_set


PAGERANK = "CALL algo.pageRank('Component', 'DEPENDS_ON') YIELD node, score RETURN node.key, score ORDER BY score DESC LIMIT 10"
SHORTEST = f"""
MATCH (a:Person {{name: $person}}), (b:Vulnerability {{id: $id}})
CALL algo.SPpaths({{sourceNode: a, targetNode: b, relTypes: ['MEMBER_OF', 'OWNS', 'SHIPS', 'DEPENDS_ON', 'AFFECTS'],
                   relDirection: 'both', maxLen: {MAX_DEPTH + 4}, pathCount: 1}}) YIELD path
RETURN length(path)
"""


def timed(g, cypher, params=None, runs=1):
    out, times = None, []
    for _ in range(runs):
        t0 = time.perf_counter()
        out = g.query(cypher, params or {}).result_set
        times.append((time.perf_counter() - t0) * 1000)
    return out, times


def benchmark(g, samples=30, seed=11):
    rnd = random.Random(seed)
    # Pick CVEs that hit popular libraries (the worst case for a graph walk) and some typical ones.
    hot = [r[0] for r in g.query("""MATCH (v:Vulnerability)-[:AFFECTS]->(c:Component {layer: 0})
                                    RETURN DISTINCT v.id LIMIT 200""").result_set]
    ids = rnd.sample(hot, min(samples // 2, len(hot))) + [f"SCALE-{rnd.randrange(5000)}" for _ in range(samples // 2)]
    reach, times, bfs_times, timeouts = [], [], [], 0
    for vid in ids:
        t0 = time.perf_counter()
        rows = blast_bfs(g, vid)
        bfs_times.append((time.perf_counter() - t0) * 1000)
        reach.append(rows[0][0])
        try:                                   # the single-query form, for comparison
            _, t = timed(g, BLAST_REACH, {"id": vid})
            times.append(t[0])
        except Exception:  # noqa: BLE001 - FalkorDB's default 1 s query timeout
            timeouts += 1
    _, pr = timed(g, PAGERANK)
    sp_times = []
    for vid in ids[:10]:
        _, t = timed(g, SHORTEST, {"person": f"person-{rnd.randrange(300)}", "id": vid})
        sp_times.append(t[0])
    pct = lambda xs, q: sorted(xs)[max(0, int(len(xs) * q) - 1)] if xs else float("nan")
    return {"bfs_median": statistics.median(bfs_times), "bfs_p95": pct(bfs_times, .95), "bfs_max": max(bfs_times),
            "var_median": statistics.median(times) if times else float("nan"), "var_p95": pct(times, .95),
            "var_timeouts": timeouts, "samples": len(ids), "products_reached_median": statistics.median(reach),
            "products_reached_max": max(reach), "pagerank_ms": pr[0], "shortest_ms_median": statistics.median(sp_times)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--products", type=int, default=2000)
    ap.add_argument("--components", type=int, default=40000)
    ap.add_argument("--people", type=int, default=3000)
    ap.add_argument("--teams", type=int, default=300)
    ap.add_argument("--vulns", type=int, default=5000)
    ap.add_argument("--keep", action="store_true", help="keep the scale graph after the run")
    args = ap.parse_args()

    g = FalkorDB(host=setup_db.FALKOR_HOST, port=setup_db.FALKOR_PORT, username=setup_db.FALKOR_USERNAME,
                 password=setup_db.FALKOR_PASSWORD).select_graph("plexus_scale")   # never the demo graph

    print(f"Building a synthetic company: {args.products:,} products, {args.components:,} component versions, "
          f"{args.people:,} people, {args.vulns:,} vulnerabilities …", flush=True)
    nodes, edges, load_s = build(g, args.products, args.components, args.people, args.teams, args.vulns)
    print(f"  loaded {nodes:,} nodes and {edges:,} edges in {load_s:.1f} s")
    print("Benchmarking the app's queries …", flush=True)
    r = benchmark(g)
    print(f"""
  Blast radius (CVE -> every product, any depth, with owner and on-call), {r['samples']} CVEs
      products reached: median {r['products_reached_median']:.0f}, max {r['products_reached_max']:,}
      breadth-first search (each part visited once)   median {r['bfs_median']:.1f} ms · p95 {r['bfs_p95']:.1f} ms · max {r['bfs_max']:.1f} ms
      single variable-length query (all paths)        median {r['var_median']:.1f} ms · p95 {r['var_p95']:.1f} ms · timed out {r['var_timeouts']}/{r['samples']}
  PageRank over all component versions          {r['pagerank_ms']:.0f} ms
  Shortest path person -> CVE (median)          {r['shortest_ms_median']:.1f} ms
""")
    if not args.keep:
        g.delete()
        print("Removed the 'plexus_scale' graph (use --keep to explore it in the FalkorDB Browser).")


if __name__ == "__main__":
    main()
