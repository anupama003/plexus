# The Cypher behind plexus

Every answer in plexus comes from one of these queries. Here they are with real values filled in, so you can paste them into the FalkorDB Browser and see the same results the app shows.

**To run them:** start plexus (`docker compose up`), open **http://localhost:3479**, connect to `localhost:6379`, and pick the graph **`plexus`**.

In the app, the values (like the CVE ID) are passed as parameters, never pasted into the query text. Some of the app's versions also return a few extra columns for the UI. The file next to each heading has the exact version.

**Jump to:** [Is a bug in our products?](#1-is-a-bug-in-our-products) · [What do we fix first?](#2-what-do-we-fix-first) · [Who owns and who knows?](#3-who-owns-and-who-knows) · [Graph algorithms](#4-graph-algorithms) · [Incident memory](#5-incident-memory-and-handoffs)

---

## 1. Is a bug in our products?

### Look up a bug
`core/exposure.py · CYPHER_LOOKUP`: the basics, plus which software parts it directly affects.

```cypher
MATCH (v:Vulnerability {id: 'CVE-2023-4863'})
OPTIONAL MATCH (v)-[a:AFFECTS]->(c:Component)
RETURN v.id, v.title, v.cvss, v.exploited, v.kev_added, v.epss, collect(c.key) AS parts
```

### Which products does it reach, and who do we call?
`core/exposure.py · CYPHER_BLAST`: this is the main query. It starts at the bug, follows the dependency chain up to 10 levels, and stops at every product that ships it. For each product it also brings back where it's sold, the owning team and who's on call.

```cypher
MATCH path = (v:Vulnerability {id: 'CVE-2023-4863'})-[a:AFFECTS]->(c0:Component)
             <-[:DEPENDS_ON*0..10]-(:Component)<-[:SHIPS]-(p:Product)
OPTIONAL MATCH (p)-[s:SOLD_IN]->(m:Market)
OPTIONAL MATCH (t:Team)-[:OWNS]->(p)
OPTIONAL MATCH (oc:Person {oncall: true})-[:MEMBER_OF]->(t)
RETURN p.name AS product, length(path) AS steps,
       [n IN nodes(path) | coalesce(n.id, n.key, n.name)] AS chain,
       collect(DISTINCT m.code) AS markets, t.name AS team, collect(DISTINCT oc.name) AS on_call
ORDER BY steps
```

You should get FernPOS T2, Fernwave Desktop and KYC Service. FernPOS T2's chain is `CVE → libwebp 1.3.1 → pillow 10.0.0 → receipt-renderer → pos-ui → FernPOS T2`.

### What if we upgrade a part?
Same query, but the path may not pass through the part we're "upgrading". The app passes it as `$exclude`.

```cypher
MATCH path = (v:Vulnerability {id: 'CVE-2023-4863'})-[:AFFECTS]->(:Component)
             <-[:DEPENDS_ON*0..10]-(:Component)<-[:SHIPS]-(p:Product)
WHERE none(n IN nodes(path) WHERE coalesce(n.key, '') IN ['pillow@10.0.0'])
RETURN DISTINCT p.name
```

Only Fernwave Desktop is left, because Electron bundles its own copy of libwebp inside Chromium. Upgrading Pillow alone isn't enough.

### Is a supplier exposed?
`core/exposure.py · CYPHER_SUPPLIERS`: the same walk, but ending at a supplier that `RUNS` the software instead of a product.

```cypher
MATCH (:Vulnerability {id: 'CVE-2023-34362'})-[:AFFECTS]->(c:Component)
      <-[:DEPENDS_ON*0..10]-(:Component)<-[:RUNS]-(s:Supplier)
OPTIONAL MATCH (owner:Person)-[:MANAGES_SUPPLIER]->(s)
RETURN DISTINCT s.name, s.service, c.key, owner.name
```

MOVEit isn't in any Fernwave product, but the payroll supplier runs it, and Elena owns that contract.

---

## 2. What do we fix first?

### Everything wrong with one product
`core/exposure.py · CYPHER_PRODUCT_VULNS`: the blast radius in reverse. Start at a product and walk down to every vulnerable part inside it.

```cypher
MATCH (p:Product {name: 'FernPOS T2'})-[:SHIPS]->(:Component)-[:DEPENDS_ON*0..10]->(c:Component)<-[a:AFFECTS]-(v:Vulnerability)
RETURN DISTINCT v.id, v.title, v.cvss, v.exploited, c.key, a.fixed_in
ORDER BY v.exploited DESC, v.cvss DESC
```

### The whole fix list
`core/exposure.py · CYPHER_QUEUE`: every bug that reaches any product. The app then ranks it: exploited first, then ransomware, then needs an EU report, then likelihood (EPSS), then severity.

```cypher
MATCH path = (v:Vulnerability)-[:AFFECTS]->(c:Component)<-[:DEPENDS_ON*0..10]-(:Component)<-[:SHIPS]-(p:Product)
RETURN v.id, v.exploited, v.ransomware, v.epss, v.cvss, p.name, min(length(path)) AS steps
ORDER BY v.exploited DESC, v.epss DESC
LIMIT 25
```

### What's new on CISA's list?
`core/exposure.py · CYPHER_KEV_NEW`: recent additions to the exploited list, and whether any reach us.

```cypher
MATCH (v:Vulnerability) WHERE v.kev_added >= '2026-09-01'
OPTIONAL MATCH (v)-[:AFFECTS]->(:Component)<-[:DEPENDS_ON*0..10]-(:Component)<-[:SHIPS]-(p:Product)
RETURN v.id, v.title, v.kev_added, collect(DISTINCT p.name) AS reaches
ORDER BY v.kev_added DESC
```

### What the watcher checks every 15 minutes
`core/memory.py · CYPHER_WATCH`: every exploited bug that reaches a product, and whether that product is sold in the EU. Each row becomes an alert in the Inbox.

```cypher
MATCH (v:Vulnerability {exploited: true})-[:AFFECTS]->(:Component)<-[:DEPENDS_ON*0..10]-(:Component)<-[:SHIPS]-(p:Product)
OPTIONAL MATCH (p)-[:SOLD_IN]->(m:Market {code: 'EU'})
RETURN v.id, v.title, collect(DISTINCT p.name) AS products, count(DISTINCT m) > 0 AS sold_in_eu
```

---

## 3. Who owns and who knows?

### Who owns what
`core/knowledge.py · CYPHER_TEAMS`

```cypher
MATCH (t:Team)
OPTIONAL MATCH (p:Person)-[:MEMBER_OF]->(t)
WITH t, collect(DISTINCT p.name) AS people, collect(DISTINCT CASE WHEN p.oncall THEN p.name END) AS on_call
OPTIONAL MATCH (t)-[:OWNS]->(pr:Product)
RETURN t.name, people, on_call, collect(DISTINCT pr.name) AS products
ORDER BY size(products) DESC
```

### Who knows Pillow?
`core/knowledge.py · _KNOW`: the app runs one small query per kind of evidence and adds up a score (maintaining it counts 5, a commit, doc, ticket or decision counts 3, a chat message 2). Here are three of them together:

```cypher
MATCH (p:Person)-[:MAINTAINS]->(x:Component {key: 'pillow@10.0.0'})
RETURN p.name, 'maintains it' AS evidence
UNION ALL
MATCH (t:Ticket)-[:ABOUT]->(:Component {key: 'pillow@10.0.0'}) MATCH (t)-[:ASSIGNED_TO]->(p:Person)
RETURN p.name, 'ticket ' + t.key + ': ' + t.title AS evidence
UNION ALL
MATCH (m:ChatMessage)-[:MENTIONS]->(:Component {key: 'pillow@10.0.0'}) MATCH (m)-[:POSTED_BY]->(p:Person)
RETURN p.name, 'said in ' + m.channel + ': ' + left(m.text, 60) AS evidence
```

### Why was a decision made?
`core/knowledge.py · CYPHER_DECISIONS`: who decided, when, why, and the document it came from.

```cypher
MATCH (d:Decision {id: 'DEC-007'})-[:DECIDED_BY]->(p:Person)
OPTIONAL MATCH (d)-[:ABOUT]->(x)
OPTIONAL MATCH (d)-[:SOURCE]->(s)
RETURN d.title, d.date, d.rationale, p.name, collect(DISTINCT coalesce(x.key, x.name)) AS about,
       coalesce(s.title, s.key) AS source
```

### Any tickets or chat about something?
`core/knowledge.py · CYPHER_KNOWLEDGE`: tickets, chat, docs and decisions in one list. The app filters it by the words you asked about. This version filters for Electron.

```cypher
MATCH (t:Ticket)-[:ASSIGNED_TO]->(a:Person) WHERE toLower(t.title) CONTAINS 'electron'
RETURN 'ticket' AS kind, t.key AS id, t.title AS text, t.status AS status, a.name AS who
UNION ALL
MATCH (m:ChatMessage)-[:POSTED_BY]->(a:Person) WHERE toLower(m.text) CONTAINS 'electron'
RETURN 'chat' AS kind, m.channel AS id, m.text AS text, '' AS status, a.name AS who
```

---

## 4. Graph algorithms

### The most important parts (PageRank)
`core/knowledge.py · CYPHER_PAGERANK`: parts that many other parts depend on score higher.

```cypher
CALL algo.pageRank('Component', 'DEPENDS_ON') YIELD node, score
RETURN node.key, score ORDER BY score DESC LIMIT 10
```

### The parts everything flows through (betweenness)
`core/knowledge.py · CYPHER_BETWEENNESS`: parts that sit on many paths between other parts and products. If one of these breaks, a lot breaks.

```cypher
CALL algo.betweenness({nodeLabels: ['Component', 'Product'], relationshipTypes: ['DEPENDS_ON', 'SHIPS']})
YIELD node, score
RETURN coalesce(node.key, node.name), score ORDER BY score DESC LIMIT 10
```

### How many products each part ends up in
`core/knowledge.py · CYPHER_FANIN`

```cypher
MATCH (c:Component)
OPTIONAL MATCH (c)<-[:DEPENDS_ON*0..10]-(:Component)<-[:SHIPS]-(p:Product)
WITH c, collect(DISTINCT p.name) AS products
OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS]->(c)
RETURN c.key, size(products) AS in_products, count(DISTINCT v) AS bugs
ORDER BY in_products DESC, bugs DESC LIMIT 10
```

### How are two things connected? (shortest path)
`core/knowledge.py · CYPHER_CONNECTION`: uses FalkorDB's `algo.SPpaths` procedure, which can walk relationships in either direction. Priya *maintains* a part, but the bug *affects* one, so the path has to go both ways.

```cypher
MATCH (a:Person {name: 'Priya Raman'}), (b:Vulnerability {id: 'CVE-2023-4863'})
CALL algo.SPpaths({sourceNode: a, targetNode: b,
                   relTypes: ['DEPENDS_ON', 'AFFECTS', 'SHIPS', 'OWNS', 'MEMBER_OF', 'MAINTAINS'],
                   relDirection: 'both', maxLen: 8, pathCount: 1}) YIELD path
RETURN [n IN nodes(path) | coalesce(n.id, n.key, n.name)] AS chain
```

Priya maintains receipt-renderer, which uses Pillow, which bundles libwebp 1.3.1, which has the bug.

---

## 5. Incident memory and handoffs

These read what people did in the app, so do something first: sign in, check a CVE, and assign the fixes.

### What happened on the latest incident
`core/memory.py · CYPHER_RECALL` (simplified): every incident is a `Session` node, and every action hangs off it.

```cypher
MATCH (s:Session)-[:LOGGED]->(e:Event)
WITH s, e ORDER BY e.ts
RETURN s.id, collect(e.actor + ': ' + e.tool + ' (' + e.status + ')') AS what_happened
ORDER BY s.started DESC LIMIT 1
```

### When did we first know, and who knew?
This is what the 24-hour clock counts from.

```cypher
MATCH (s:Session)-[i:INVESTIGATED]->(v:Vulnerability)
RETURN s.id, v.id, i.first_seen, i.by ORDER BY i.first_seen DESC LIMIT 10
```

### Fix tasks handed to people
`core/workflows.py · CYPHER_TASKS`

```cypher
MATCH (t:Task)-[:ASSIGNED_TO]->(a:Person)
OPTIONAL MATCH (t)-[:TRACKED_IN]->(k:Ticket)
RETURN a.name, t.title, t.status, collect(k.key) AS ticket
ORDER BY t.status DESC
```

### Which open ticket already tracks this fix?
`core/workflows.py · CYPHER_TICKETS_FOR`: used when assigning fixes, so we link the existing ticket instead of opening a duplicate.

```cypher
MATCH (t:Ticket)-[:ABOUT]->(:Product {name: 'FernPOS T2'}) WHERE t.status <> 'done'
MATCH (t)-[:ABOUT]->(:Component)-[:DEPENDS_ON*0..10]->(:Component {key: 'libwebp@1.3.1'})
RETURN DISTINCT t.key, t.title, t.status
```

### How did we fix this last time?
`core/knowledge.py · CYPHER_PAST`: fixes recorded on earlier incidents.

```cypher
MATCH (s:Session)-[r:REMEDIATED]->(p:Product)
RETURN r.cve, p.name, r.by, r.ts, r.note ORDER BY r.ts DESC
```

---

## Things FalkorDB taught me

- **A second `MATCH` after a filtered one needs a `WITH` in between**, or it quietly returns nothing.
- **Not every FalkorDB version supports an undirected `shortestPath`.** `algo.SPpaths` with `relDirection: 'both'` works everywhere, so that's what plexus uses.
- **Put brackets around `+` inside `STARTS WITH`, and around `x IN list` after `NOT`.** `c.key STARTS WITH (n + '@')` and `NOT (c.key IN $list)`. Some versions read them differently without the brackets.
- **`null IN [...]` breaks a `none(...)` filter.** That's why the what-if query uses `coalesce(n.key, '')`.
- **To look nodes up by a list of ids, unwind the list.** `WHERE id(n) IN $list` checks every node; `UNWIND $ids AS x MATCH (n) WHERE id(n) = x` jumps straight to each one. At 124,000 nodes that was the difference between a timeout and 62 ms.
