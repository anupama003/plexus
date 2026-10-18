# Why plexus is built the way it is

These are the choices that shaped plexus, why I made them, and what each one cost.

---

### A graph database, because the question is a graph

"Is this bug in our products?" really means: follow the library to whatever uses it, then whatever uses that, and so on, until you reach something we sell. You don't know how deep that goes. In SQL that's a recursive join you have to tune. In Cypher it's one line: `-[:DEPENDS_ON*0..10]->`. Once the products are found, the next questions (who owns it, where is it sold, who's on call, what did we decide last time) are just more hops from the same nodes.

**The cost:** one more service to run. Docker Compose hides most of that.

### One node for every version of a library

"Affected" is always about an exact version. libwebp 1.3.1 is vulnerable and 1.3.2 isn't. Fernwave Desktop ships the fixed 1.3.2, so a simple check says it's safe, but it's still exposed through the older copy built into Chromium. If a library were a single node, plexus would either miss that or raise false alarms everywhere. With one node per version, it gets both right.

**The cost:** more nodes. At Fernwave's size that doesn't matter, and at 124,000 nodes it still answers in milliseconds.

### The AI picks from a fixed menu. It never writes queries.

I wanted people to ask questions in their own words, but I didn't want a model writing database queries. So every question is answered by one of 19 tools, and each tool is a fixed Cypher query with parameters. Gemini reads the question and chooses which tools to call, over MCP. It can't invent a query, so there's nothing for a prompt injection to get into. Every fact in an answer can be traced back to a tool result.

**The cost:** a new kind of question needs a new tool. I think that's the right price for answers you can trust under a legal deadline.

### Gemini acts as the person who's signed in

When Gemini calls a tool, the MCP server runs it as that person, with their permissions. If Priya (an engineer) asks it to assign fixes for other teams, the tool says no, and Gemini can't talk its way around that because the check isn't in the prompt. The same goes for memory and the audit trail: whatever Gemini does is recorded as Priya's action.

### A plain rule-based agent as a backup

Free AI quotas run out, and models get overloaded. I didn't want the product to stop working when that happens. So there's a second agent with simple rules: it spots CVE numbers, nicknames like "Log4Shell", product and people names, and what you're asking for. If Gemini is busy or takes more than 10 seconds, this one answers instead. The facts are the same because it uses the same 19 tools.

**The cost:** it only understands phrasings it has rules for. Gemini handles everything else.

### Memory lives in the graph, not in the app

Every incident is a small subgraph: who looked at which bug and when, what was decided per product, which reports went out, who shipped which fix. Chat history is stored the same way. That means a restart loses nothing, everyone on the incident sees the same state, and an auditor can read exactly what happened. It also means the 24-hour clock is calculated from a fact in the database ("first seen by Lukas at 14:39"), not from a timer in someone's browser.

**The cost:** each question writes a few small nodes.

### Agents talk through the graph, not to each other

The watcher agent checks CISA's exploited list every 15 minutes and leaves alerts. The chat agents and people read those alerts, and when someone investigates one, it's marked for everyone. Fix tasks work the same way: they're nodes assigned to a person, and shipping the fix closes the task and its ticket. Nobody needs to know who else is running.

### Permissions are checked on the server

The sign-in is a demo (you pick a person), but what each person can do is enforced on every tool call and every action, on the server. Analysts prepare reports and only the security lead sends them. Engineers can only mark their own team's fixes. The browser can be bypassed; the server can't.

### Real vulnerability data, saved as a snapshot

Fernwave is made up, but the bugs aren't. All 1,748 entries on CISA's exploited list, 410 OSV advisories for the exact package versions Fernwave uses, and EPSS scores are downloaded once and saved in the repo. Everyone who runs plexus gets the same results, it works offline, and seeding takes under a second.

**The cost:** the data gets old. `ingest_real.py` refreshes it.

### A depth limit of 10

The dependency walk stops after 10 levels, so a loop in the data can't run forever. Real chains at Fernwave are at most 5 deep.

### One query that returns the proof, for now

The app's main query returns every path from the bug to each product. That's what lets plexus show *how* the bug gets in, not just *that* it does, and it takes a few milliseconds at Fernwave's size. I tested it on a made-up company with 124,000 nodes: the number of possible paths explodes, and 17 out of 30 queries timed out. A level-by-level search that visits each part once took 62 ms there.

**The trade-off:** for a company that big, the app should switch to the level-by-level search and only fetch paths for the products it finds. The test code for that is already in `scale_test.py`.

### What I left out on purpose

- **Real filing to ENISA.** Their reporting platform has no public API yet, so reports are prepared, approved and recorded, and you can download them.
- **Legal certainty.** The CRA and DORA decisions are good rules of thumb, and borderline cases are flagged for a person to decide.
- **Real Jira and Slack connections.** Tickets and chat are seeded, and new messages can be posted to `/api/knowledge`. Connectors are the obvious next step.
