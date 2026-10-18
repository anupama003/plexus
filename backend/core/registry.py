"""The tool menu: what each tool takes, who may call it, and run_tool()."""
import time

from .access import PERM_LABEL, ROLE_LABEL, can, who_can
from .db import ToolInputError, fail, log
from .exposure import blast_radius, component_experts, fix_queue, kev_watch, lookup_vulnerability, product_context, product_vulnerabilities, simulate_patch
from .knowledge import connection, critical_components, decision_trace, past_fixes, search_knowledge, team_directory, who_knows
from .memory import recall_session, remember
from .workflows import create_fix_tasks, draft_report_facts, my_tasks


TOOLS = {
    "lookup_vulnerability": lookup_vulnerability,
    "blast_radius": blast_radius,
    "simulate_patch": simulate_patch,
    "product_context": product_context,
    "component_experts": component_experts,
    "recall_session": recall_session,
    "draft_report_facts": draft_report_facts,
    "product_vulnerabilities": product_vulnerabilities,
    "fix_queue": fix_queue,
    "kev_watch": kev_watch,
    "team_directory": team_directory,
    "who_knows": who_knows,
    "decision_trace": decision_trace,
    "search_knowledge": search_knowledge,
    "critical_components": critical_components,
    "connection": connection,
    "past_fixes": past_fixes,
    "create_fix_tasks": create_fix_tasks,
    "my_tasks": my_tasks,
}


# Permission each tool needs (see ROLE_PERMS). Anything not listed needs "investigate".
TOOL_ACCESS = {"draft_report_facts": "draft_report", "create_fix_tasks": "assign_tasks"}


def _schema(props, required):
    return {"type": "object", "properties": props, "required": required,
            "additionalProperties": False}


_CVE = {"cve_id": {"type": "string", "description": "CVE identifier, e.g. CVE-2023-4863"}}


TOOL_SPECS = [
    {"name": "lookup_vulnerability",
     "description": "Get a CVE's details from the graph: CVSS, whether it is actively exploited "
                    "(CISA KEV), fix version, and which component versions it directly affects.",
     "input_schema": _schema(_CVE, ["cve_id"])},
    {"name": "blast_radius",
     "description": "Traverse Vulnerability -> Component -> (transitive dependencies) -> Product "
                    "to find every affected product, its markets, owning team, on-call engineer, "
                    "and a CRA reportability verdict. Use this to answer 'are we affected?'.",
     "input_schema": _schema(_CVE, ["cve_id"])},
    {"name": "simulate_patch",
     "description": "What-if: if we upgrade one component (e.g. 'pillow', 'electron'), which "
                    "products are fixed and which stay exposed to this CVE? Read-only.",
     "input_schema": _schema({**_CVE, "component_name": {"type": "string"}}, ["cve_id", "component_name"])},
    {"name": "product_context",
     "description": "Company brain for a product: owning team, team members and roles, on-call, "
                    "repos, top committers, runbooks/ADRs/SBOM docs, markets.",
     "input_schema": _schema({"product_name": {"type": "string"}}, ["product_name"])},
    {"name": "component_experts",
     "description": "Who knows a library/component: maintainers, committers, docs, which internal "
                    "components depend on it, and the maintainers of those dependents.",
     "input_schema": _schema({"component_name": {"type": "string"}}, ["component_name"])},
    {"name": "recall_session",
     "description": "Recall this incident's shared memory: CVEs investigated (when and by whom), "
                    "product verdicts, and the audit trail of every tool call by every person.",
     "input_schema": _schema({}, [])},
    {"name": "draft_report_facts",
     "description": "PSIRT only. Collect the verified facts for a CRA Article 14 early warning / "
                    "notification for one CVE: awareness time, 24h/72h deadlines, reportable "
                    "products, PSIRT contact, who investigated, and the evidence trail.",
     "input_schema": _schema(_CVE, ["cve_id"])},
    {"name": "product_vulnerabilities",
     "description": "Everything that affects one product, ranked: exploited first (CISA KEV), then ransomware use, "
                    "EPSS likelihood and CVSS. Use for 'what's wrong with <product>?'.",
     "input_schema": _schema({"product_name": {"type": "string"}}, ["product_name"])},
    {"name": "fix_queue",
     "description": "Portfolio-wide fix priority list across every product: which vulnerabilities to fix first and "
                    "why. Use for 'what should we fix first?' or 'what is our exposure?'.",
     "input_schema": _schema({"limit": {"type": "integer", "description": "1-25, default 10"}}, [])},
    {"name": "kev_watch",
     "description": "What CISA added to its Known Exploited Vulnerabilities list recently, and whether any of it "
                    "affects Fernwave. Use for 'anything new this week/month?'.",
     "input_schema": _schema({"days": {"type": "integer", "description": "look-back window, default 30"}}, [])},
    {"name": "team_directory",
     "description": "Who's who: every team (or one), its members with roles and permission level, who is on call, "
                    "and which products each team owns. Use for 'how many teams', 'who owns what', 'who is on X team'.",
     "input_schema": _schema({"team_name": {"type": "string", "description": "optional, e.g. 'Identity'"}}, [])},
    {"name": "who_knows",
     "description": "Who actually knows a component or product, ranked by evidence in the graph: maintainership, "
                    "commits, docs written, tickets, team chat and decisions. Each fact has its source.",
     "input_schema": _schema({"topic": {"type": "string", "description": "component or product, e.g. 'pillow'"}}, ["topic"])},
    {"name": "decision_trace",
     "description": "Why is something the way it is? Finds recorded decisions, who made them, the rationale and "
                    "the source document or ticket. Use for 'why is KYC out of CRA scope?', 'why do terminals use Pillow?'.",
     "input_schema": _schema({"subject": {"type": "string"}}, ["subject"])},
    {"name": "search_knowledge",
     "description": "Search company knowledge (tickets, team chat, docs, decisions). Returns sources with dates and "
                    "flags stale open tickets. Use when the question is about work in flight or what people said.",
     "input_schema": _schema({"query": {"type": "string"}}, ["query"])},
    {"name": "critical_components",
     "description": "Graph algorithms: which components matter most, using FalkorDB PageRank and betweenness plus how "
                    "many products each one reaches. Use for 'what are our riskiest/most critical parts?'.",
     "input_schema": _schema({"limit": {"type": "integer", "description": "1-25, default 8"}}, [])},
    {"name": "connection",
     "description": "Shortest chain of relationships between any two things in the graph (people, teams, products, "
                    "components, CVEs, tickets, decisions). Use for 'how is X connected to Y?'.",
     "input_schema": _schema({"from_name": {"type": "string"}, "to_name": {"type": "string"}}, ["from_name", "to_name"])},
    {"name": "past_fixes",
     "description": "Procedural memory: how Fernwave fixed this CVE, this library or this product in earlier "
                    "incidents, who did it and what they did. Use for 'have we dealt with this before?'.",
     "input_schema": _schema({"subject": {"type": "string", "description": "CVE, component or product"}}, ["subject"])},
    {"name": "create_fix_tasks",
     "description": "ACTION. For each product this CVE reaches, assign a fix task to the owning team's on-call engineer "
                    "and link existing tickets. Idempotent. Needs the 'assign fix tasks' permission.",
     "input_schema": _schema(_CVE, ["cve_id"])},
    {"name": "my_tasks",
     "description": "The asking user's handoff inbox: fix tasks assigned to them (managers: their team) across incidents.",
     "input_schema": _schema({}, [])},
]


_SPEC_BY_NAME = {s["name"]: s["input_schema"] for s in TOOL_SPECS}


def run_tool(name, args, session_id, actor=None):
    """Validate -> authorise -> execute -> remember. Never raises."""
    t0 = time.perf_counter()
    if name not in TOOLS:
        result = fail("invalid", f"Unknown tool {name}. Options: {list(TOOLS)}")
    else:
        schema = _SPEC_BY_NAME[name]
        args = {k: v for k, v in (args or {}).items() if k in schema["properties"]}
        missing = [k for k in schema["required"] if k not in args]
        needed = TOOL_ACCESS.get(name, "investigate")
        if missing:
            result = fail("invalid", f"Missing argument(s): {', '.join(missing)}")
        elif not can(actor, needed):
            result = fail("denied", f"{(actor or {}).get('name', 'This user')} ({ROLE_LABEL.get((actor or {}).get('access'), 'no role')}) "
                           f"can't do this: it needs the '{PERM_LABEL[needed]}' permission. "
                           f"Ask {', '.join(who_can(needed)) or 'the security team'}.")
        else:
            try:
                result = TOOLS[name](**args, session_id=session_id, actor=actor)
            except ToolInputError as e:
                result = fail("invalid", str(e))
            except Exception as e:  # noqa: BLE001 - a DB hiccup must not crash the agent loop
                log.exception("tool %s failed", name)
                result = fail("error", f"Graph query failed ({type(e).__name__}). Treat this as unknown.")
    result.setdefault("status", "ok" if result["found"] else "not_found")
    result["ms"] = round((time.perf_counter() - t0) * 1000, 1)
    try:
        remember(session_id, name, args, result, actor)
    except Exception:  # noqa: BLE001 - memory is best-effort, the answer still goes out
        log.exception("could not write memory")
    return result
