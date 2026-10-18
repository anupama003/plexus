"""
plexus API.

The chat answers through one of two agents, both limited to the same graph tools:
Gemini choosing tools over MCP (mcp_agent.py), or the rule-based graph agent
(desk_agent.py) when Gemini is busy or not configured.

    uvicorn main:app --port 8042
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from core import access, db, exposure, knowledge, memory, registry, showcase, workflows
import desk_agent
import mcp_agent

load_dotenv()
log = logging.getLogger("plexus")

RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MIN", "120"))  # questions per person per minute
AUTH_SECRET = (os.getenv("AUTH_SECRET") or secrets.token_hex(32)).encode()
FEATURED = ["Mei Tanaka", "Lukas Berger", "Priya Raman", "Arjun Mehta", "Aisha Bello", "Sofia Costa",
            "Elena Rossi", "Daniel Weber", "Sam Okafor"]   # everyone who gets work in the demo can sign in
FRONTEND = Path(__file__).resolve().parent.parent / "frontend"

@asynccontextmanager
async def lifespan(app):
    threading.Thread(target=_watch_loop, daemon=True, name="watcher-agent").start()
    yield


app = FastAPI(title="plexus", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# Demo auth
TOKEN_TTL = int(os.getenv("TOKEN_TTL_HOURS", "12")) * 3600


def make_token(name):
    payload = base64.urlsafe_b64encode(f"{name}\n{int(time.time()) + TOKEN_TTL}".encode()).decode()
    sig = hmac.new(AUTH_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def read_token(token):
    """Signed name + expiry. Tampered, unsigned or expired -> None."""
    try:
        payload, sig = token.split(".", 1)
        good = hmac.new(AUTH_SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        name, exp = base64.urlsafe_b64decode(payload).decode().rsplit("\n", 1)
        return name if int(exp) > time.time() else None
    except (ValueError, UnicodeDecodeError):
        return None


def current_user(authorization: str = Header(default="")):
    name = read_token(authorization.removeprefix("Bearer ").strip()) if authorization else None
    user = access.get_person(name) if name else None
    if not user:
        raise HTTPException(401, "Not signed in (or the session expired). Pick a persona again.")
    return user


# Guard rails: input limits, one request at a time per pane, rate limit
INCIDENT_ID = r"^[A-Za-z0-9_-]{1,64}$"


class ChatIn(BaseModel):
    incident_id: str = Field(pattern=INCIDENT_ID)
    message: str = Field(min_length=1, max_length=2000)
    agent: Literal["graph", "gemini"] = "graph"   # the chat asks for "gemini"; API callers and tests default to graph

    @field_validator("message")
    @classmethod
    def not_blank(cls, v):
        if not v.strip():
            raise ValueError("message is blank")
        return v.strip()


class LoginIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)


LOCKS: dict[tuple, threading.Lock] = defaultdict(threading.Lock)
CALLS: dict[str, deque] = defaultdict(deque)
_registry_lock = threading.Lock()


def _rate_limit(user):
    now, q = time.time(), CALLS[user["name"]]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(429, f"Slow down: {RATE_LIMIT} questions per minute per person.")
    q.append(now)


class _PaneGuard:
    """One in-flight request per (incident, person, pane): a double-click can't
    interleave two answers into the same transcript."""

    def __init__(self, key):
        with _registry_lock:
            self.lock = LOCKS[key]

    def __enter__(self):
        if not self.lock.acquire(blocking=False):
            raise HTTPException(409, "Still answering your previous question in this pane.")

    def __exit__(self, *exc):
        self.lock.release()


# Routes
@app.get("/api/personas")
def personas():
    """Everyone in the graph can sign in. The featured ones come first, in story order."""
    everyone = access.people()
    order = {n: i for i, n in enumerate(FEATURED)}
    for p in everyone:
        p["featured"] = p["name"] in order
    return sorted(everyone, key=lambda p: (order.get(p["name"], 99), p["team"], p["name"]))


@app.post("/api/login")
def login(body: LoginIn):
    user = access.get_person(body.name.strip())
    if not user:
        raise HTTPException(404, f"No person called '{body.name}'.")
    return {"token": make_token(user["name"]), "user": user}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return user


def _trace_item(name, args, out):
    return {"tool": name, "args": args, "status": out["status"], "found": out["found"],
            "paths": out.get("paths") or [], "touched": out.get("touched") or [],
            "message": out["data"].get("message"),
            "reportable": [x["product"] for x in out["data"].get("affected_products") or []
                           if x["cra_verdict"].startswith("CRA REPORTABLE")],
            "evidence": sorted({f"{x['product']}: {x['evidence']}" for x in out["data"].get("affected_products") or []
                                if x.get("evidence")})}


GEMINI_BUSY_UNTIL = 0.0   # after a rate limit, let the graph agent answer for a minute instead of waiting
GEMINI_TIMEOUT = float(os.getenv("GEMINI_TIMEOUT", "10"))   # slower than this, the graph agent answers instead


def _gemini(body, user, trace, done):
    """Gemini picks tools over MCP as this person, on this incident; its calls become the trace.
    done collects each call as it happens, so a fallback can reuse them if Gemini is cut short."""
    turns = memory.load_turns(body.incident_id, user["name"], pane="agent", limit=12)
    history = [(t["role"], t["text"][:2000]) for t in turns]
    answer, calls = asyncio.run(asyncio.wait_for(
        mcp_agent.run(body.message, user["name"], body.incident_id, history=history, verbose=False, patient=False,
                      calls=done),
        GEMINI_TIMEOUT))
    for c in calls:
        trace.append(_trace_item(c["name"], c["args"], c["result"]))
    return answer


def _answer(body, user, trace, done=()):
    def run(name, args):
        # if Gemini already ran this exact call before it was cut short, reuse the result: never do an action twice
        same = lambda a, b: {k: str(v).strip().upper() for k, v in a.items()} == {k: str(v).strip().upper() for k, v in b.items()}
        out = next((c["result"] for c in done if c["name"] == name and same(c["args"], args)), None) \
            or registry.run_tool(name, args, body.incident_id, user)
        trace.append(_trace_item(name, args, out))
        return out
    return desk_agent.answer(body.message, body.incident_id, user, run)


def _need(user, perm):
    if not access.can(user, perm):
        raise HTTPException(403, f"{user['role_label']} access can't do this ({access.PERM_LABEL[perm].lower()}).")


@app.post("/api/agent")
def agent_chat(body: ChatIn, user=Depends(current_user)):
    """Gemini (tools chosen over MCP) answers when asked and available; otherwise the graph agent does."""
    _need(user, "investigate")
    with _PaneGuard((body.incident_id, user["name"], "agent")):
        _rate_limit(user)
        t0 = time.perf_counter()
        global GEMINI_BUSY_UNTIL
        trace, engine, done = [], "graph", []
        if body.agent == "gemini" and mcp_agent.available() and time.time() >= GEMINI_BUSY_UNTIL:
            try:
                answer, engine = _gemini(body, user, trace, done), "gemini"
            except Exception as e:  # noqa: BLE001 - whatever went wrong, the graph agent answers
                while isinstance(e, BaseExceptionGroup) and e.exceptions:
                    e = e.exceptions[0]
                log.warning("Gemini agent failed, graph agent answered: %s: %s", type(e).__name__, str(e)[:200])
                GEMINI_BUSY_UNTIL = time.time() + (60 if isinstance(e, (mcp_agent.GeminiBusy, TimeoutError)) else 300)
                trace = []
        if engine == "graph":
            answer = _answer(body, user, trace, done)
        try:   # conversation memory lives in the graph, per person and incident
            memory.save_turn(body.incident_id, user["name"], "agent", "user", body.message)
            memory.save_turn(body.incident_id, user["name"], "agent", "assistant", answer)
        except Exception:  # noqa: BLE001 - the answer still goes out
            pass
        return {"answer": answer, "trace": trace, "engine": engine, "clock": _clock(body.incident_id),
                "seconds": round(time.perf_counter() - t0, 2)}


def _clock(incident_id):
    """The 24h/72h clock, for exploited CVEs that reach a reportable product (FLAGGED).
    Follows the earliest one whose reports aren't all sent; exploited CVEs with nothing to report never start it."""
    rows = db.q("""
        MATCH (s:Session {id:$sid})-[i:INVESTIGATED]->(v:Vulnerability {exploited:true})
        MATCH (s)-[f:FLAGGED]->(:Product) WHERE f.cve = v.id
        RETURN DISTINCT v.id, i.first_seen, i.by ORDER BY i.first_seen""", {"sid": incident_id})
    if not rows:
        return None
    done = {r["cve"] for r in workflows.reports(incident_id) if r["stage"] == "notification"}
    cve, first_seen, by = next((r for r in rows if r[0] not in done), rows[0])
    aware = datetime.fromisoformat(first_seen)
    return {"cve": cve, "aware": first_seen, "by": by,
            "deadline_24h": (aware + timedelta(hours=24)).isoformat(),
            "deadline_72h": (aware + timedelta(hours=72)).isoformat()}


@app.get("/api/incident/{incident_id}")
def incident(incident_id: str, user=Depends(current_user)):
    if not re.fullmatch(INCIDENT_ID, incident_id):
        raise HTTPException(422, "Bad incident id")
    mem = memory.recall_session(incident_id)["data"]
    return {"incident_id": incident_id, "clock": _clock(incident_id),
            "assessed": mem.get("assessed", []), "investigated": mem.get("investigated", []),
            "reports": workflows.reports(incident_id),
            "pending_reports": [r for r in workflows.reports(incident_id, include_pending=True) if r["status"] != "sent"],
            "remediated": mem.get("remediated", []), "dora": mem.get("dora_assessments", []),
            "events": mem.get("events", [])[-25:]}


# CRA Article 14 filing: pre-filled from the graph, PSIRT reviews and submits
_HTTP = {"denied": 403, "not_found": 404, "not_reportable": 409, "conflict": 409, "invalid": 422, "error": 500,
         "ambiguous": 422}


def _ok(r):
    if r["status"] != "ok":
        raise HTTPException(_HTTP.get(r["status"], 400), r["data"]["message"])
    return r["data"]


class ReportIn(BaseModel):
    fields: dict[str, str] = Field(default_factory=dict)


def _check_ids(incident_id, cve_id):
    if not re.fullmatch(INCIDENT_ID, incident_id) or len(cve_id) > 40:
        raise HTTPException(422, "Bad incident or CVE id")


@app.get("/api/report/{incident_id}/{cve_id}")
def report_form(incident_id: str, cve_id: str, user=Depends(current_user)):
    _check_ids(incident_id, cve_id)
    r = workflows.report_package(cve_id, incident_id, user)
    if r["status"] != "ok":
        raise HTTPException(_HTTP.get(r["status"], 400), r["data"]["message"])
    return {**r["data"], "can_prepare": access.can(user, "prepare_report"),
            "can_send": access.can(user, "send_report"),
            "can_submit": access.can(user, "prepare_report")}


@app.post("/api/report/{incident_id}/{cve_id}/{stage}")
def report_submit(incident_id: str, cve_id: str, stage: str, body: ReportIn, user=Depends(current_user)):
    _check_ids(incident_id, cve_id)
    return _ok(workflows.submit_report(cve_id, stage, body.fields, incident_id, user))


@app.post("/api/report/{incident_id}/{cve_id}/{stage}/approve")
def report_approve(incident_id: str, cve_id: str, stage: str, user=Depends(current_user)):
    _check_ids(incident_id, cve_id)
    return _ok(workflows.approve_report(cve_id, stage, incident_id, user))


# Fixes, DORA assessments, portfolio queue, timeline, SBOMs
class RemediateIn(BaseModel):
    incident_id: str = Field(pattern=INCIDENT_ID)
    cve_id: str = Field(min_length=1, max_length=40)
    product: str = Field(min_length=1, max_length=100)
    note: str = Field(min_length=3, max_length=500)


class DoraIn(BaseModel):
    incident_id: str = Field(pattern=INCIDENT_ID)
    cve_id: str = Field(min_length=1, max_length=40)
    product: str = Field(min_length=1, max_length=100)
    outcome: str = Field(min_length=1, max_length=200)
    note: str = Field(default="", max_length=500)


def _guard(fn, *args):
    try:
        return _ok(fn(*args))
    except db.ToolInputError as e:
        raise HTTPException(422, str(e))


@app.post("/api/remediate")
def remediate(body: RemediateIn, user=Depends(current_user)):
    return _guard(workflows.remediate, body.cve_id, body.product, body.note, body.incident_id, user)


@app.post("/api/dora")
def dora(body: DoraIn, user=Depends(current_user)):
    return _guard(workflows.dora_assess, body.cve_id, body.product, body.outcome, body.note, body.incident_id, user)


@app.get("/api/dora/outcomes")
def dora_outcomes():
    return workflows.DORA_OUTCOMES


@app.get("/api/queue")
def queue(limit: int = 12, user=Depends(current_user)):
    if not (access.can(user, "investigate") or access.can(user, "view_audit")):
        raise HTTPException(403, "No access to the fix queue.")
    return _guard(exposure.fix_queue, limit)


@app.get("/api/products")
def products(user=Depends(current_user)):
    rows = db.q(f"""
        MATCH (p:Product) OPTIONAL MATCH (t:Team)-[:OWNS]->(p)
        OPTIONAL MATCH (p)-[:SHIPS]->(:Component)-[:DEPENDS_ON*0..{db.MAX_DEPTH}]->(:Component)<-[:AFFECTS]-(v:Vulnerability)
        RETURN p.name, p.version, p.category, p.cra_in_scope, t.name,
               count(DISTINCT v), count(DISTINCT CASE WHEN v.exploited THEN v END) ORDER BY p.name""")
    return [{"product": n, "version": v, "category": c, "cra_in_scope": s, "owner_team": t,
             "vulnerabilities": total, "actively_exploited": ex} for n, v, c, s, t, total, ex in rows]


@app.get("/api/sbom/{product}")
def export_sbom(product: str, user=Depends(current_user)):
    _need(user, "export_sbom")
    bom, err = workflows.sbom(product)
    if err:
        _ok(err)
    return JSONResponse(bom, headers={"Content-Disposition": f'attachment; filename="sbom-{bom["metadata"]["component"]["name"].replace(" ", "-")}.cdx.json"'})


@app.get("/api/timeline/{incident_id}")
def incident_timeline(incident_id: str, user=Depends(current_user)):
    _need(user, "view_audit")
    if not re.fullmatch(INCIDENT_ID, incident_id):
        raise HTTPException(422, "Bad incident id")
    return workflows.timeline(incident_id)


@app.get("/api/sources")
def sources():
    """Where the real data came from, and when it was fetched."""
    path = Path(__file__).resolve().parent / "data" / "real_snapshot.json"
    if not path.exists():
        return {"real_data": False}
    snap = json.loads(path.read_text())
    return {"real_data": True, "fetched_at": snap["fetched_at"], **snap["sources"]}


# Memory, handoffs, the watcher agent and company knowledge
class NoteIn(BaseModel):
    channel: str = Field(pattern=r"^#[a-z0-9-]{2,40}$")
    text: str = Field(min_length=3, max_length=1000)


class TasksIn(BaseModel):
    incident_id: str = Field(pattern=INCIDENT_ID)
    cve_id: str = Field(min_length=5, max_length=40)


@app.get("/api/history/{incident_id}")
def history(incident_id: str, user=Depends(current_user)):
    """Your own conversation on this incident. Nobody can read anyone else's."""
    if not re.fullmatch(INCIDENT_ID, incident_id):
        raise HTTPException(422, "Bad incident id")
    return memory.load_turns(incident_id, user["name"], pane="agent")


@app.get("/api/alerts")
def get_alerts(user=Depends(current_user)):
    if not (access.can(user, "investigate") or access.can(user, "view_audit")):
        raise HTTPException(403, "No access to alerts.")
    return memory.alerts()


@app.post("/api/watch")
def run_watcher(user=Depends(current_user)):
    _need(user, "investigate")
    return memory.watch_kev()


@app.get("/api/tasks")
def tasks(user=Depends(current_user)):
    _need(user, "investigate")
    return workflows.my_tasks(actor=user)["data"]


@app.post("/api/tasks")
def assign_tasks(body: TasksIn, user=Depends(current_user)):
    return _ok(registry.run_tool("create_fix_tasks", {"cve_id": body.cve_id}, body.incident_id, user))


@app.post("/api/knowledge")
def add_note(body: NoteIn, user=Depends(current_user)):
    """A chat message, as a Slack webhook would send it. Mentions are linked automatically."""
    return _ok(knowledge.add_knowledge(body.channel, body.text, actor=user))


@app.get("/api/knowledge/status")
def knowledge_status(user=Depends(current_user)):
    return knowledge.knowledge_status()


@app.get("/api/company")
def company():
    """Fernwave at a glance, from the graph, for the landing page."""
    return showcase.company_overview()


@app.get("/api/cases")
def cases():
    """Real incidents replayed against Fernwave's graph, for the landing page."""
    return showcase.replay_cases()


def _watch_loop():
    every = int(os.getenv("WATCH_EVERY_MIN", "15")) * 60
    while True:
        try:
            memory.watch_kev()
        except Exception:  # noqa: BLE001 - the watcher retries on the next tick
            pass
        time.sleep(every)


@app.post("/api/tools/{name}")
def call_tool(name: str, args: dict, user=Depends(current_user)):
    if name not in registry.TOOLS:
        raise HTTPException(404, f"No tool named {name}. Options: {list(registry.TOOLS)}")
    incident_id = str(args.pop("incident_id", "debug"))
    if not re.fullmatch(INCIDENT_ID, incident_id):
        raise HTTPException(422, "Bad incident id")
    return registry.run_tool(name, args, incident_id, user)


@app.get("/api/graph")
def get_graph():
    return showcase.full_graph()


@app.get("/api/health")
def health():
    try:
        nodes, mem = db.q(
            "MATCH (n) RETURN count(CASE WHEN NOT (n:Session OR n:Event OR n:Report OR n:Turn OR n:Task OR n:Alert) THEN 1 END), "
            "count(CASE WHEN n:Session OR n:Event OR n:Report OR n:Turn OR n:Task OR n:Alert THEN 1 END)")[0]
        status = {"ok": True, "nodes": nodes, "memory_nodes": mem}
    except Exception as e:  # noqa: BLE001
        status = {"ok": False, "error": str(e)}
    return {"falkordb": status, "gemini": mcp_agent.available()}


app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


@app.get("/")
def index():
    # the version stamp makes browsers fetch app.js/style.css again after every change
    version = str(int(max((FRONTEND / f).stat().st_mtime for f in ("app.js", "style.css"))))
    page = (FRONTEND / "index.html").read_text().replace("__V__", version)
    return HTMLResponse(page, headers={"Cache-Control": "no-cache"})
