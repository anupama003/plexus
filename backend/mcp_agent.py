"""
The Gemini agent: Gemini chooses plexus's graph tools over MCP.

For each question it starts mcp_server.py as the signed-in person, lists the tools,
gives their schemas to Gemini, runs the calls Gemini asks for, and loops until Gemini
answers (at most 8 rounds). The chat uses it through main.py; it also runs on its own:

    python mcp_agent.py "Are we affected by CVE-2023-4863, and who should fix it?"
    python mcp_agent.py --as "Priya Raman" "Assign the fixes for CVE-2023-4863"
"""
import argparse
import asyncio
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
# tried in order when a model is overloaded or out of its daily free quota
FALLBACK_MODELS = [m.strip() for m in os.getenv("GEMINI_FALLBACK_MODELS",
                   "gemini-3.5-flash,gemini-3.8-flash,gemini-flash-latest").split(",") if m.strip()]
MAX_ROUNDS = 8

SYSTEM = """You are the plexus agent for Fernwave, an EU fintech. You answer questions about which products a
security bug reaches, who owns and fixes them, whether the EU Cyber Resilience Act requires a report within
24 hours, and what the company knows (tickets, chat, decisions).

Rules:
- You know nothing about Fernwave except what the tools return. Call tools before answering.
- If a tool returns status "not_found", say "Not in Fernwave's data" and what is missing. Never guess.
- If a tool returns "denied", explain who is allowed instead. Never work around it.
- Show how a product gets a bug as a plain chain, e.g. "libwebp 1.3.1 -> Pillow -> receipt-renderer -> FernPOS T2".
  Write versions with a space ("pillow 10.0.0"), never package notation like "pillow@10.0.0".
- Answer in under 150 words, plain language, lead with the answer in one bold line. No code formatting,
  no tool names, no database terms: the reader runs the product, they don't build it.
- You are plexus. Never mention Gemini, Google, AI, models or language models, even if asked what you are."""


def _need_sdk():
    if importlib.util.find_spec("google.genai") is None:
        sys.exit("This agent needs Google's SDK:  pip install -r requirements.txt")


SKIP_UNTIL = {}   # model -> time before which we don't try it (it was out of quota or overloaded)
MUST_THINK = set()   # models that reject thinking_budget=0


class GeminiBusy(RuntimeError):
    """Gemini's rate limit was hit (free tier) and the caller doesn't want to wait."""


async def _generate(client, contents, config, verbose, patient=True, tries=3):
    """Free-tier quotas are per model and per day, so on 429/503 try the next model. If all are out,
    wait (terminal) or raise GeminiBusy at once so the chat can answer with the graph agent."""
    from google.genai import errors, types
    models = [MODEL] + [m for m in FALLBACK_MODELS if m != MODEL]
    # Thinking makes each tool-choosing round several seconds slower and doesn't change which tool is picked.
    fast = config.model_copy(update={"thinking_config": types.ThinkingConfig(thinking_budget=0)})
    for attempt in range(tries):
        ready = [m for m in models if SKIP_UNTIL.get(m, 0) <= time.time()] or models
        for model in ready:
            try:
                return await client.aio.models.generate_content(
                    model=model, contents=contents, config=config if model in MUST_THINK else fast)
            except (errors.ServerError, errors.ClientError) as e:
                if e.code == 400 and "think" in str(e).lower() and model not in MUST_THINK:
                    MUST_THINK.add(model)
                    return await client.aio.models.generate_content(model=model, contents=contents, config=config)
                if e.code not in (429, 503) and not isinstance(e, errors.ServerError):
                    raise
                SKIP_UNTIL[model] = time.time() + (600 if e.code == 429 else 60)   # don't retry it on every request
                if verbose:
                    print(f"  · {model} is {'out of quota' if e.code == 429 else 'overloaded'} ({e.code}); trying the next model")
        if not patient or attempt == tries - 1:
            raise GeminiBusy("every Gemini model is out of quota or overloaded right now")
        wait = 20 * (attempt + 1)
        if verbose:
            print(f"  · all models busy; waiting {wait}s")
        await asyncio.sleep(wait)


def available():
    """Gemini is usable when a key is set and Google's SDK is installed."""
    return bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")) and \
        importlib.util.find_spec("google.genai") is not None


async def run(question, actor, incident, history=(), verbose=True, patient=True, calls=None):
    """Returns (answer, calls). calls = [{"name", "args", "result"}] in the order Gemini chose them.
    history = earlier [(role, text)] turns of this person on this incident, for follow-ups.
    calls, if given, is filled as tools run, so the caller still has them if this is cut short."""
    from google import genai
    from google.genai import types
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not key:
        raise RuntimeError("Put GEMINI_API_KEY=... in backend/.env (free key: https://aistudio.google.com/apikey)")
    client = genai.Client(api_key=key)

    # 1. Start plexus's MCP server, signed in as `actor`, writing to `incident`.
    params = StdioServerParameters(command=sys.executable, args=[str(HERE / "mcp_server.py")], cwd=str(HERE),
                                   env={**os.environ, "MCP_ACTOR": actor, "MCP_INCIDENT": incident})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = (await session.list_tools()).tools
            decls = [types.FunctionDeclaration(name=t.name, description=t.description or "",
                                               parameters_json_schema=getattr(t, "input_schema", None) or t.inputSchema) for t in tools]
            config = types.GenerateContentConfig(
                system_instruction=SYSTEM + f"\nYou are talking to {actor}.",
                tools=[types.Tool(function_declarations=decls)],
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True))
            if verbose:
                print(f"· connected to plexus over MCP as {actor} · {len(tools)} tools · model {MODEL}")

            contents = [types.Content(role="model" if role == "assistant" else "user",
                                      parts=[types.Part.from_text(text=text)]) for role, text in history]
            contents.append(types.Content(role="user", parts=[types.Part.from_text(text=question)]))
            chosen = calls if calls is not None else []
            for _ in range(MAX_ROUNDS):
                response = await _generate(client, contents, config, verbose, patient)
                calls = response.function_calls or []
                if not calls:
                    return response.text or "(no answer)", chosen
                contents.append(response.candidates[0].content)
                parts = []
                for call in calls:
                    args = dict(call.args or {})
                    result = await session.call_tool(call.name, args)
                    payload = json.loads(result.content[0].text) if result.content else {}
                    chosen.append({"name": call.name, "args": args, "result": payload})
                    if verbose:
                        shown = ", ".join(f"{k}={v!r}" for k, v in args.items())
                        print(f"  → Gemini chose {call.name}({shown}) · {payload.get('status')}")
                    # Gemini only needs the facts; queries, node ids and timings stay with us.
                    facts = {k: payload.get(k) for k in ("status", "found", "data", "paths")}
                    parts.append(types.Part.from_function_response(name=call.name, response={"result": facts}))
                contents.append(types.Content(role="user", parts=parts))
            return "Stopped after too many tool calls. Try a narrower question.", chosen


def main():
    ap = argparse.ArgumentParser(description="Gemini selects plexus graph tools over MCP")
    ap.add_argument("question", nargs="*")
    ap.add_argument("--as", dest="actor", default="Mei Tanaka", help="who the agent acts as (permissions apply)")
    ap.add_argument("--incident", default="mcp-gemini", help="incident memory to write to")
    args = ap.parse_args()
    _need_sdk()
    if not available():
        sys.exit("Put GEMINI_API_KEY=... in backend/.env (free key: https://aistudio.google.com/apikey)")
    questions = [" ".join(args.question)] if args.question else None
    while True:
        q = questions.pop(0) if questions else input("\nAsk plexus (empty to quit): ").strip()
        if not q:
            break
        try:
            answer, _ = asyncio.run(run(q, args.actor, args.incident))
        except Exception as e:  # noqa: BLE001 - show API errors (quota, bad key) plainly
            while isinstance(e, BaseExceptionGroup) and e.exceptions:   # MCP's task group wraps the real error
                e = e.exceptions[0]
            answer = f"Gemini error: {type(e).__name__}: {str(e)[:400]}"
        print("\n" + answer)
        if questions is not None and not questions:
            break


if __name__ == "__main__":
    main()
