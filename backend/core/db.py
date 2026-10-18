"""FalkorDB connection, the query helper and input cleaning."""
import logging
import os
import re
from datetime import datetime, timezone

from dotenv import load_dotenv
from falkordb import FalkorDB


load_dotenv()
log = logging.getLogger("plexus")


_db = FalkorDB(
    host=os.getenv("FALKOR_HOST", "localhost"),
    port=int(os.getenv("FALKOR_PORT", "6479")),
    username=os.getenv("FALKOR_USERNAME") or None,
    password=os.getenv("FALKOR_PASSWORD") or None,
)


graph = _db.select_graph(os.getenv("GRAPH_NAME", "plexus"))


MAX_DEPTH = 10  # dependency hops we follow; bounded so a cycle can't run away


def q(cypher, params=None):
    return graph.query(cypher, params or {}).result_set


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ToolInputError(ValueError):
    pass


_DASH = r"[\s_\-‐-―−]*"   # spaces, underscores, every unicode dash


CVE_RE = re.compile(rf"CVE{_DASH}(\d{{4}}){_DASH}(\d{{4,7}})", re.I)


# advisories with no CVE number yet (GitHub, Go, PyPI, RustSec), as OSV names them
ADVISORY_RE = re.compile(r"\b(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|(?:GO|PYSEC|RUSTSEC)-\d{4}-\d+)\b", re.I)


def norm_cve(value):
    """'cve 2023 4863' -> 'CVE-2023-4863'; also accepts advisory IDs like GHSA-xxxx-xxxx-xxxx."""
    text = str(value or "")
    m = CVE_RE.search(text)
    if m:
        return f"CVE-{m[1]}-{m[2]}"
    m = ADVISORY_RE.search(text)
    if m:
        a = m[1]
        return "GHSA" + a[4:].lower() if a.upper().startswith("GHSA") else a.upper()
    raise ToolInputError(f"'{text[:40]}' is not a valid CVE or advisory id (expected CVE-YYYY-NNNN).")


def clean_name(value, field):
    s = " ".join(str(value or "").split())
    if not s:
        raise ToolInputError(f"{field} is empty.")
    if len(s) > 100:
        raise ToolInputError(f"{field} is too long (max 100 characters).")
    return s


def plural(n, word, many=None):
    return f"{n} {word if n == 1 else (many or word + 's')}"


def fail(status, message, cypher="", **extra):
    return {"found": False, "status": status, "cypher": cypher, "paths": [], "touched": [],
            "data": {"message": message, **extra}}


def fmt_path(names, rels, forward):
    """Parallel lists from Cypher -> '(A)-[:R]->(B)<-[:S]-(C)'."""
    out = f"({names[0]})"
    for i, rel in enumerate(rels):
        out += f"-[:{rel}]->" if forward[i] else f"<-[:{rel}]-"
        out += f"({names[i + 1]})"
    return out


PATH_PROJECTION = """
  [n IN nodes(path) | labels(n)[0] + ':' + coalesce(n.id, n.key, n.name, n.title)] AS names,
  [r IN relationships(path) | type(r)] AS rels,
  [i IN range(0, length(path) - 1) | id(startNode(relationships(path)[i])) = id(nodes(path)[i])] AS fwd
"""


def plain_chain(path):
    """'(Vulnerability:X)-[:AFFECTS]->(Component:libwebp@1.3.1)<-...(Product:P)' -> 'libwebp 1.3.1 → … → P'"""
    parts = re.split(r"<-\[:[A-Z_*]+\]-|-\[:[A-Z_*]+\]->", path or "")
    return " → ".join(p.strip("() ").split(":", 1)[-1].replace("@", " ") for p in parts[1:])
