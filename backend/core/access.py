"""Roles and permissions. Every tool call and action checks these."""
from .db import q


CYPHER_PERSON = """
MATCH (p:Person)-[:MEMBER_OF]->(t:Team)
WHERE $name IS NULL OR p.name = $name
OPTIONAL MATCH (t)-[:OWNS]->(pr:Product)
RETURN p.name, p.role, p.email, p.oncall, p.access, t.name, collect(pr.name)
ORDER BY p.name
"""


ROLE_PERMS = {
    "psirt_lead":    {"investigate", "draft_report", "prepare_report", "send_report", "remediate_any", "assign_tasks",
                      "dora_assess", "view_audit", "export_sbom"},
    "psirt_analyst": {"investigate", "draft_report", "prepare_report", "assign_tasks", "view_audit", "export_sbom"},
    "eng_manager":   {"investigate", "remediate_team", "assign_tasks", "view_audit", "export_sbom"},
    "engineer":      {"investigate", "remediate_team", "export_sbom"},
    "compliance":    {"investigate", "dora_assess", "view_audit", "export_sbom"},
    "ciso":          {"investigate", "view_audit", "export_sbom"},
    "auditor":       {"view_audit", "export_sbom"},
}


ROLE_LABEL = {"psirt_lead": "Security lead", "psirt_analyst": "Security analyst", "eng_manager": "Engineering manager",
              "engineer": "Engineer", "compliance": "Compliance", "ciso": "CISO", "auditor": "External auditor"}


PERM_LABEL = {"investigate": "Investigate exposure", "draft_report": "Draft EU reports",
              "prepare_report": "Prepare EU reports", "send_report": "Approve and send EU reports",
              "remediate_any": "Mark any fix shipped", "remediate_team": "Mark own team's fixes shipped",
              "dora_assess": "Record DORA assessments", "view_audit": "View the audit timeline",
              "export_sbom": "Export SBOMs", "assign_tasks": "Assign fix tasks"}


def perms(actor):
    return ROLE_PERMS.get((actor or {}).get("access"), set())


def can(actor, perm):
    return perm in perms(actor)


def who_can(perm):
    return [p["name"] for p in people() if perm in ROLE_PERMS.get(p["access"], set())]


def people(name=None):
    return [{"name": n, "role": r, "email": e, "oncall": o, "access": a or "engineer",
             "team": t, "owns": owns, "role_label": ROLE_LABEL.get(a, a),
             "permissions": sorted(ROLE_PERMS.get(a, set()))}
            for n, r, e, o, a, t, owns in q(CYPHER_PERSON, {"name": name})]


def get_person(name):
    found = people(name)
    return found[0] if found else None
