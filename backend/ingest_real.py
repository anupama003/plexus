"""
ingest_real.py - pulls REAL vulnerability data into a local snapshot.

Sources (all public, no API key needed):
  * CISA KEV   - every vulnerability known to be exploited in the wild
                 https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  * OSV.dev    - which advisories affect the exact package versions Fernwave ships
                 https://osv.dev
  * FIRST EPSS - probability that a CVE is exploited in the next 30 days
                 https://www.first.org/epss

Writes backend/data/real_snapshot.json, which setup_db.py loads. The snapshot is
committed, so the demo works offline; re-run this script to refresh it.

    python ingest_real.py            # fetch everything and write the snapshot
    python ingest_real.py --verify   # also check the hand-written seed facts against it
"""
import json
import math
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
OUT = Path(__file__).resolve().parent / "data" / "real_snapshot.json"

# Fernwave's real open-source components, as OSV identifies them.
# (C libraries like libwebp, OpenSSL, Chromium and xz have no package ecosystem in
# OSV, so their links stay hand-mapped in setup_db.py, each with an NVD source.)
OSV_PACKAGES = {
    "pillow@10.0.0":            ("PyPI", "pillow", "10.0.0"),
    "requests@2.31.0":          ("PyPI", "requests", "2.31.0"),
    "urllib3@1.26.17":          ("PyPI", "urllib3", "1.26.17"),
    "electron@25.8.0":          ("npm", "electron", "25.8.0"),
    "sharp@0.32.6":             ("npm", "sharp", "0.32.6"),
    "axios@1.5.0":              ("npm", "axios", "1.5.0"),
    "golang-x-net@0.15.0":      ("Go", "golang.org/x/net", "0.15.0"),
    "golang-x-crypto@0.14.0":   ("Go", "golang.org/x/crypto", "0.14.0"),
    "spring-boot@3.1.3":        ("Maven", "org.springframework.boot:spring-boot", "3.1.3"),
    "netty@4.1.97":             ("Maven", "io.netty:netty-codec-http2", "4.1.97.Final"),
    "jackson-databind@2.13.4":  ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.13.4"),
    "activemq-client@5.18.2":   ("Maven", "org.apache.activemq:activemq-client", "5.18.2"),
    "log4j-core@2.17.1":        ("Maven", "org.apache.logging.log4j:log4j-core", "2.17.1"),
    "log4j-core@2.14.1":        ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
    # added for the larger Fernwave portfolio (mobile, merchant portal, SDK, fraud, data, terminal cloud)
    "okhttp@4.9.0":             ("Maven", "com.squareup.okhttp3:okhttp", "4.9.0"),
    "protobuf-java@3.16.0":     ("Maven", "com.google.protobuf:protobuf-java", "3.16.0"),
    "tomcat-embed-core@9.0.40": ("Maven", "org.apache.tomcat.embed:tomcat-embed-core", "9.0.40"),
    "snakeyaml@1.30":           ("Maven", "org.yaml:snakeyaml", "1.30"),
    "guava@30.0":               ("Maven", "com.google.guava:guava", "30.0-jre"),
    "jquery@3.4.1":             ("npm", "jquery", "3.4.1"),
    "lodash@4.17.20":           ("npm", "lodash", "4.17.20"),
    "moment@2.29.1":            ("npm", "moment", "2.29.1"),
    "express@4.17.1":           ("npm", "express", "4.17.1"),
    "jsonwebtoken@8.5.1":       ("npm", "jsonwebtoken", "8.5.1"),
    "ws@7.4.0":                 ("npm", "ws", "7.4.0"),
    "node-fetch@2.6.0":         ("npm", "node-fetch", "2.6.0"),
    "flask@1.1.2":              ("PyPI", "flask", "1.1.2"),
    "werkzeug@1.0.1":           ("PyPI", "werkzeug", "1.0.1"),
    "jinja2@2.11.2":            ("PyPI", "jinja2", "2.11.2"),
    "numpy@1.21.0":             ("PyPI", "numpy", "1.21.0"),
    "pyyaml@5.3.1":             ("PyPI", "pyyaml", "5.3.1"),
    "cryptography@3.3.1":       ("PyPI", "cryptography", "3.3.1"),
    "sqlalchemy@1.3.23":        ("PyPI", "sqlalchemy", "1.3.23"),
    "next@15.0.3":              ("npm", "next", "15.0.3"),
    "react-server-dom-webpack@19.0.0": ("npm", "react-server-dom-webpack", "19.0.0"),
}


def fetch(url, body=None, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json", "User-Agent": "plexus-ingest/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------------------
# CVSS v3.x base score from a vector string (the official FIRST formula)
# ---------------------------------------------------------------------------
_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
      "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0}}


def _roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))
    except (KeyError, ValueError):
        return None


def _vkey(v):
    """'4.1.100.Final' -> (4, 1, 100); good enough to order fix versions."""
    out = []
    for part in v.replace("-", ".").split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        if num:
            out.append(int(num))
    return tuple(out)


def _fixed_for(record, ecosystem, name, version):
    fixes = []
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] != ecosystem or pkg.get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []):
            fixes += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    later = sorted({f for f in fixes if _vkey(f) > _vkey(version)}, key=_vkey)
    return later[0] if later else None


def _osv_vuln(vid):
    return fetch(OSV_VULN + vid)


def main():
    print("1/3  CISA KEV …", flush=True)
    kev = fetch(KEV_URL)
    keep = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
            "requiredAction", "dueDate", "knownRansomwareCampaignUse", "cwes")
    kev_rows = [{k: v.get(k) for k in keep} for v in kev["vulnerabilities"]]
    print(f"     {len(kev_rows)} exploited vulnerabilities (catalog {kev['catalogVersion']})")

    print("2/3  OSV.dev …", flush=True)
    keys = list(OSV_PACKAGES)
    batch = fetch(OSV_BATCH, {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v}
                                          for e, n, v in (OSV_PACKAGES[k] for k in keys)]})
    ids_by_comp = {k: [x["id"] for x in (res.get("vulns") or [])] for k, res in zip(keys, batch["results"])}
    unique = sorted({i for ids in ids_by_comp.values() for i in ids})
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = dict(zip(unique, pool.map(_osv_vuln, unique)))
    osv = {}
    for comp, ids in ids_by_comp.items():
        eco, name, version = OSV_PACKAGES[comp]
        rows = []
        for vid in ids:
            r = records[vid]
            cves = sorted({a for a in r.get("aliases", []) + r.get("upstream", []) + r.get("related", []) + [r["id"]]
                           if a.startswith("CVE-")})
            vec = next((s["score"] for s in r.get("severity", []) if s.get("type") == "CVSS_V3"), None)
            ref = next((x["url"] for x in r.get("references", []) if x.get("type") == "ADVISORY"), None)
            rows.append({"osv_id": vid, "cve": cves[0] if cves else None, "aliases": cves,
                         "summary": (r.get("summary") or r.get("details") or "")[:300],
                         "cvss_vector": vec, "cvss": cvss3_score(vec) if vec else None,
                         "fixed_in": _fixed_for(r, eco, name, version),
                         "published": (r.get("published") or "")[:10],
                         "url": ref or f"https://osv.dev/vulnerability/{vid}"})
        osv[comp] = rows
        print(f"     {comp:26s} {len(rows):3d} advisories")

    print("3/3  FIRST EPSS …", flush=True)
    cves = sorted({r["cveID"] for r in kev_rows} | {x["cve"] for rows in osv.values() for x in rows if x["cve"]}
                  | {"CVE-2023-4863", "CVE-2014-0160", "CVE-2024-3094"})
    epss, epss_date = {}, None
    for i in range(0, len(cves), 100):
        d = fetch(EPSS_URL + ",".join(cves[i:i + 100]) + "&limit=100")
        for row in d.get("data", []):
            epss[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
            epss_date = row.get("date")
    print(f"     {len(epss)} scores ({epss_date})")

    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {
            "kev": {"url": KEV_URL, "catalogVersion": kev["catalogVersion"], "dateReleased": kev["dateReleased"],
                    "count": len(kev_rows)},
            "osv": {"url": "https://osv.dev", "packages": {k: list(v) for k, v in OSV_PACKAGES.items()},
                    "advisories": len(unique)},
            "epss": {"url": "https://www.first.org/epss", "date": epss_date, "count": len(epss)},
        },
        "kev": kev_rows, "osv": osv, "epss": epss,
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(snapshot, indent=1))
    print(f"Wrote {OUT.relative_to(Path.cwd()) if OUT.is_relative_to(Path.cwd()) else OUT} "
          f"({OUT.stat().st_size // 1024} KB)")
    if "--verify" in sys.argv:
        import setup_db
        setup_db.verify_against(snapshot)


if __name__ == "__main__":
    main()
