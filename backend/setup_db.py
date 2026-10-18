"""
setup_db.py - seeds the plexus graph in FalkorDB.

Two kinds of data go in:

  REAL (from data/real_snapshot.json, produced by ingest_real.py)
    * every vulnerability on CISA's Known Exploited Vulnerabilities list (KEV)
    * every OSV.dev advisory that affects the exact package versions Fernwave ships,
      which become the AFFECTS links, each one carrying its OSV advisory ID
    * FIRST EPSS exploitation probabilities
  CURATED (hand-written below, each link citing a public source)
    * C libraries with no package ecosystem in OSV (libwebp, OpenSSL, Chromium, xz)
    * friendly titles and "what users should do" for the six headline CVEs

  FICTIONAL
    * Fernwave (an EU fintech), its products, teams, people, repos and docs

Run:  python setup_db.py          (wipes and re-seeds the graph, then verifies curated facts)
"""
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

FALKOR_HOST = os.getenv("FALKOR_HOST", "localhost")
FALKOR_PORT = int(os.getenv("FALKOR_PORT", "6479"))
FALKOR_PASSWORD = os.getenv("FALKOR_PASSWORD") or None
FALKOR_USERNAME = os.getenv("FALKOR_USERNAME") or None
GRAPH_NAME = os.getenv("GRAPH_NAME", "plexus")
SNAPSHOT = Path(__file__).resolve().parent / "data" / "real_snapshot.json"
CASES = Path(__file__).resolve().parent / "data" / "cases.json"

# --------------------------------------------------------------------------
# 1. CURATED VULNERABILITIES: friendly text for the headline CVEs. Whether each
#    one is exploited (and since when) is overwritten from the real KEV feed.
# --------------------------------------------------------------------------
VULNERABILITIES = [
    {"id": "CVE-2023-4863", "title": "libwebp heap buffer overflow (WebP lossless decoder)", "cvss": 8.8,
     "exploited": True, "kev_added": "2023-09-13", "fixed_in": "libwebp 1.3.2",
     "summary": "A crafted WebP image triggers a heap overflow in BuildHuffmanTable. Exploited in the wild in "
                "zero-click chains. Anything that decodes untrusted WebP with libwebp < 1.3.2 is exposed, "
                "including bundled copies.",
     "user_mitigation": "Install the update that bundles libwebp 1.3.2 or later. Until then, do not open untrusted WebP images."},
    {"id": "CVE-2014-0160", "title": "Heartbleed - OpenSSL TLS heartbeat memory disclosure", "cvss": 7.5,
     "exploited": True, "kev_added": "2022-05-04", "fixed_in": "OpenSSL 1.0.1g",
     "summary": "A malformed TLS heartbeat makes the server leak up to 64 KB of memory per request: private keys, "
                "session data, card data in transit. OpenSSL 1.0.1 to 1.0.1f.",
     "user_mitigation": "Install terminal firmware with OpenSSL 1.0.1g or later, then rotate TLS keys and certificates."},
    {"id": "CVE-2023-46604", "title": "Apache ActiveMQ OpenWire remote code execution", "cvss": 9.8,
     "exploited": True, "kev_added": "2023-11-02", "fixed_in": "ActiveMQ 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3",
     "summary": "Unauthenticated attackers send a crafted OpenWire message that makes the broker instantiate "
                "arbitrary classes. Used by ransomware groups within days.",
     "user_mitigation": "Upgrade the broker and block the OpenWire port (61616) from untrusted networks."},
    {"id": "CVE-2023-44487", "title": "HTTP/2 Rapid Reset denial of service", "cvss": 7.5,
     "exploited": True, "kev_added": "2023-10-10", "fixed_in": "netty 4.1.100.Final, golang.org/x/net 0.17.0",
     "summary": "Clients open and instantly cancel HTTP/2 streams, exhausting server resources. Used in "
                "record-breaking DDoS attacks.",
     "user_mitigation": "Apply vendor patches and rate-limit HTTP/2 stream resets at the edge."},
    {"id": "CVE-2021-44228", "title": "Log4Shell - JNDI lookup remote code execution in log4j-core", "cvss": 10.0,
     "exploited": True, "kev_added": "2021-12-10", "fixed_in": "log4j-core 2.17.1",
     "summary": "Attacker-controlled log messages trigger JNDI lookups and remote code execution. "
                "log4j-core 2.0-beta9 to 2.14.1 is affected.",
     "user_mitigation": "Upgrade log4j-core to 2.17.1 or later. As a stopgap, remove the JndiLookup class."},
    {"id": "CVE-2024-3094", "title": "xz-utils / liblzma backdoor", "cvss": 10.0,
     "exploited": False, "kev_added": "", "fixed_in": "xz-utils 5.6.2 (or downgrade to 5.4.x)",
     "summary": "Malicious code shipped in the xz-utils 5.6.0 and 5.6.1 tarballs. Caught before broad rollout; "
                "no confirmed exploitation in the wild.",
     "user_mitigation": "Downgrade xz-utils to 5.4.x or upgrade to 5.6.2 or later."},
]

# A Component is one *version* of a part. Same library, different version = different node.
COMPONENTS = [
    # key,                         name,                  version,        ecosystem
    ("libwebp@1.3.1",              "libwebp",             "1.3.1",        "c"),
    ("libwebp@1.3.2",              "libwebp",             "1.3.2",        "c"),
    ("pillow@10.0.0",              "Pillow",              "10.0.0",       "pypi"),
    ("receipt-renderer@2.4.0",     "receipt-renderer",    "2.4.0",        "internal"),
    ("pos-ui@3.1.0",               "pos-ui",              "3.1.0",        "internal"),
    ("pos-os@4.2.0",               "pos-os",              "4.2.0",        "internal"),
    ("openssl@1.0.1e",             "openssl",             "1.0.1e",       "c"),
    ("kyc-imaging@1.9.0",          "kyc-imaging",         "1.9.0",        "internal"),
    ("requests@2.31.0",            "requests",            "2.31.0",       "pypi"),
    ("urllib3@1.26.17",            "urllib3",             "1.26.17",      "pypi"),
    ("chromium@114",               "chromium",            "114.0.5735",   "c++"),
    ("electron@25.8.0",            "electron",            "25.8.0",       "npm"),
    ("sharp@0.32.6",               "sharp",               "0.32.6",       "npm"),
    ("libvips@8.14.5",             "libvips",             "8.14.5",       "c"),
    ("axios@1.5.0",                "axios",               "1.5.0",        "npm"),
    ("openbanking-gateway@2.7.0",  "openbanking-gateway", "2.7.0",        "internal"),
    ("golang-x-net@0.15.0",        "golang.org/x/net",    "0.15.0",       "go"),
    ("golang-x-crypto@0.14.0",     "golang.org/x/crypto", "0.14.0",       "go"),
    ("spring-boot@3.1.3",          "spring-boot",         "3.1.3",        "maven"),
    ("netty@4.1.97",               "netty-codec-http2",   "4.1.97.Final", "maven"),
    ("jackson-databind@2.13.4",    "jackson-databind",    "2.13.4",       "maven"),
    ("activemq-client@5.18.2",     "activemq-client",     "5.18.2",       "maven"),
    ("log4j-core@2.17.1",          "log4j-core",          "2.17.1",       "maven"),
    ("log4j-core@2.14.1",          "log4j-core",          "2.14.1",       "maven"),
    ("pos-os-next@5.0.0-rc1",      "pos-os-next",         "5.0.0-rc1",    "internal"),
    ("debian-base@sid-2024-03",    "debian-base-image",   "sid-2024-03",  "oci"),
    ("xz-utils@5.6.1",             "xz-utils",            "5.6.1",        "deb"),
    ("kyc-portal@3.2.0",           "kyc-portal",          "3.2.0",        "internal"),
    ("next@15.0.3",                "next",                "15.0.3",       "npm"),
    ("react-server-dom-webpack@19.0.0", "react-server-dom-webpack", "19.0.0", "npm"),
    ("moveit-transfer@2023.0.0",   "MOVEit Transfer",     "2023.0.0",     "vendor"),
    # the wider portfolio: mobile, merchant portal, SDK, fraud, data, terminal cloud
    ("fernwave-android@7.4.0",     "fernwave-android",    "7.4.0",        "internal"),
    ("okhttp@4.9.0",               "okhttp",              "4.9.0",        "maven"),
    ("protobuf-java@3.16.0",       "protobuf-java",       "3.16.0",       "maven"),
    ("guava@30.0",                 "guava",               "30.0-jre",     "maven"),
    ("merchant-portal-web@4.2.0",  "merchant-portal-web", "4.2.0",        "internal"),
    ("merchant-portal-api@4.2.0",  "merchant-portal-api", "4.2.0",        "internal"),
    ("jquery@3.4.1",               "jquery",              "3.4.1",        "npm"),
    ("lodash@4.17.20",             "lodash",              "4.17.20",      "npm"),
    ("moment@2.29.1",              "moment",              "2.29.1",       "npm"),
    ("express@4.17.1",             "express",             "4.17.1",       "npm"),
    ("jsonwebtoken@8.5.1",         "jsonwebtoken",        "8.5.1",        "npm"),
    ("fernpay-js@2.1.0",           "fernpay-js",          "2.1.0",        "internal"),
    ("ws@7.4.0",                   "ws",                  "7.4.0",        "npm"),
    ("node-fetch@2.6.0",           "node-fetch",          "2.6.0",        "npm"),
    ("fraud-model-service@3.0.0",  "fraud-model-service", "3.0.0",        "internal"),
    ("flask@1.1.2",                "flask",               "1.1.2",        "pypi"),
    ("werkzeug@1.0.1",             "werkzeug",            "1.0.1",        "pypi"),
    ("jinja2@2.11.2",              "jinja2",              "2.11.2",       "pypi"),
    ("numpy@1.21.0",               "numpy",               "1.21.0",       "pypi"),
    ("pyyaml@5.3.1",               "pyyaml",              "5.3.1",        "pypi"),
    ("dw-ingest@1.8.0",            "dw-ingest",           "1.8.0",        "internal"),
    ("cryptography@3.3.1",         "cryptography",        "3.3.1",        "pypi"),
    ("sqlalchemy@1.3.23",          "sqlalchemy",          "1.3.23",       "pypi"),
    ("fleet-manager@2.3.0",        "fleet-manager",       "2.3.0",        "internal"),
    ("tomcat-embed-core@9.0.40",   "tomcat-embed-core",   "9.0.40",       "maven"),
    ("snakeyaml@1.30",             "snakeyaml",           "1.30",         "maven"),
]

# Suppliers: third-party ICT services Fernwave depends on. DORA makes financial
# entities keep a register of these and assess incidents that start there.
SUPPLIERS = [
    # name,                                 service,                         data it holds,                              contact,                         DORA critical, contract owner
    ("Paylane HR (fictional payroll provider)", "Payroll for all Fernwave staff", "staff names, bank details, tax IDs",
     "security@paylane.example", True, "Elena Rossi"),
]
SUPPLIER_RUNS = [("Paylane HR (fictional payroll provider)", "moveit-transfer@2023.0.0")]

# cra_in_scope: is this a "product with digital elements placed on the market"?
# Services (SaaS) generally aren't; for a financial entity they fall under DORA.
PRODUCTS = [
    ("FernPOS T2", "fw 4.2.0", "hardware+firmware", True,
     "Card payment terminal sold to merchants. A product with digital elements under the CRA."),
    ("Fernwave Desktop", "5.3.1", "desktop software", True,
     "Electron treasury app for business customers, downloadable in the EU and UK."),
    ("KYC Service", "2026.10", "SaaS", False,
     "Identity-verification service that processes customers' ID photos. A service, not a product "
     "placed on the market, so generally outside the CRA. As a financial entity, Fernwave handles it "
     "under DORA's ICT-risk rules: tell Compliance."),
    ("Open Banking API", "v3", "SaaS", False,
     "PSD2 API for third-party providers. A service, so generally outside the CRA. DORA applies: tell Compliance."),
    ("Payments Core", "2026.10", "internal platform", False,
     "Internal settlement platform, never placed on the market. Outside the CRA. DORA applies: tell Compliance."),
    ("Legacy Merchant Gateway", "1.9", "on-prem appliance", True,
     "End-of-sale 2024. Still supported for US bank customers only."),
    ("FernPOS T3", "fw 5.0.0-rc1", "hardware+firmware", True,
     "Next-generation terminal. Release candidate, not yet placed on the market."),
    ("Fernwave Mobile", "7.4.0", "mobile app", True,
     "Business banking app on Android, distributed through EU and UK app stores. A product with digital elements under the CRA."),
    ("Merchant Portal", "2026.10", "SaaS", False,
     "Web portal where merchants manage terminals, payouts and disputes. A service: DORA applies, not the CRA."),
    ("Fernwave Pay SDK", "2.1.0", "developer SDK", True,
     "JavaScript SDK merchants embed in their own checkout pages. Distributed software, so a product under the CRA."),
    ("Fraud Scoring Engine", "2026.10", "internal platform", False,
     "Scores every card payment for fraud risk. Internal, never placed on the market: DORA applies."),
    ("Data Warehouse", "2026.10", "internal platform", False,
     "Reporting and regulatory data store. Internal: DORA applies."),
    ("FernPOS Cloud", "2.3.0", "SaaS", False,
     "Fleet management for FernPOS terminals: updates, configuration, monitoring. A service: DORA applies."),
]

MARKETS = [("EU", "European Union"), ("UK", "United Kingdom"), ("US", "United States")]

TEAMS = [
    ("Terminals", "#team-terminals"), ("Desktop", "#team-desktop"), ("Identity", "#team-identity"),
    ("Platform", "#team-platform"), ("PSIRT", "#psirt"), ("Compliance", "#compliance"),
    ("Security Leadership", "#security-leads"), ("External Audit", "#audit-guests"),
    ("Mobile", "#team-mobile"), ("Merchant Web", "#team-merchant-web"), ("Risk", "#team-risk"),
    ("Developer Platform", "#team-devplatform"), ("Data", "#team-data"),
]

# `access` is the permission level (see ROLE_PERMS in core/access.py).
PEOPLE = [
    # name,            email,                 role,                          team,                 oncall, access
    ("Priya Raman",    "priya@fernwave.eu",   "Staff Engineer",              "Terminals",           True,  "engineer"),
    ("Tomasz Wójcik",  "tomasz@fernwave.eu",  "Firmware Engineer",           "Terminals",           False, "engineer"),
    ("Arjun Mehta",    "arjun@fernwave.eu",   "Senior Engineer",             "Desktop",             True,  "engineer"),
    ("Lena Fischer",   "lena@fernwave.eu",    "Engineering Manager",         "Desktop",             False, "eng_manager"),
    ("Aisha Bello",    "aisha@fernwave.eu",   "Senior Engineer",             "Identity",            True,  "engineer"),
    ("Sofia Costa",    "sofia@fernwave.eu",   "Platform Lead",               "Platform",            True,  "eng_manager"),
    ("Kwame Mensah",   "kwame@fernwave.eu",   "SRE",                         "Platform",            False, "engineer"),
    ("Mei Tanaka",     "mei@fernwave.eu",     "PSIRT Lead / CRA contact",    "PSIRT",               True,  "psirt_lead"),
    ("Lukas Berger",   "lukas@fernwave.eu",   "PSIRT Analyst",               "PSIRT",               False, "psirt_analyst"),
    ("Elena Rossi",    "elena@fernwave.eu",   "Head of Compliance (DORA)",   "Compliance",          False, "compliance"),
    ("Daniel Weber",   "daniel@fernwave.eu",  "CISO",                        "Security Leadership", False, "ciso"),
    ("Sam Okafor",     "sam@auditfirm.example", "External auditor",          "External Audit",      False, "auditor"),
    ("Chiara Bianchi", "chiara@fernwave.eu",  "Mobile Lead",                 "Mobile",              False, "eng_manager"),
    ("Mateusz Nowak",  "mateusz@fernwave.eu", "Android Engineer",            "Mobile",              True,  "engineer"),
    ("Inès Laurent",   "ines@fernwave.eu",    "Senior Frontend Engineer",    "Merchant Web",        True,  "engineer"),
    ("Bram de Vries",  "bram@fernwave.eu",    "Engineering Manager",         "Merchant Web",        False, "eng_manager"),
    ("Freya Lindqvist", "freya@fernwave.eu",  "Staff ML Engineer",           "Risk",                True,  "engineer"),
    ("Omar Haddad",    "omar@fernwave.eu",    "Backend Engineer",            "Risk",                False, "engineer"),
    ("Niamh Byrne",    "niamh@fernwave.eu",   "SDK Engineer",                "Developer Platform",  True,  "engineer"),
    ("Pedro Alves",    "pedro@fernwave.eu",   "Developer Platform Lead",     "Developer Platform",  False, "eng_manager"),
    ("Katarzyna Zielińska", "katarzyna@fernwave.eu", "Data Engineer",        "Data",                True,  "engineer"),
    ("Hugo Martin",    "hugo@fernwave.eu",    "Analytics Engineer",          "Data",                False, "engineer"),
    ("Lars Jensen",    "lars@fernwave.eu",    "SRE",                         "Platform",            False, "engineer"),
    ("Elif Demir",     "elif@fernwave.eu",    "Cloud Engineer",              "Terminals",           False, "engineer"),
]

REPOS = [
    ("fernwave/pos-firmware", "https://git.fernwave.eu/pos-firmware"),
    ("fernwave/receipt-renderer", "https://git.fernwave.eu/receipt-renderer"),
    ("fernwave/desktop", "https://git.fernwave.eu/desktop"),
    ("fernwave/kyc-service", "https://git.fernwave.eu/kyc-service"),
    ("fernwave/payments-core", "https://git.fernwave.eu/payments-core"),
    ("fernwave/openbanking-gateway", "https://git.fernwave.eu/openbanking-gateway"),
    ("fernwave/android", "https://git.fernwave.eu/android"),
    ("fernwave/merchant-portal", "https://git.fernwave.eu/merchant-portal"),
    ("fernwave/pay-sdk-js", "https://git.fernwave.eu/pay-sdk-js"),
    ("fernwave/fraud-engine", "https://git.fernwave.eu/fraud-engine"),
    ("fernwave/data-warehouse", "https://git.fernwave.eu/data-warehouse"),
    ("fernwave/fernpos-cloud", "https://git.fernwave.eu/fernpos-cloud"),
]

DOCS = [
    ("Runbook: OTA firmware rollout for FernPOS terminals", "runbook", "https://wiki.fernwave.eu/terminals/ota-rollout", "Priya Raman"),
    ("ADR-021: Why terminals render merchant logos on-device", "adr", "https://wiki.fernwave.eu/adr/021", "Tomasz Wójcik"),
    ("Runbook: shipping an Electron security release", "runbook", "https://wiki.fernwave.eu/desktop/electron-hotfix", "Arjun Mehta"),
    ("Runbook: emergency patch for the KYC image pipeline", "runbook", "https://wiki.fernwave.eu/identity/kyc-hotfix", "Aisha Bello"),
    ("Runbook: HTTP/2 and broker hardening on the platform edge", "runbook", "https://wiki.fernwave.eu/platform/edge-hardening", "Sofia Costa"),
    ("SBOM: FernPOS T2 fw 4.2.0 (CycloneDX)", "sbom", "https://sbom.fernwave.eu/fernpos-t2-4.2.0.json", "Priya Raman"),
    ("PSIRT playbook: CRA Art. 14 and DORA reporting", "policy", "https://wiki.fernwave.eu/psirt/cra-dora", "Mei Tanaka"),
    ("CRA scoping memo: which Fernwave offerings are products", "policy", "https://wiki.fernwave.eu/compliance/cra-scope", "Elena Rossi"),
    ("Runbook: Android hotfix release via staged rollout", "runbook", "https://wiki.fernwave.eu/mobile/hotfix", "Mateusz Nowak"),
    ("Runbook: merchant portal emergency deploy", "runbook", "https://wiki.fernwave.eu/merchant-web/emergency", "Inès Laurent"),
    ("SDK release and npm deprecation policy", "policy", "https://wiki.fernwave.eu/devplatform/sdk-releases", "Niamh Byrne"),
    ("Runbook: patching and redeploying the fraud engine", "runbook", "https://wiki.fernwave.eu/risk/fraud-engine", "Freya Lindqvist"),
    ("Runbook: FernPOS Cloud maintenance windows", "runbook", "https://wiki.fernwave.eu/terminals/cloud", "Elif Demir"),
]

# --------------------------------------------------------------------------
# COMPANY KNOWLEDGE (fictional): tickets, team chat, decisions. Linked to the
# products, parts and people they are about, so the agent can answer "who
# knows", "why", and "what's already in flight" with a source.
# --------------------------------------------------------------------------
TICKETS = [
    # key,        title,                                                         status,        created,      updated,      reporter,       assignee,        about (labels:keys)
    ("TERM-142", "Upgrade Pillow in receipt-renderer to 10.0.1 or later", "open", "2026-09-20", "2026-10-02", "Priya Raman", "Tomasz Wójcik",
     [("Component", "pillow@10.0.0"), ("Component", "receipt-renderer@2.4.0"), ("Product", "FernPOS T2")]),
    ("TERM-131", "Replace end-of-life OpenSSL 1.0.1e in pos-os", "open", "2026-06-03", "2026-09-11", "Tomasz Wójcik", "Tomasz Wójcik",
     [("Component", "openssl@1.0.1e"), ("Component", "pos-os@4.2.0"), ("Product", "FernPOS T2")]),
    ("DESK-88", "Bump Electron to 25.8.4+ for Chromium security fixes", "in progress", "2026-09-28", "2026-10-14", "Lena Fischer", "Arjun Mehta",
     [("Component", "electron@25.8.0"), ("Product", "Fernwave Desktop")]),
    ("ID-57", "Reject WebP uploads at the edge until Pillow is upgraded", "open", "2026-10-01", "2026-10-01", "Aisha Bello", "Aisha Bello",
     [("Component", "kyc-imaging@1.9.0"), ("Component", "pillow@10.0.0"), ("Product", "KYC Service")]),
    ("PLAT-301", "Upgrade activemq-client to 5.18.3 in Payments Core", "open", "2026-07-22", "2026-09-30", "Sofia Costa", "Kwame Mensah",
     [("Component", "activemq-client@5.18.2"), ("Product", "Payments Core")]),
    ("PLAT-288", "Rate-limit HTTP/2 RST_STREAM floods at the edge", "done", "2023-10-10", "2023-10-12", "Sofia Costa", "Sofia Costa",
     [("Product", "Open Banking API"), ("Product", "Payments Core"), ("Component", "netty@4.1.97")]),
    ("MOB-412", "Upgrade OkHttp to 4.12 in the Android app", "open", "2026-08-14", "2026-08-20", "Chiara Bianchi", "Mateusz Nowak",
     [("Component", "okhttp@4.9.0"), ("Component", "fernwave-android@7.4.0"), ("Product", "Fernwave Mobile")]),
    ("WEB-233", "Remove jQuery 3.4 from the merchant portal's dispute pages", "in progress", "2026-09-30", "2026-10-12", "Bram de Vries", "Inès Laurent",
     [("Component", "jquery@3.4.1"), ("Component", "merchant-portal-web@4.2.0"), ("Product", "Merchant Portal")]),
    ("SDK-77", "Drop node-fetch 2.6.0 from the Pay SDK", "open", "2026-10-05", "2026-10-05", "Pedro Alves", "Niamh Byrne",
     [("Component", "node-fetch@2.6.0"), ("Component", "fernpay-js@2.1.0"), ("Product", "Fernwave Pay SDK")]),
    ("RISK-19", "Upgrade Flask and Werkzeug in the fraud scoring service", "open", "2026-07-01", "2026-07-15", "Omar Haddad", "Freya Lindqvist",
     [("Component", "werkzeug@1.0.1"), ("Component", "fraud-model-service@3.0.0"), ("Product", "Fraud Scoring Engine")]),
    ("CLOUD-58", "Upgrade embedded Tomcat in FernPOS Cloud", "open", "2026-10-10", "2026-10-15", "Priya Raman", "Elif Demir",
     [("Component", "tomcat-embed-core@9.0.40"), ("Component", "fleet-manager@2.3.0"), ("Product", "FernPOS Cloud")]),
]

CHATS = [
    # id,     channel,           author,          ts,                    text,                                                                                                   mentions
    ("m1", "#team-terminals", "Priya Raman", "2026-09-18T10:12:00Z",
     "Reminder: receipt-renderer still pulls Pillow 10.0.0 because of the merchant-logo scaler. Upgrade tracked in TERM-142.",
     [("Component", "pillow@10.0.0"), ("Component", "receipt-renderer@2.4.0")]),
    ("m2", "#team-terminals", "Tomasz Wójcik", "2026-09-11T15:40:00Z",
     "pos-os on the T2 still ships OpenSSL 1.0.1e. The T3 moves to pos-os-next, so don't expect a T2 fix before Q1.",
     [("Component", "openssl@1.0.1e"), ("Product", "FernPOS T2"), ("Product", "FernPOS T3")]),
    ("m3", "#team-desktop", "Arjun Mehta", "2026-10-14T09:05:00Z",
     "Electron 25 goes end-of-life soon. DESK-88 gets us to 25.8.4 now; planning the jump to 27 next sprint.",
     [("Component", "electron@25.8.0"), ("Product", "Fernwave Desktop")]),
    ("m4", "#psirt", "Mei Tanaka", "2026-09-01T08:30:00Z",
     "Process reminder: anything actively exploited in a product sold in the EU gets a 24h early warning. Lukas prepares, I approve and send.",
     []),
    ("m5", "#compliance", "Elena Rossi", "2026-08-29T13:20:00Z",
     "KYC Service, Open Banking API and Payments Core are services, so DORA applies, not the CRA. Details in the CRA scoping memo.",
     [("Product", "KYC Service"), ("Product", "Open Banking API"), ("Product", "Payments Core")]),
    ("m6", "#team-platform", "Sofia Costa", "2023-10-12T17:02:00Z",
     "Rapid Reset is mitigated at the edge (PLAT-288). netty under spring-boot is still 4.1.97; the real upgrade comes with spring-boot 3.2.",
     [("Component", "netty@4.1.97"), ("Product", "Payments Core")]),
    ("m7", "#team-identity", "Aisha Bello", "2026-10-01T11:47:00Z",
     "kyc-imaging decodes every uploaded ID photo with Pillow, including WebP. ID-57 blocks WebP uploads as a stopgap.",
     [("Component", "kyc-imaging@1.9.0"), ("Component", "pillow@10.0.0"), ("Product", "KYC Service")]),
    ("m8", "#team-merchant-web", "Inès Laurent", "2026-10-12T10:00:00Z",
     "jQuery 3.4 is still in the portal's legacy dispute pages. WEB-233 removes it; the new pages don't use it.",
     [("Component", "jquery@3.4.1"), ("Product", "Merchant Portal")]),
    ("m9", "#team-devplatform", "Niamh Byrne", "2026-10-05T09:30:00Z",
     "Merchants pin our SDK for months. Any fix in fernpay-js needs a deprecation notice on npm, not just a new version.",
     [("Product", "Fernwave Pay SDK"), ("Component", "fernpay-js@2.1.0")]),
    ("m10", "#team-risk", "Freya Lindqvist", "2026-07-15T16:20:00Z",
     "The fraud engine can't take Flask 2 until the model server is refactored. RISK-19 tracks it.",
     [("Product", "Fraud Scoring Engine"), ("Component", "flask@1.1.2")]),
    ("m11", "#team-terminals", "Elif Demir", "2026-10-15T08:45:00Z",
     "FernPOS Cloud still runs embedded Tomcat 9.0.40. CLOUD-58 bumps it; it needs a maintenance window with merchants.",
     [("Product", "FernPOS Cloud"), ("Component", "tomcat-embed-core@9.0.40")]),
    ("m12", "#team-mobile", "Mateusz Nowak", "2026-08-20T14:10:00Z",
     "The OkHttp upgrade is blocked on the certificate-pinning rewrite. Tracked in MOB-412.",
     [("Product", "Fernwave Mobile"), ("Component", "okhttp@4.9.0")]),
]

DECISIONS = [
    # id,        title,                                                                          date,        decided_by,     rationale,                                                                                          about,                                                       source (label, key)
    ("DEC-007", "KYC Service, Open Banking API and Payments Core are services: DORA, not CRA", "2026-08-29", "Elena Rossi",
     "They are run by Fernwave as online services and never placed on the market as products, so the CRA's product rules don't apply. As a financial entity Fernwave handles them under DORA.",
     [("Product", "KYC Service"), ("Product", "Open Banking API"), ("Product", "Payments Core")], ("Doc", "CRA scoping memo: which Fernwave offerings are products")),
    ("DEC-011", "Card terminals render merchant logos on-device", "2025-11-04", "Tomasz Wójcik",
     "Receipts must print offline, so logo scaling happens on the terminal. That brought Pillow (and its bundled libwebp) into the T2 firmware.",
     [("Component", "receipt-renderer@2.4.0"), ("Component", "pillow@10.0.0"), ("Product", "FernPOS T2")], ("Doc", "ADR-021: Why terminals render merchant logos on-device")),
    ("DEC-014", "Security analysts prepare EU reports; only the PSIRT lead sends them", "2026-09-01", "Mei Tanaka",
     "Four-eyes check before anything goes to ENISA, without slowing down the 24h early warning.",
     [], ("Doc", "PSIRT playbook: CRA Art. 14 and DORA reporting")),
    ("DEC-016", "Legacy Merchant Gateway: US-only support until end of life, no EU sales", "2024-12-10", "Sofia Costa",
     "The appliance can't be brought up to EU requirements economically; remaining customers are US banks.",
     [("Product", "Legacy Merchant Gateway")], ("Ticket", "PLAT-288")),
    ("DEC-019", "Fernwave Pay SDK is a product under the CRA", "2026-09-12", "Elena Rossi",
     "Merchants download it and run it in their own checkouts, so Fernwave places it on the market as software. Exploited bugs in it must be reported within 24 hours.",
     [("Product", "Fernwave Pay SDK")], ("Doc", "CRA scoping memo: which Fernwave offerings are products")),
    ("DEC-021", "Mobile releases ramp over 7 days, except security fixes", "2026-05-20", "Chiara Bianchi",
     "Security fixes go to 100% of users within 24 hours; everything else ramps over 7 days to limit blast radius.",
     [("Product", "Fernwave Mobile")], ("Doc", "Runbook: Android hotfix release via staged rollout")),
]

# --------------------------------------------------------------------------
# PAST INCIDENTS (procedural memory): how Fernwave fixed things before.
# --------------------------------------------------------------------------
PAST_INCIDENTS = [
    # incident,              started,      cve,              who,            fixes: (product, note, by, ts)
    ("INC-2021-LOG4SHELL", "2021-12-11T07:00:00+00:00", "CVE-2021-44228", "Sofia Costa", [
        ("Payments Core", "Upgraded log4j-core to 2.17.1 across Payments Core (PLAT-112) and redeployed all pods.", "Sofia Costa", "2021-12-20T18:00:00+00:00"),
        ("Legacy Merchant Gateway", "Removed the JndiLookup class from the appliance image as a mitigation; US customers patched over two weeks.", "Kwame Mensah", "2022-01-05T12:00:00+00:00"),
    ]),
    ("INC-2023-RAPIDRESET", "2023-10-10T09:00:00+00:00", "CVE-2023-44487", "Sofia Costa", [
        ("Open Banking API", "Mitigated at the edge by rate-limiting RST_STREAM floods (PLAT-288); Go x/net upgrade scheduled.", "Sofia Costa", "2023-10-12T17:00:00+00:00"),
    ]),
]

# --------------------------------------------------------------------------
# 2. EDGES
# --------------------------------------------------------------------------
# Hand-mapped links for C libraries OSV can't match by package. Each cites its source.
CURATED_AFFECTS = [
    # cve,             component,          fixed in,       source
    ("CVE-2023-4863",  "libwebp@1.3.1",    "1.3.2",        "https://nvd.nist.gov/vuln/detail/CVE-2023-4863"),
    ("CVE-2023-4863",  "chromium@114",     "116.0.5845.187", "https://nvd.nist.gov/vuln/detail/CVE-2023-4863"),
    ("CVE-2014-0160",  "openssl@1.0.1e",   "1.0.1g",       "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"),
    ("CVE-2024-3094",  "xz-utils@5.6.1",   "5.6.2",        "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"),
    ("CVE-2025-55182", "react-server-dom-webpack@19.0.0", "19.0.1", "https://nvd.nist.gov/vuln/detail/CVE-2025-55182"),
    ("CVE-2023-34362", "moveit-transfer@2023.0.0", "2023.0.1", "https://nvd.nist.gov/vuln/detail/CVE-2023-34362"),
]
# Used only when no snapshot exists (offline first run): the OSV links for the headline CVEs.
FALLBACK_AFFECTS = [
    ("CVE-2023-46604", "activemq-client@5.18.2", "5.18.3", "https://osv.dev/vulnerability/GHSA-crg9-44h2-xw35"),
    ("CVE-2023-44487", "netty@4.1.97", "4.1.100.Final", "https://osv.dev/vulnerability/GHSA-xpw8-rcwv-8f8p"),
    ("CVE-2023-44487", "golang-x-net@0.15.0", "0.17.0", "https://osv.dev/vulnerability/GO-2023-2102"),
    ("CVE-2021-44228", "log4j-core@2.14.1", "2.15.0", "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q"),
]

DEPENDS_ON = [
    ("pillow@10.0.0", "libwebp@1.3.1"),
    ("receipt-renderer@2.4.0", "pillow@10.0.0"),
    ("pos-ui@3.1.0", "receipt-renderer@2.4.0"),
    ("pos-os@4.2.0", "openssl@1.0.1e"),
    ("kyc-imaging@1.9.0", "pillow@10.0.0"),
    ("kyc-imaging@1.9.0", "requests@2.31.0"),
    ("requests@2.31.0", "urllib3@1.26.17"),
    ("electron@25.8.0", "chromium@114"),
    ("sharp@0.32.6", "libvips@8.14.5"),           # sharp 0.32.6 shipped the libwebp fix
    ("libvips@8.14.5", "libwebp@1.3.2"),
    ("openbanking-gateway@2.7.0", "golang-x-net@0.15.0"),
    ("openbanking-gateway@2.7.0", "golang-x-crypto@0.14.0"),
    ("spring-boot@3.1.3", "netty@4.1.97"),
    ("pos-os-next@5.0.0-rc1", "debian-base@sid-2024-03"),
    ("debian-base@sid-2024-03", "xz-utils@5.6.1"),
    ("kyc-portal@3.2.0", "next@15.0.3"),
    ("next@15.0.3", "react-server-dom-webpack@19.0.0"),
    ("fernwave-android@7.4.0", "okhttp@4.9.0"), ("fernwave-android@7.4.0", "protobuf-java@3.16.0"),
    ("fernwave-android@7.4.0", "guava@30.0"),
    ("merchant-portal-web@4.2.0", "jquery@3.4.1"), ("merchant-portal-web@4.2.0", "lodash@4.17.20"),
    ("merchant-portal-web@4.2.0", "moment@2.29.1"),
    ("merchant-portal-api@4.2.0", "express@4.17.1"), ("merchant-portal-api@4.2.0", "jsonwebtoken@8.5.1"),
    ("merchant-portal-api@4.2.0", "lodash@4.17.20"),
    ("fernpay-js@2.1.0", "axios@1.5.0"), ("fernpay-js@2.1.0", "ws@7.4.0"), ("fernpay-js@2.1.0", "node-fetch@2.6.0"),
    ("fraud-model-service@3.0.0", "flask@1.1.2"), ("flask@1.1.2", "werkzeug@1.0.1"), ("flask@1.1.2", "jinja2@2.11.2"),
    ("fraud-model-service@3.0.0", "numpy@1.21.0"), ("fraud-model-service@3.0.0", "pyyaml@5.3.1"),
    ("fraud-model-service@3.0.0", "requests@2.31.0"),
    ("dw-ingest@1.8.0", "sqlalchemy@1.3.23"), ("dw-ingest@1.8.0", "cryptography@3.3.1"), ("dw-ingest@1.8.0", "pyyaml@5.3.1"),
    ("fleet-manager@2.3.0", "tomcat-embed-core@9.0.40"), ("fleet-manager@2.3.0", "snakeyaml@1.30"),
    ("fleet-manager@2.3.0", "guava@30.0"), ("fleet-manager@2.3.0", "jackson-databind@2.13.4"),
]

SHIPS = [
    ("FernPOS T2", "pos-ui@3.1.0"), ("FernPOS T2", "pos-os@4.2.0"),
    ("Fernwave Desktop", "electron@25.8.0"), ("Fernwave Desktop", "sharp@0.32.6"), ("Fernwave Desktop", "axios@1.5.0"),
    ("KYC Service", "kyc-imaging@1.9.0"), ("KYC Service", "kyc-portal@3.2.0"),
    ("Open Banking API", "openbanking-gateway@2.7.0"),
    ("Payments Core", "spring-boot@3.1.3"), ("Payments Core", "activemq-client@5.18.2"),
    ("Payments Core", "log4j-core@2.17.1"), ("Payments Core", "jackson-databind@2.13.4"),
    ("Legacy Merchant Gateway", "log4j-core@2.14.1"),
    ("FernPOS T3", "pos-os-next@5.0.0-rc1"),
    ("Fernwave Mobile", "fernwave-android@7.4.0"),
    ("Merchant Portal", "merchant-portal-web@4.2.0"), ("Merchant Portal", "merchant-portal-api@4.2.0"),
    ("Fernwave Pay SDK", "fernpay-js@2.1.0"), ("Fraud Scoring Engine", "fraud-model-service@3.0.0"),
    ("Data Warehouse", "dw-ingest@1.8.0"), ("FernPOS Cloud", "fleet-manager@2.3.0"),
]

SOLD_IN = [
    ("FernPOS T2", "EU", ["NL", "DE", "BE", "FR"]),
    ("Fernwave Desktop", "EU", ["NL", "DE", "FR", "ES", "IT", "IE"]),
    ("Fernwave Desktop", "UK", []),
    ("KYC Service", "EU", ["NL", "DE", "FR", "ES", "IT", "IE"]),
    ("Open Banking API", "EU", ["NL", "DE", "FR", "ES", "IT", "IE"]),
    ("Payments Core", "EU", ["NL"]),
    ("Legacy Merchant Gateway", "US", []),
    ("Fernwave Mobile", "EU", ["NL", "DE", "FR", "ES", "IT", "IE", "BE"]), ("Fernwave Mobile", "UK", []),
    ("Merchant Portal", "EU", ["NL", "DE", "BE", "FR"]),
    ("Fernwave Pay SDK", "EU", ["NL", "DE", "FR", "ES", "IT", "IE"]), ("Fernwave Pay SDK", "UK", []), ("Fernwave Pay SDK", "US", []),
    ("Fraud Scoring Engine", "EU", ["NL"]), ("Data Warehouse", "EU", ["NL"]),
    ("FernPOS Cloud", "EU", ["NL", "DE", "BE", "FR"]),
]

OWNS = [
    ("Terminals", "FernPOS T2"), ("Terminals", "FernPOS T3"), ("Desktop", "Fernwave Desktop"),
    ("Identity", "KYC Service"), ("Platform", "Open Banking API"), ("Platform", "Payments Core"),
    ("Platform", "Legacy Merchant Gateway"), ("Mobile", "Fernwave Mobile"), ("Merchant Web", "Merchant Portal"),
    ("Developer Platform", "Fernwave Pay SDK"), ("Risk", "Fraud Scoring Engine"), ("Data", "Data Warehouse"),
    ("Terminals", "FernPOS Cloud"),
]

MAINTAINS = [
    ("Priya Raman", "receipt-renderer@2.4.0"), ("Tomasz Wójcik", "pos-ui@3.1.0"), ("Tomasz Wójcik", "pos-os@4.2.0"),
    ("Tomasz Wójcik", "pos-os-next@5.0.0-rc1"), ("Arjun Mehta", "electron@25.8.0"), ("Aisha Bello", "kyc-imaging@1.9.0"), ("Aisha Bello", "kyc-portal@3.2.0"),
    ("Sofia Costa", "spring-boot@3.1.3"), ("Sofia Costa", "openbanking-gateway@2.7.0"), ("Kwame Mensah", "activemq-client@5.18.2"),
    ("Mateusz Nowak", "fernwave-android@7.4.0"), ("Inès Laurent", "merchant-portal-web@4.2.0"),
    ("Bram de Vries", "merchant-portal-api@4.2.0"), ("Niamh Byrne", "fernpay-js@2.1.0"),
    ("Freya Lindqvist", "fraud-model-service@3.0.0"), ("Katarzyna Zielińska", "dw-ingest@1.8.0"),
    ("Elif Demir", "fleet-manager@2.3.0"),
]

BUILDS = [
    ("fernwave/pos-firmware", "Product", "FernPOS T2"), ("fernwave/pos-firmware", "Product", "FernPOS T3"),
    ("fernwave/receipt-renderer", "Component", "receipt-renderer@2.4.0"),
    ("fernwave/kyc-service", "Component", "kyc-portal@3.2.0"),
    ("fernwave/desktop", "Product", "Fernwave Desktop"), ("fernwave/kyc-service", "Product", "KYC Service"),
    ("fernwave/payments-core", "Product", "Payments Core"), ("fernwave/openbanking-gateway", "Product", "Open Banking API"),
    ("fernwave/android", "Product", "Fernwave Mobile"), ("fernwave/merchant-portal", "Product", "Merchant Portal"),
    ("fernwave/pay-sdk-js", "Product", "Fernwave Pay SDK"), ("fernwave/fraud-engine", "Product", "Fraud Scoring Engine"),
    ("fernwave/data-warehouse", "Product", "Data Warehouse"), ("fernwave/fernpos-cloud", "Product", "FernPOS Cloud"),
]

COMMITTED_TO = [
    ("Tomasz Wójcik", "fernwave/pos-firmware", 340), ("Priya Raman", "fernwave/receipt-renderer", 212),
    ("Priya Raman", "fernwave/pos-firmware", 87), ("Arjun Mehta", "fernwave/desktop", 501),
    ("Lena Fischer", "fernwave/desktop", 44), ("Aisha Bello", "fernwave/kyc-service", 260),
    ("Sofia Costa", "fernwave/payments-core", 389), ("Sofia Costa", "fernwave/openbanking-gateway", 150),
    ("Kwame Mensah", "fernwave/payments-core", 120), ("Lars Jensen", "fernwave/payments-core", 75),
    ("Mateusz Nowak", "fernwave/android", 410), ("Chiara Bianchi", "fernwave/android", 95),
    ("Inès Laurent", "fernwave/merchant-portal", 380), ("Bram de Vries", "fernwave/merchant-portal", 120),
    ("Niamh Byrne", "fernwave/pay-sdk-js", 290), ("Pedro Alves", "fernwave/pay-sdk-js", 60),
    ("Freya Lindqvist", "fernwave/fraud-engine", 330), ("Omar Haddad", "fernwave/fraud-engine", 210),
    ("Katarzyna Zielińska", "fernwave/data-warehouse", 270), ("Hugo Martin", "fernwave/data-warehouse", 150),
    ("Elif Demir", "fernwave/fernpos-cloud", 240), ("Priya Raman", "fernwave/fernpos-cloud", 40),
]

DOCUMENTS = [
    ("Runbook: OTA firmware rollout for FernPOS terminals", "Product", "FernPOS T2"),
    ("SBOM: FernPOS T2 fw 4.2.0 (CycloneDX)", "Product", "FernPOS T2"),
    ("ADR-021: Why terminals render merchant logos on-device", "Component", "receipt-renderer@2.4.0"),
    ("Runbook: shipping an Electron security release", "Product", "Fernwave Desktop"),
    ("Runbook: emergency patch for the KYC image pipeline", "Product", "KYC Service"),
    ("Runbook: HTTP/2 and broker hardening on the platform edge", "Product", "Open Banking API"),
    ("Runbook: HTTP/2 and broker hardening on the platform edge", "Product", "Payments Core"),
    ("Runbook: Android hotfix release via staged rollout", "Product", "Fernwave Mobile"),
    ("Runbook: merchant portal emergency deploy", "Product", "Merchant Portal"),
    ("SDK release and npm deprecation policy", "Product", "Fernwave Pay SDK"),
    ("Runbook: patching and redeploying the fraud engine", "Product", "Fraud Scoring Engine"),
    ("Runbook: FernPOS Cloud maintenance windows", "Product", "FernPOS Cloud"),
]


# --------------------------------------------------------------------------
# 3. Merge real + curated into the final dataset
# --------------------------------------------------------------------------
def load_snapshot():
    return json.loads(SNAPSHOT.read_text()) if SNAPSHOT.exists() else None


def build(snapshot=None):
    """Everything that goes into the graph, as plain lists. Used by seed() and validate.py."""
    snap = snapshot if snapshot is not None else load_snapshot()
    vulns = {}

    def vuln(vid, **props):
        v = vulns.setdefault(vid, {"id": vid, "title": vid, "cvss": None, "cvss_vector": None, "exploited": False,
                                   "kev_added": "", "fixed_in": "", "summary": "", "user_mitigation": "",
                                   "vendor": "", "kev_product": "", "ransomware": "", "kev_due": "",
                                   "required_action": "", "epss": None, "epss_pct": None, "sources": [], "url": ""})
        for k, val in props.items():
            if k == "sources":
                v["sources"] = sorted(set(v["sources"]) | set(val))
            elif val not in (None, "") and (v.get(k) in (None, "", False, vid) or k in ("exploited",)):
                v[k] = val
        return v

    affects = []
    if snap:
        for r in snap["kev"]:
            vuln(r["cveID"], title=r["vulnerabilityName"], exploited=True, kev_added=r["dateAdded"],
                 summary=r["shortDescription"], vendor=r["vendorProject"], kev_product=r["product"],
                 ransomware=r["knownRansomwareCampaignUse"], kev_due=r["dueDate"], required_action=r["requiredAction"],
                 sources=["CISA KEV"], url=f"https://nvd.nist.gov/vuln/detail/{r['cveID']}")
        kev_ids = {r["cveID"] for r in snap["kev"]}
        curated = {}
        for cve, comp, fixed, src in CURATED_AFFECTS:
            curated.setdefault(cve, set()).add(comp)
        deps = {}
        for a, b in DEPENDS_ON:
            deps.setdefault(a, set()).add(b)

        def reaches(comp, targets, seen=None):
            seen = seen or set()
            return any(d in targets or (d not in seen and reaches(d, targets, seen | {d})) for d in deps.get(comp, ()))

        confirmations = {}
        for comp, rows in snap["osv"].items():
            seen_ids = set()
            for r in rows:
                vid = next((a for a in r["aliases"] if a in kev_ids), None) or r["cve"] or r["osv_id"]
                if vid in seen_ids:
                    continue                                          # same CVE from two advisory databases
                seen_ids.add(vid)
                vuln(vid, title=r["summary"] or vid, cvss=r["cvss"], cvss_vector=r["cvss_vector"],
                     summary=r["summary"], sources=["OSV"], url=r["url"])
                if vid in curated and reaches(comp, curated[vid]):
                    confirmations.setdefault(vid, []).append(f"{r['osv_id']} ({comp})")
                    continue                                          # bundled copy already modelled hop by hop
                affects.append((vid, comp, r["fixed_in"] or "", f"OSV {r['osv_id']}", r["url"]))
        for cve, comp, fixed, src in CURATED_AFFECTS:
            note = "; confirmed by OSV " + ", ".join(confirmations[cve]) if cve in confirmations else ""
            affects.append((cve, comp, fixed, "NVD + vendor advisory" + note, src))
        for cve, e in snap["epss"].items():
            if cve in vulns:
                vulns[cve]["epss"], vulns[cve]["epss_pct"] = e["epss"], e["percentile"]
    else:
        affects = [(c, k, f, "NVD + vendor advisory", s) for c, k, f, s in CURATED_AFFECTS + FALLBACK_AFFECTS]

    for v in VULNERABILITIES:                                         # curated wording wins; KEV wins on facts
        real = vulns.get(v["id"])
        vuln(v["id"], **{k: val for k, val in v.items() if k not in ("exploited", "kev_added", "cvss")}, sources=["curated"])
        target = vulns[v["id"]]
        target["title"], target["summary"] = v["title"], v["summary"]
        if not real or not snap:
            target["exploited"], target["kev_added"] = v["exploited"], v["kev_added"]
        target["cvss"] = v["cvss"]                                    # NVD base score, checked by hand
    for v in vulns.values():
        if not v["user_mitigation"] and v["required_action"]:
            v["user_mitigation"] = v["required_action"]
    return {"vulnerabilities": list(vulns.values()), "affects": affects, "snapshot": snap}


def verify_against(snapshot):
    """Check every curated fact against the real feeds and print a report."""
    kev = {r["cveID"]: r for r in snapshot["kev"]}
    print("\nVerifying curated facts against CISA KEV / FIRST EPSS:")
    ok = True
    for v in VULNERABILITIES:
        real = kev.get(v["id"])
        exploited_ok = bool(real) == v["exploited"]
        date_ok = (real or {}).get("dateAdded", "") == v["kev_added"]
        ok &= exploited_ok and date_ok
        epss = snapshot["epss"].get(v["id"], {}).get("epss")
        print(f"   {'✓' if exploited_ok and date_ok else '✗'} {v['id']:15s} exploited={bool(real)!s:5s} "
              f"KEV date={(real or {}).get('dateAdded', '-'):10s} EPSS={epss if epss is not None else '-'}")
    print("   all curated facts match the real feeds" if ok else "   ✗ MISMATCH: fix VULNERABILITIES above")
    return ok


def connect():
    return FalkorDB(host=FALKOR_HOST, port=FALKOR_PORT, username=FALKOR_USERNAME,
                    password=FALKOR_PASSWORD).select_graph(GRAPH_NAME)


def seed():
    data = build()
    g = connect()
    try:
        g.delete()
        print(f"Deleted existing graph '{GRAPH_NAME}'")
    except Exception:
        pass
    q = g.query
    for label, prop in [("Vulnerability", "id"), ("Component", "key"), ("Product", "name"), ("Person", "name"),
                        ("Team", "name"), ("Repo", "name"), ("Doc", "title"), ("Market", "code"),
                        ("Session", "id"), ("Event", "id"), ("Report", "id"), ("Ticket", "key"),
                        ("ChatMessage", "id"), ("Decision", "id"), ("Task", "id"), ("Alert", "cve"), ("Turn", "id"), ("Supplier", "name"), ("Case", "id")]:
        q(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")

    vulns = data["vulnerabilities"]
    for i in range(0, len(vulns), 500):            # UNWIND in chunks: one round trip per 500 rows
        q("UNWIND $rows AS r CREATE (v:Vulnerability) SET v = r", {"rows": vulns[i:i + 500]})
    q("UNWIND $rows AS r CREATE (:Component {key:r[0], name:r[1], version:r[2], ecosystem:r[3]})",
      {"rows": [list(c) for c in COMPONENTS]})
    q("UNWIND $rows AS r CREATE (:Product {name:r[0], version:r[1], category:r[2], cra_in_scope:r[3], note:r[4]})",
      {"rows": [list(p) for p in PRODUCTS]})
    q("UNWIND $rows AS r CREATE (:Market {code:r[0], name:r[1]})", {"rows": [list(m) for m in MARKETS]})
    q("UNWIND $rows AS r CREATE (:Team {name:r[0], slack:r[1]})", {"rows": [list(t) for t in TEAMS]})
    q("UNWIND $rows AS r MATCH (t:Team {name:r[3]}) "
      "CREATE (p:Person {name:r[0], email:r[1], role:r[2], oncall:r[4], access:r[5]})-[:MEMBER_OF]->(t)",
      {"rows": [list(p) for p in PEOPLE]})
    q("UNWIND $rows AS r CREATE (:Repo {name:r[0], url:r[1]})", {"rows": [list(r) for r in REPOS]})
    q("UNWIND $rows AS r MATCH (a:Person {name:r[3]}) CREATE (d:Doc {title:r[0], type:r[1], url:r[2]})-[:AUTHORED_BY]->(a)",
      {"rows": [list(d) for d in DOCS]})

    def link(cypher, rows):
        q(cypher, {"rows": [list(r) for r in rows]})

    link("UNWIND $rows AS r MATCH (v:Vulnerability {id:r[0]}), (c:Component {key:r[1]}) "
         "CREATE (v)-[:AFFECTS {fixed_in:r[2], source:r[3], url:r[4]}]->(c)", data["affects"])
    link("UNWIND $rows AS r MATCH (a:Component {key:r[0]}), (b:Component {key:r[1]}) CREATE (a)-[:DEPENDS_ON]->(b)", DEPENDS_ON)
    link("UNWIND $rows AS r MATCH (p:Product {name:r[0]}), (c:Component {key:r[1]}) CREATE (p)-[:SHIPS]->(c)", SHIPS)
    link("UNWIND $rows AS r MATCH (p:Product {name:r[0]}), (m:Market {code:r[1]}) CREATE (p)-[:SOLD_IN {countries:r[2]}]->(m)", SOLD_IN)
    link("UNWIND $rows AS r MATCH (t:Team {name:r[0]}), (p:Product {name:r[1]}) CREATE (t)-[:OWNS]->(p)", OWNS)
    link("UNWIND $rows AS r MATCH (p:Person {name:r[0]}), (c:Component {key:r[1]}) CREATE (p)-[:MAINTAINS]->(c)", MAINTAINS)
    link("UNWIND $rows AS r MATCH (p:Person {name:r[0]}), (x:Repo {name:r[1]}) CREATE (p)-[:COMMITTED_TO {commits:r[2]}]->(x)", COMMITTED_TO)
    for label, key in [("Product", "name"), ("Component", "key")]:
        link(f"UNWIND $rows AS r MATCH (x:Repo {{name:r[0]}}), (t:{label} {{{key}:r[1]}}) CREATE (x)-[:BUILDS]->(t)",
             [(a, c) for a, l, c in BUILDS if l == label])
        link(f"UNWIND $rows AS r MATCH (d:Doc {{title:r[0]}}), (t:{label} {{{key}:r[1]}}) CREATE (d)-[:DOCUMENTS]->(t)",
             [(a, c) for a, l, c in DOCUMENTS if l == label])

    link("UNWIND $rows AS r MATCH (p:Person {name:r[5]}) "
         "CREATE (s:Supplier {name:r[0], service:r[1], data:r[2], contact:r[3], dora_critical:r[4]})<-[:MANAGES_SUPPLIER]-(p)",
         SUPPLIERS)
    link("UNWIND $rows AS r MATCH (s:Supplier {name:r[0]}), (c:Component {key:r[1]}) CREATE (s)-[:RUNS]->(c)", SUPPLIER_RUNS)
    # Real-world cases (data/cases.json) linked to their CVEs, for the landing page replays.
    for c in json.loads(CASES.read_text())["cases"]:
        q("""CREATE (k:Case {id:$id, name:$name, date:$date, pattern:$pattern, stat:$stat, stat_label:$stat_label,
                            happened:$happened, hard_part:$hard_part, sources:$sources})
             WITH k UNWIND $cves AS cve MATCH (v:Vulnerability {id:cve}) CREATE (k)-[:ABOUT]->(v)""",
          {**{f: c[f] for f in ("id", "name", "date", "pattern", "stat", "stat_label", "happened", "hard_part", "cves")},
           "sources": [s["url"] for s in c["sources"]]})

    # Company knowledge: tickets, chat, decisions, each linked to what it's about.
    for key, title, status, created, updated, reporter, assignee, about in TICKETS:
        q("""MATCH (r:Person {name:$rep}), (a:Person {name:$asg})
             CREATE (t:Ticket {key:$key, title:$title, status:$status, created:$created, updated:$updated,
                               url:'https://jira.fernwave.eu/browse/' + $key})-[:REPORTED_BY]->(r), (t)-[:ASSIGNED_TO]->(a)""",
          {"key": key, "title": title, "status": status, "created": created, "updated": updated, "rep": reporter, "asg": assignee})
        for label, k in about:
            prop = "key" if label == "Component" else "name"
            q(f"MATCH (t:Ticket {{key:$t}}), (x:{label} {{{prop}:$k}}) CREATE (t)-[:ABOUT]->(x)", {"t": key, "k": k})
    for mid, channel, author, ts, text, mentions in CHATS:
        q("""MATCH (p:Person {name:$a}) CREATE (m:ChatMessage {id:$id, channel:$ch, ts:$ts, text:$text})-[:POSTED_BY]->(p)""",
          {"id": mid, "ch": channel, "ts": ts, "text": text, "a": author})
        for label, k in mentions:
            prop = "key" if label == "Component" else "name"
            q(f"MATCH (m:ChatMessage {{id:$m}}), (x:{label} {{{prop}:$k}}) CREATE (m)-[:MENTIONS]->(x)", {"m": mid, "k": k})
    for did, title, date, by, why, about, (src_label, src_key) in DECISIONS:
        q("""MATCH (p:Person {name:$by}) CREATE (d:Decision {id:$id, title:$title, date:$date, rationale:$why})-[:DECIDED_BY]->(p)""",
          {"id": did, "title": title, "date": date, "why": why, "by": by})
        for label, k in about:
            prop = "key" if label == "Component" else "name"
            q(f"MATCH (d:Decision {{id:$d}}), (x:{label} {{{prop}:$k}}) CREATE (d)-[:ABOUT]->(x)", {"d": did, "k": k})
        src_prop = {"Doc": "title", "Ticket": "key", "ChatMessage": "id"}[src_label]
        q(f"MATCH (d:Decision {{id:$d}}), (x:{src_label} {{{src_prop}:$k}}) CREATE (d)-[:SOURCE]->(x)", {"d": did, "k": src_key})
    # Past incidents: the procedural memory the agent can recall ("how did we fix this before?").
    for inc, started, cve, who, fixes in PAST_INCIDENTS:
        q("""MATCH (v:Vulnerability {id:$cve})
             CREATE (s:Session {id:$inc, started:$ts, closed:true})-[:INVESTIGATED {first_seen:$ts, by:$who}]->(v)""",
          {"inc": inc, "ts": started, "cve": cve, "who": who})
        for product, note, by, ts in fixes:
            q("""MATCH (s:Session {id:$inc}), (p:Product {name:$p})
                 CREATE (s)-[:REMEDIATED {cve:$cve, by:$by, ts:$ts, note:$note}]->(p)""",
              {"inc": inc, "p": product, "cve": cve, "by": by, "ts": ts, "note": note})

    nodes = q("MATCH (n) RETURN count(n)").result_set[0][0]
    edges = q("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
    snap = data["snapshot"]
    src = (f"CISA KEV {snap['sources']['kev']['catalogVersion']} ({snap['sources']['kev']['count']} exploited CVEs), "
           f"{snap['sources']['osv']['advisories']} OSV advisories, EPSS {snap['sources']['epss']['date']}"
           if snap else "no real-data snapshot (run ingest_real.py)")
    print(f"Seeded graph '{GRAPH_NAME}': {nodes} nodes, {edges} edges · real data: {src}")
    rows = q("""MATCH path = (v:Vulnerability {id:'CVE-2023-4863'})-[:AFFECTS]->(:Component)
                <-[:DEPENDS_ON*0..10]-(:Component)<-[:SHIPS]-(p:Product)
                RETURN p.name, min(length(path)) AS hops ORDER BY hops""").result_set
    print("Smoke test, products hit by CVE-2023-4863:")
    for name, hops in rows:
        print(f"   {name}  ({hops} hops)")
    if snap:
        verify_against(snap)


if __name__ == "__main__":
    seed()
