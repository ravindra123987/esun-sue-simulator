// The app: state, transport, panels, selection, live client, keyboard and URL state.
(function(){
"use strict";
const {ALL1, WHERE, PROB, newData, ingest, addNotes, prune, view, noteIdx, frameHistory, lastAt} = SUE.data;
const RD = SUE.render;
const $ = id => document.getElementById(id);
const TR = window.SUE_TRACES;
if (!TR || !TR.length){
  document.body.insertAdjacentHTML("afterbegin", '<div class="err">traces.js did not load. Run <code>tools/make_traces.py</code> and open this page next to it.</div>');
  return;
}
const store = {get(k, dflt){ try { const v = localStorage.getItem(k); return v == null ? dflt : v; } catch (e){ return dflt; } }, set(k, v){ try { localStorage.setItem(k, v); } catch (e) {} }};
const KIND_TAG = {clean:"baseline", "bit-error":"hop 1 · error", "bit-error-2":"hop 2 · error", "lost-nack":"hop 1 · timer", backpressure:"flow control",
  "small-pool":"flow control", "outage-short":"hop 1 · outage", "outage-flush":"hop 1 · FLUSH", "no-llr":"LLR off"};

// ---------------------------------------------------------------- state
const D = TR.map(tr => { const d = newData(tr, tr.cfg); ingest(d, tr.events); d.notes = tr.notes.slice(); return d; });
let d = D[0], t = 0, playing = false, lastFrame = 0;
let mode = store.get("sue-viz-view", "simple") === "detail" ? "detail" : "simple";
let sel = null, hover = null, tab = "events", filter = "all";
const LIVE = {avail:false, on:false, id:null, busy:false, simT:0, metas:[], waiting:false, gen:0, over:null};
const LOOK = 40;                 // ns the simulator stays ahead of the picture (a frame is logged when its last bit leaves)
const cv = $("cNet");
const ready = () => d.snaps.A.length && d.snaps.B.length && d.snaps.S7.length;

// ---------------------------------------------------------------- theme
RD.readTheme();
function applyTheme(){ const th = store.get("sue-viz-theme", ""); if (th) document.documentElement.dataset.theme = th; else delete document.documentElement.dataset.theme; RD.readTheme(); }
applyTheme();
$("bTheme").onclick = () => {
  const dark = matchMedia("(prefers-color-scheme: dark)").matches, cur = document.documentElement.dataset.theme || (dark ? "dark" : "light");
  store.set("sue-viz-theme", cur === "dark" ? "light" : "dark"); applyTheme(); drawAll(true);
};
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { RD.readTheme(); drawAll(true); });

// ---------------------------------------------------------------- layout: the picture fits the stage, panels resize
let zoom = store.get("sue-viz-zoom", "fit");
function layout(){
  const aw = $("pic").clientWidth - 12;
  const s = zoom === "fit" ? Math.max(.66, aw / RD.W) : +zoom;
  const w = Math.round(RD.W * s) + "px", h = Math.round(RD.H * s) + "px";
  if (cv.style.width !== w){ cv.style.width = w; cv.style.height = h; }
  drawAll(true);
}
$("zoom").value = zoom;
$("zoom").onchange = () => { zoom = $("zoom").value; store.set("sue-viz-zoom", zoom); layout(); };
new ResizeObserver(() => layout()).observe($("pic"));
new ResizeObserver(() => { if (tab === "flow") drawAll(true); }).observe($("pFlow"));
window.addEventListener("resize", () => { if (!LIVE.on) RD.drawMarks($("cMarks"), d); });

function setSide(open){ $("app").classList.toggle("noside", !open); store.set("sue-viz-side", open ? "1" : "0"); }
$("tSide").onclick = () => setSide($("app").classList.contains("noside"));
setSide(store.get("sue-viz-side", innerWidth > 900 ? "1" : "0") === "1");

const dock = $("dock");
function setDock(px){ px = Math.max(140, Math.min(Math.max(140, innerHeight - 200), px)); $("app").style.setProperty("--dock", px + "px"); store.set("sue-viz-dock", String(Math.round(px))); }
setDock(+store.get("sue-viz-dock", "300"));
if (store.get("sue-viz-dock-open", "1") === "0") dock.classList.add("collapsed");
$("dockToggle").onclick = () => { dock.classList.toggle("collapsed"); store.set("sue-viz-dock-open", dock.classList.contains("collapsed") ? "0" : "1"); $("dockToggle").textContent = dock.classList.contains("collapsed") ? "▴" : "▾"; };
$("dockHandle").addEventListener("pointerdown", e => {
  e.preventDefault(); dock.classList.remove("collapsed"); $("dockHandle").setPointerCapture(e.pointerId);
  const move = ev => setDock(dock.getBoundingClientRect().bottom - ev.clientY), up = () => { $("dockHandle").removeEventListener("pointermove", move); $("dockHandle").removeEventListener("pointerup", up); };
  $("dockHandle").addEventListener("pointermove", move); $("dockHandle").addEventListener("pointerup", up);
});
function setTab(name){
  tab = name;
  for (const b of document.querySelectorAll(".dtabs [role=tab]")) b.setAttribute("aria-selected", b.dataset.tab === name);
  for (const [k, id] of [["events", "pEvents"], ["counters", "pCounters"], ["flow", "pFlow"], ["inspect", "pInspect"]]) $(id).hidden = k !== name;
  if (dock.classList.contains("collapsed")) $("dockToggle").click();
  drawAll(true);
}
for (const b of document.querySelectorAll(".dtabs [role=tab]")) b.onclick = () => setTab(b.dataset.tab);

// ---------------------------------------------------------------- sidebar: scenarios + about
function buildList(){
  const L = $("sclist"); L.textContent = "";
  for (const x of D){
    const b = document.createElement("button"); b.className = "sc"; b.setAttribute("role", "option"); b.dataset.id = x.id;
    const s = document.createElement("span"); s.textContent = x.title; const tg = document.createElement("span"); tg.className = "tag"; tg.textContent = KIND_TAG[x.id] || "";
    b.append(s, tg); b.onclick = () => pick(x.id); L.appendChild(b);
  }
}
function showScenario(){
  for (const b of $("sclist").children) b.setAttribute("aria-selected", b.dataset.id === d.id ? "true" : "false");
  $("scname").innerHTML = ""; const bb = document.createElement("b"); bb.textContent = d.title; $("scname").append(LIVE.on ? "Live · " : "", bb);
  $("sTitle").textContent = d.title; $("sSum").textContent = d.summary;
  $("sWatch").innerHTML = "<b>What to watch.</b> "; $("sWatch").append(LIVE.on ? "Use the fault-injection buttons: every reaction you see is the simulator's." : d.watch);
  const c = d.cfg, r = d.result, kb = n => `${(n * c.credit_size / 1024).toFixed(0)} KB`;
  const downs = c.hops.flatMap((h, i) => h.down.map(([a, b]) => `hop ${i + 1} down ${a}–${b} ns`));
  const bits = [`${c.hops[0].cable_m} m + ${c.hops[1].cable_m} m · ${c.rate_gbps}G`, `${c.frame} B frames`,
    c.llr.enabled ? `LLR timer ${c.llr.replay_timer_ns} ns · ${c.llr.replay_ct_max} retries` : "LLR off",
    `switch buffer ${kb(c.credits.S1)}`, `XPU B buffer ${kb(c.credits.B)}`, `XPU B HBM ${c.nic_gbps} Gb/s`,
    ...(LIVE.on ? [] : downs), r && !LIVE.on ? `result: ${r.delivered} delivered · ${r.lost} lost · ${r.replayed} replayed` : null];
  $("sCfg").textContent = ""; for (const s of bits.filter(Boolean)){ const e = document.createElement("span"); e.className = "tag"; e.textContent = s; $("sCfg").appendChild(e); }
}

// ---------------------------------------------------------------- banner, log, counters, inspector
function chip(at){ const [name, k] = WHERE[at] || [at, "muted"]; const s = document.createElement("span"); s.className = "chip"; s.style.setProperty("--k", `var(--${k})`); s.textContent = name; return s; }
// caption text with every "#12" turned into a button that selects that frame
function richText(text){
  const frag = document.createDocumentFragment(), re = /#(\d+)/g; let i = 0, m;
  while ((m = re.exec(text))){
    frag.append(text.slice(i, m.index));
    const b = document.createElement("button"); b.className = "fid"; b.type = "button"; b.textContent = m[0]; b.title = "Follow this frame";
    const fid = +m[1]; b.onclick = ev => { ev.stopPropagation(); select({kind:"frame", fid}); };
    frag.append(b); i = m.index + m[0].length;
  }
  frag.append(text.slice(i));
  return frag;
}
const passes = n => filter === "all" || (filter === "prob" ? PROB.has(n.kind) : filter === "S" ? (n.at === "S1" || n.at === "S7") :
  filter === "A" ? (n.at === "A" || n.at === "h1") : (n.at === "B" || n.at === "h2"));
let lastNote = -2, pausedHere = false, resumedAt = -1;
function buildLog(){
  const Lg = $("log"); Lg.textContent = "";
  d.notes.forEach((n, i) => {
    const b = document.createElement("button"); b.dataset.i = i;
    if (PROB.has(n.kind)) b.classList.add("prob");
    const tt = document.createElement("span"); tt.className = "t"; tt.textContent = n.t.toFixed(1) + " ns";
    const x = document.createElement("span"); x.className = "x"; x.appendChild(richText(n.text));
    const c = document.createElement("span"); c.appendChild(chip(n.at));
    b.append(tt, c, x); b.hidden = !passes(n);
    b.onclick = () => { stop(); setT(n.t); }; Lg.appendChild(b);
  });
  if (!d.notes.length){ const e = document.createElement("div"); e.className = "empty"; e.textContent = LIVE.on ? "Nothing has happened yet." : "No events."; Lg.appendChild(e); }
  $("nEvents").textContent = d.notes.length ? String(d.notes.length) : "";
  lastNote = -2;
}
function drawNotes(){
  const i = noteIdx(d, t);
  if (i === lastNote) return; lastNote = i;
  $("nowAt").textContent = ""; $("nowTxt").textContent = "";
  const nx = pausedHere ? d.notes.find(n => n.t > t + 1e-6) : null;
  $("pausedTag").hidden = !pausedHere; $("pausedTag").textContent = nx ? `paused · Continue runs to ${nx.t.toFixed(1)} ns` : "paused at the last event";
  if (i < 0){ $("nowTxt").textContent = (playing ? "" : "Press Play. ") + "Frames leave XPU A's HBM, pass the NIC's credit gate and LLR, cross hop 1, wait in the switch, cross hop 2 and land in XPU B's HBM."; $("nowT").textContent = ""; }
  else { const n = d.notes[i]; $("nowAt").appendChild(chip(n.at)); $("nowTxt").appendChild(richText(n.text)); $("nowT").textContent = `${n.t.toFixed(1)} ns`; }
  [...$("log").children].forEach((b, k) => { b.classList.toggle("cur", k === i); b.classList.toggle("future", k > i); });
  const cur = $("log").children[i];
  if (cur && playing && !cur.hidden && tab === "events"){ const L = $("pEvents"), top = cur.offsetTop; if (top < L.scrollTop + 30 || top > L.scrollTop + L.clientHeight - 40) L.scrollTop = top - 60; }
}
let lastStats = "";
function drawStats(v){
  const last = v.li >= 0 ? d.lat[v.li].lat.toFixed(0) + " ns" : "–";
  const groups = [["End to end", [["delivered to XPU B", v.deliv], ["last latency", last], ["in the switch buffer", v.swq.length], ["in XPU B's buffer", v.nq.length + (v.wr ? 1 : 0)]]],
    ["Hop 1 · XPU A → port 1", [["frames replayed", v.rep.A], ["FCS drops", v.drop.S1, v.drop.S1 > 0], ["XPU A credits in use", `${v.A.cr_used} / ${v.A.cl}`, v.A.stalled], ["LLR state", v.A.llr]]],
    ["Hop 2 · port 7 → XPU B", [["frames replayed", v.rep.S7], ["FCS drops", v.drop.B, v.drop.B > 0], ["port 7 credits in use", `${v.S7.cr_used} / ${v.S7.cl}`, v.S7.stalled], ["LLR state", v.S7.llr]]]];
  const key = JSON.stringify(groups); if (key === lastStats) return; lastStats = key;
  const P = $("pCounters"); P.textContent = "";
  for (const [title, rows] of groups){
    const dl = document.createElement("dl"); const h = document.createElement("div"); h.className = "sec-title"; h.textContent = title; dl.appendChild(h);
    for (const [k, val, bad] of rows){ const dt = document.createElement("dt"); dt.textContent = k; const dd = document.createElement("dd"); dd.textContent = val; if (bad) dd.className = "bad"; dl.append(dt, dd); }
    P.appendChild(dl);
  }
}

// ---- inspector
function select(s){ sel = s; $("nInspect").textContent = s ? (s.kind === "frame" ? `#${s.fid}` : "") : ""; if (s && tab !== "inspect") setTab("inspect"); else drawAll(true); }
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
function fidList(fids){ const w = el("div", "fidlist"); for (const f of fids){ const b = el("button", null, "#" + f); b.onclick = () => select({kind:"frame", fid:f}); w.appendChild(b); } if (!fids.length) w.append(el("span", "muted", "none")); return w; }
function rowsDl(rows){ const dl = el("dl"); for (const [k, v] of rows){ dl.append(el("dt", null, k)); const dd = el("dd"); if (v instanceof Node) dd.appendChild(v); else dd.textContent = String(v); dl.appendChild(dd); } return dl; }
const inFlight = (dir, t) => d.frames[dir].filter(f => f.t0 <= t && t < f.arrive && f.kind === "data").map(f => f.fid);
function blockRows(key, v){
  const c = d.cfg, A = v.A, S7 = v.S7, llrOn = c.llr.enabled;
  const sender = (a, rx) => [["LLR state", llrOn ? a.llr : "LLR off"], ["next seq to send", a.tx_seq], ["acknowledged up to", a.acked === ALL1 ? "– (nothing yet)" : a.acked],
    ["frames in replay buffer", a.nbuf], ["retries", `${a.replay_ct} of ${c.llr.replay_ct_max}`], ["replay timer", a.timer ? `running (${c.llr.replay_timer_ns} ns)` : "idle"],
    ["credits in use", `${a.cr_used} of ${a.cl} (${(a.cl * c.credit_size / 1024).toFixed(0)} KB at ${rx})`], ["credit gate", a.stalled ? "STOP: out of credits" : "GO"]];
  const receiver = (b, k) => [["expects seq", llrOn ? b.next_rx : "LLR off"], ["ACK state", llrOn ? b.ack_state : "–"], ["FCS drops so far", v.drop[k]],
    ["last verdict", v.rx[k] ? `${v.rx[k].res} ${v.rx[k].kind === "data" ? "#" + v.rx[k].fid : "CC"}` : "–"]];
  const ctl = k => { const x = v.last[k]; return x ? [["last block sent", `${x.kind} ${x.kind === "CF_UPDATE" ? x.cf : (x.seq === ALL1 ? "–" : x.seq)} at ${x.t1.toFixed(1)} ns`], ["carried news", x.news ? "yes" : "no: a periodic repeat"], ["fate", x.fate]] : [["last block sent", "none yet"]]; };
  const cable = h => { const hc = c.hops[h], dir = h ? "s2b" : "a2s"; return [["status", v.down[h] ? "DOWN" : "up"], ["length", `${hc.cable_m} m`], ["one-way delay", `${hc.prop_ns.toFixed(1)} ns (cable + MAC/PHY)`], ["rate", `${c.rate_gbps} Gb/s`],
    ["frames in flight", fidList(inFlight(dir, t))], ["outages", hc.down.length ? hc.down.map(([a, b]) => `${a}–${b} ns`).join(", ") : "none"]]; };
  const rb = (a, dir) => { const fids = []; for (let i = 0; i < a.nbuf && i < 200; i++){ const f = d.seqFid[dir].get((a.buf0 + i) & ALL1); if (typeof f === "number") fids.push(f); }
    return [["frames held", a.nbuf], ["about", `${a.nbuf} KB of 64 KB`], ["first LLR seq", a.nbuf ? a.buf0 : "–"], ["frames", fidList(fids)]]; };
  switch (key){
    case "hbmA": return [["next frame to send", "#" + v.next], ["source", "always full (backlog)"]];
    case "cred": return [["credits in use", `${A.cr_used} of ${A.cl}`], ["pool", `${(A.cl * c.credit_size / 1024).toFixed(0)} KB of switch port 1 buffer`], ["per 1 KB frame", `${Math.ceil(c.frame / c.credit_size)} credits`], ["gate", A.stalled ? "STOP: waiting for a CF_Update" : "GO"]];
    case "llrA": return sender(A, "port 1");
    case "rbA": return rb(A, "a2s");
    case "p1": return receiver(v.S1, "S1");
    case "c1": return ctl("S1");
    case "sbuf": return [["occupancy", `${v.S1.occ} of ${c.credits.S1} credits (${(c.credits.S1 * c.credit_size / 1024).toFixed(0)} KB)`], ["frames queued", fidList(v.swq.map(q => q.fid))], ["forwarded so far", v.fwd]];
    case "p7": return sender(S7, "XPU B");
    case "rb7": return rb(S7, "s2b");
    case "rxB": return receiver(v.B, "B");
    case "cB": return ctl("B");
    case "bufB": return [["occupancy", `${v.B.occ} of ${c.credits.B} credits`], ["frames queued", fidList(v.nq.map(q => q.fid))], ["DMA to HBM", `${c.nic_gbps} Gb/s` + (v.wr ? `, writing #${v.wr.fid}` : "")]];
    case "hbmB": return [["frames received", v.deliv], ["last latency", v.li >= 0 ? `${d.lat[v.li].lat.toFixed(1)} ns` : "–"], ["recent", fidList(d.lat.slice(Math.max(0, v.li - 11), v.li + 1).map(e => e.fid).reverse())]];
    case "h1": return cable(0);
    case "h2": return cable(1);
  }
  return [];
}
let lastInsp = "";
function drawInspector(v){
  const key = JSON.stringify([sel, Math.round(t * 2), v.deliv, v.fwd, d.notes.length]); if (key === lastInsp) return; lastInsp = key;
  const P = $("pInspect"); P.textContent = "";
  if (!sel){ P.append(el("p", "hint", "Click a block in the picture to see its state, or click a frame (on a cable, in a buffer, in a queue, or a #number in a caption) to follow it through the path.")); return; }
  const head = el("h3"); const clear = el("button", "btn ghost", "Clear"); clear.style.marginLeft = "auto"; clear.onclick = () => select(null);
  if (sel.kind === "block"){
    head.append(RD.BLOCK_NAMES[sel.key] || sel.key, clear); P.append(head, rowsDl(blockRows(sel.key, v)));
    P.append(el("p", "hint", `State at t = ${t.toFixed(1)} ns. It updates as time moves.`));
    return;
  }
  head.append(`Frame #${sel.fid}`, clear); P.append(head);
  const steps = frameHistory(d, sel.fid);
  if (!steps.length){ P.append(el("p", "hint", v.next <= sel.fid ? "Not sent yet: it is still in XPU A's send queue." : "No record of this frame in the loaded data.")); return; }
  let now = -1; steps.forEach((s, i) => { if (s.t <= t + 1e-6) now = i; });
  P.append(el("p", "hint", now < 0 ? "Not sent yet at this time." : `Now: ${steps[now].text} (${steps[now].t.toFixed(1)} ns).`));
  const box = el("div", "steps");
  steps.forEach((s, i) => {
    const row = el("div", "step" + (i > now ? " future" : "") + (i === now ? " now" : "") + (s.kind === "bad" ? " bad" : ""));
    row.append(el("span", "t", s.t.toFixed(1) + " ns"), chip(s.at), el("span", "x", s.text));
    row.style.cursor = "pointer"; row.onclick = () => { stop(); setT(s.t); }; box.appendChild(row);
  });
  P.append(box);
}

// ---------------------------------------------------------------- main loop
function drawAll(force){
  if (!ready()) return;
  $("clock").innerHTML = ""; $("clock").append(`t = ${t.toFixed(1)} ns`); if (LIVE.on && LIVE.waiting){ const s = el("small", null, "waiting for the simulator"); $("clock").appendChild(s); }
  if (!LIVE.on) $("scrub").value = t;
  cv.classList.toggle("hit", !!hover);
  const v = RD.drawPath(cv, d, t, {mode, sel, hover});
  if (tab === "flow") RD.drawLadder($("cLadder"), d, t, +$("span").value);
  drawNotes();
  if (tab === "counters") drawStats(v);
  if (tab === "inspect") drawInspector(v);
}
function setT(v){ t = Math.max(0, LIVE.on ? Math.min(v, Math.max(0, LIVE.simT - LOOK)) : Math.min(d.dur, v)); drawAll(); }
function tick(now){
  if (!playing) return;
  const dt = Math.max(0, Math.min(100, now - lastFrame)) / 1000; lastFrame = now;   // a frame timestamp can precede the click's performance.now()
  let nt = t + dt * +$("speed").value;
  if (LIVE.on){
    pump();
    const lim = LIVE.simT - LOOK; LIVE.waiting = nt > lim; if (nt > lim) nt = Math.max(t, lim);
    prune(d, nt);
  }
  if ($("pauseAt").checked){ const n = d.notes.find(n => n.t > Math.max(t, resumedAt) + 1e-6 && n.t <= nt); if (n){ setT(n.t); stop(true); return; } }
  if (!LIVE.on && nt >= d.dur){ setT(d.dur); stop(); return; }
  setT(nt); requestAnimationFrame(tick);
}
function play(){ if (!LIVE.on && t >= d.dur) t = 0; playing = true; resumedAt = pausedHere ? t : -1; pausedHere = false; lastNote = -2; $("bPlay").textContent = "Pause"; lastFrame = performance.now(); requestAnimationFrame(tick); }
function stop(atEvent = false){ playing = false; pausedHere = !!atEvent; lastNote = -2; $("bPlay").textContent = !LIVE.on && t >= d.dur ? "Replay" : (atEvent ? "Continue" : "Play"); }

// ---------------------------------------------------------------- live client
async function api(path, body){
  const r = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
  const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); return j;
}
function liveStatus(text, bad){ const s = $("liveStatus"); s.textContent = text; s.classList.toggle("bad", !!bad); }
async function pump(){
  if (!LIVE.on || LIVE.busy) return;
  const want = t + LOOK + 20 + +$("speed").value * .6;
  if (LIVE.simT >= want) return;
  LIVE.busy = true; const gen = LIVE.gen;
  try {
    const r = await api("/live/step", {id:LIVE.id, until:want});
    if (gen !== LIVE.gen) return;                       // restarted meanwhile
    ingest(d, r.events); LIVE.simT = r.t; $("liveT").textContent = `simulated to ${r.t.toFixed(0)} ns`;
    if (addNotes(d, r.notes)) buildLog();
  } catch (e){ liveStatus("simulator unreachable: " + e.message, true); stop(); }
  finally { if (gen === LIVE.gen) LIVE.busy = false; }
}
async function startLive(id, over){
  stop(); LIVE.gen++; LIVE.busy = false; LIVE.over = over || null;
  const meta = LIVE.metas.find(m => m.id === id) || LIVE.metas[0];
  try {
    const r = await api("/live/new", {scenario:meta.id, cfg:LIVE.over});
    LIVE.id = r.id; LIVE.simT = 0;
    d = newData(meta, r.cfg); t = 0; sel = null; lastInsp = ""; lastStats = "";
    const first = await api("/live/step", {id:LIVE.id, until:LOOK + 60});
    ingest(d, first.events); LIVE.simT = first.t; addNotes(d, first.notes);
    showScenario(); buildLog(); drawAll(true);
    liveStatus(`running: ${meta.title}` + (LIVE.over ? " with custom settings" : "") + (meta.id === "clean" ? "" : " (its scripted faults still happen)"));
    play();
  } catch (e){ liveStatus("could not start: " + e.message, true); }
}
function setSource(live){
  if (live && !LIVE.avail){ $("liveHelp").showModal(); return; }
  LIVE.on = live;
  $("sRec").setAttribute("aria-pressed", !live); $("sLive").setAttribute("aria-pressed", live);
  $("liveSec").hidden = $("customSec").hidden = !live; $("tl").hidden = live; $("liveTag").hidden = !live; $("bRestart").hidden = !live; $("bShare").hidden = live;
  $("bPrevN").disabled = $("bNextN").disabled = live;
  if (live){ $("pauseAt").checked = false; startLive(d.id); }
  else { LIVE.gen++; stop(); $("pauseAt").checked = true; pick(d.id); }
}
for (const b of document.querySelectorAll("#liveSec [data-cmd]")){
  b.onclick = async () => {
    try {
      const arg = {hop:+(b.dataset.hop || 1)}; if (b.dataset.ns) arg.ns = +b.dataset.ns; if (b.dataset.gbps) arg.gbps = +b.dataset.gbps;
      const r = await api("/live/cmd", {id:LIVE.id, cmd:b.dataset.cmd, arg});
      d.cfg = r.cfg; showScenario();
      if (!playing) play();
    } catch (e){ liveStatus("command failed: " + e.message, true); }
  };
}
$("custom").onsubmit = e => {
  e.preventDefault();
  const over = {};
  for (const f of $("custom").elements){
    if (!f.name) continue;
    const [sec, key] = f.name.split("."); over[sec] = over[sec] || {};
    over[sec][key] = f.type === "checkbox" ? f.checked : +f.value;
  }
  startLive(d.id, over);
};
$("bRestart").onclick = () => startLive(d.id, LIVE.over);

// ---------------------------------------------------------------- scenario + mode switching
function pick(id){
  if (LIVE.on){ startLive(id); return; }
  stop();
  d = D.find(x => x.id === id) || D[0]; t = 0; sel = null; lastInsp = ""; lastStats = "";
  showScenario();
  $("scrub").max = d.dur;
  buildLog(); RD.drawMarks($("cMarks"), d); drawAll(true);
  if (location.hash.slice(1) !== d.id) history.replaceState(null, "", location.search + "#" + d.id);
}
function setMode(m){
  mode = m; store.set("sue-viz-view", m);
  $("vSimple").setAttribute("aria-pressed", m === "simple"); $("vDetail").setAttribute("aria-pressed", m === "detail");
  drawAll(true);
}

// ---------------------------------------------------------------- picture interaction
cv.addEventListener("mousemove", e => { const h = RD.hitTest(cv, e.clientX, e.clientY); if (JSON.stringify(h) !== JSON.stringify(hover)){ hover = h; drawAll(true); } });
cv.addEventListener("mouseleave", () => { if (hover){ hover = null; drawAll(true); } });
cv.addEventListener("click", e => { const h = RD.hitTest(cv, e.clientX, e.clientY); select(h && sel && h.kind === sel.kind && (h.fid === sel.fid && h.key === sel.key) ? null : h); });

// ---------------------------------------------------------------- transport, filters, overlays
$("bPlay").onclick = () => playing ? stop() : play();
$("bNextN").onclick = () => { stop(); const n = d.notes.find(n => n.t > t + 1e-6); setT(n ? n.t : d.dur); };
$("bPrevN").onclick = () => { stop(); const ns = d.notes.filter(n => n.t < t - 1e-6); setT(ns.length ? ns[ns.length - 1].t : 0); };
$("scrub").oninput = e => { stop(); setT(+e.target.value); };
$("cMarks").onclick = e => { const r = e.target.getBoundingClientRect(); stop(); setT((e.clientX - r.left) / r.width * d.dur); };
$("span").onchange = () => drawAll(true);
$("vSimple").onclick = () => setMode("simple"); $("vDetail").onclick = () => setMode("detail");
$("sRec").onclick = () => setSource(false); $("sLive").onclick = () => setSource(true);
for (const b of document.querySelectorAll(".filters button")){
  b.onclick = () => {
    filter = b.dataset.f;
    for (const o of document.querySelectorAll(".filters button")) o.setAttribute("aria-pressed", o === b);
    [...$("log").children].forEach(r => { if (r.dataset.i != null) r.hidden = !passes(d.notes[+r.dataset.i]); });
  };
}
let toastTimer = 0;
function toast(msg){ const x = $("toast"); x.textContent = msg; x.classList.add("show"); clearTimeout(toastTimer); toastTimer = setTimeout(() => x.classList.remove("show"), 1800); }
function shareUrl(){ const q = new URLSearchParams({view:mode, t:t.toFixed(1)}); if (sel && sel.kind === "frame") q.set("sel", sel.fid); return `${location.origin}${location.pathname}?${q}#${d.id}`; }
$("bShare").onclick = async () => {
  const url = shareUrl();
  try { await navigator.clipboard.writeText(url); toast("Link copied: this scenario, view and moment"); }
  catch (e){ history.replaceState(null, "", url.slice(location.origin.length)); toast("Link is in the address bar"); }
};
$("bLegend").onclick = () => { const p = $("legend"); p.hidden = !p.hidden; $("bLegend").setAttribute("aria-expanded", !p.hidden); };
document.addEventListener("click", e => { if (!$("legend").hidden && !e.target.closest("#legend, #bLegend")){ $("legend").hidden = true; $("bLegend").setAttribute("aria-expanded", "false"); } });
$("bHelp").onclick = () => $("help").showModal();
for (const b of document.querySelectorAll("dialog [data-close]")) b.onclick = () => b.closest("dialog").close();
for (const dg of document.querySelectorAll("dialog")) dg.addEventListener("click", e => { if (e.target === dg) dg.close(); });

document.addEventListener("keydown", e => {
  if (e.target.closest && e.target.closest("input, select, textarea")) return;
  if (document.querySelector("dialog[open]")) return;
  const k = e.key;
  if (k === " " && !(e.target.closest && e.target.closest("button"))){ e.preventDefault(); $("bPlay").click(); }
  else if (k === "ArrowRight" && !LIVE.on){ e.preventDefault(); stop(); setT(t + (e.shiftKey ? 10 : 1)); }
  else if (k === "ArrowLeft" && !LIVE.on){ e.preventDefault(); stop(); setT(t - (e.shiftKey ? 10 : 1)); }
  else if (k === "]" && !LIVE.on) $("bNextN").click();
  else if (k === "[" && !LIVE.on) $("bPrevN").click();
  else if (k === "1") setMode("simple");
  else if (k === "2") setMode("detail");
  else if (k === "e") setTab("events"); else if (k === "c") setTab("counters"); else if (k === "f") setTab("flow"); else if (k === "i") setTab("inspect");
  else if (k === "s") $("tSide").click();
  else if (k === "?") $("help").showModal();
  else if (k === "Escape"){ if (sel) select(null); if (!$("legend").hidden) $("bLegend").click(); }
});
window.addEventListener("hashchange", () => { if (location.hash.slice(1) !== d.id) pick(location.hash.slice(1)); });
if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => drawAll(true));

// ---------------------------------------------------------------- start
buildList();
const q = new URLSearchParams(location.search);
if (q.get("view") === "detail" || q.get("view") === "simple") mode = q.get("view");
setMode(mode);
pick(location.hash.slice(1) || D[0].id);
if (q.has("t")) setT(+q.get("t"));
if (q.has("sel")) select({kind:"frame", fid:+q.get("sel")});
layout();
// live mode is available when the page is served by tools/live.py
if (location.protocol.startsWith("http")){
  fetch("/live/hello").then(r => r.ok ? r.json() : null).then(j => {
    if (!j || !j.ok) return;
    LIVE.avail = true; LIVE.metas = j.scenarios; $("liveDot").classList.add("ok"); $("sLive").title = "Simulator found: drive the page from it";
    if (q.has("live")) setSource(true);
  }).catch(() => {});
}
})();
