// Data layer: turns simulator events (traces.js, or batches from tools/live.py) into what the
// pictures and panels need at a given time. No DOM here.
window.SUE = window.SUE || {};
SUE.data = (function(){
"use strict";
const ALL1 = (1 << 20) - 1;
const SENDER = {a2s:"A", s2b:"S7"}, REVTO = {s2a:"A", b2s:"S7"}, REVFROM = {s2a:"S1", b2s:"B"};
const WHERE = {A:["XPU A", "dev-a"], S1:["Switch · port 1", "dev-s"], S7:["Switch · port 7", "dev-s"], B:["XPU B", "dev-b"],
  h1:["Hop 1 cable", "muted"], h2:["Hop 2 cable", "muted"], cmd:["You", "accent"]};
const PROB = new Set(["bad", "nack", "ooo", "timer", "flush", "overflow", "stall", "down", "cc", "fill"]);

const lastAt = (arr, t) => { let lo = 0, hi = arr.length - 1, r = -1; while (lo <= hi){ const m = (lo + hi) >> 1; if (arr[m].t <= t){ r = m; lo = m + 1; } else hi = m - 1; } return r; };
const countLE = (arr, t) => { let lo = 0, hi = arr.length; while (lo < hi){ const m = (lo + hi) >> 1; if (arr[m] <= t) lo = m + 1; else hi = m; } return lo; };
const isDown = (d, h, t) => d.cfg.hops[h].down.some(([a, b]) => a <= t && t < b);

function newData(meta, cfg){
  return {id:meta.id, title:meta.title, summary:meta.summary, watch:meta.watch, result:meta.result || null, cfg,
    frames:{a2s:[], s2b:[]}, ctl:[], snaps:{A:[], S1:[], S7:[], B:[]}, rx:{S1:[], B:[]},
    swq:[], swqBy:new Map(), nq:[], nqBy:new Map(), seqFid:{a2s:new Map(), s2b:new Map()},
    firsts:[], deliv:[], lat:[], lastCtl:new Map(), replays:{A:[], S7:[]}, drops:{S1:[], B:[]}, fwdT:[], notes:[], dur:cfg.sim_ns || 0};
}
function ingest(d, events){
  for (const e of events){
    switch (e.ev){
      case "frame": {
        const L = d.frames[e.dir]; if (!L) break;
        L.push(e);
        if (e.replay) d.replays[SENDER[e.dir]].push(e.t1);
        else { if (e.seq != null) d.seqFid[e.dir].set(e.seq, e.kind === "data" ? e.fid : "CC"); if (e.dir === "a2s" && e.kind === "data") d.firsts.push(e.t0); }
        break; }
      case "ctlos": {
        // "news": an ACK that moves the acknowledged seq, a CF_Update that returns credits, any NACK/INIT/ECHO
        const k = e.dir + e.kind, prev = d.lastCtl.has(k) ? d.lastCtl.get(k) : (e.kind === "CF_UPDATE" ? 0 : ALL1), val = e.kind === "CF_UPDATE" ? e.cf : e.seq;
        e.news = !(e.kind === "LLR_ACK" || e.kind === "CF_UPDATE") || (val !== prev && !(e.kind === "LLR_ACK" && val === ALL1));
        if (e.fate === "ok") d.lastCtl.set(k, val);
        d.ctl.push(e); break; }
      case "mac": if (d.snaps[e.mac]) d.snaps[e.mac].push(e); break;
      case "rx": {
        const L = d.rx[e.mac]; if (!L) break;
        L.push(e);
        if (e.res === "bad") d.drops[e.mac].push(e.t);
        if (e.res === "accept" && e.kind === "data"){
          if (e.mac === "S1" && !d.swqBy.has(e.fid)){ const it = {fid:e.fid, tin:e.t, tout:null}; d.swq.push(it); d.swqBy.set(e.fid, it); }
          if (e.mac === "B" && !d.nqBy.has(e.fid)){ const it = {fid:e.fid, tin:e.t, ts:null, te:null}; d.nq.push(it); d.nqBy.set(e.fid, it); }
        }
        break; }
      case "fwd": { const it = d.swqBy.get(e.fid); if (it) it.tout = e.t; d.fwdT.push(e.t); break; }
      case "egress": { const it = d.nqBy.get(e.fid); if (it){ it.ts = e.t; it.te = e.t_end; } break; }
      case "deliver": d.deliv.push(e.t); d.lat.push(e); break;
    }
  }
}
function addNotes(d, notes){ if (!notes.length) return false; d.notes.push(...notes); d.notes.sort((x, y) => x.t - y.t); return true; }
// live mode: forget what is far behind the playhead (counters only ever look back with countLE)
function prune(d, t){
  const cut = t - 2000, big = 1500;
  for (const k of ["a2s", "s2b"]) if (d.frames[k].length > big) d.frames[k] = d.frames[k].filter(f => f.arrive >= cut);
  if (d.ctl.length > big * 2) d.ctl = d.ctl.filter(c => c.arrive >= cut);
  for (const k of ["S1", "B"]) if (d.rx[k].length > big) d.rx[k] = d.rx[k].filter(r => r.t >= cut);
  if (d.lat.length > big) d.lat = d.lat.slice(-300);
  if (d.swq.length > big){ d.swq = d.swq.filter(i => i.tout == null || i.tout >= cut); d.swqBy = new Map(d.swq.map(i => [i.fid, i])); }
  if (d.nq.length > big){ d.nq = d.nq.filter(i => i.te == null || i.te >= cut); d.nqBy = new Map(d.nq.map(i => [i.fid, i])); }
  for (const k in d.snaps){ const arr = d.snaps[k]; if (arr.length > big){ d.snaps[k] = arr.slice(Math.max(0, lastAt(arr, cut))); } }
}
// everything the pictures need at time t
function view(d, t){
  const snap = k => { const a = d.snaps[k]; return a[Math.max(0, lastAt(a, t))]; };
  const v = {t, A:snap("A"), S1:snap("S1"), S7:snap("S7"), B:snap("B"), ser:{}, rx:{}, cin:{A:null, S7:null}, last:{S1:null, B:null}};
  for (const dir of ["a2s", "s2b"]){
    const L = d.frames[dir]; let s = null;
    for (let i = L.length - 1; i >= 0; i--){ const f = L[i]; if (f.t1 < t - 40) break; if (f.t0 <= t && t < f.t1){ s = f; break; } }
    v.ser[dir] = s;
  }
  for (const k of ["S1", "B"]){ const L = d.rx[k], i = lastAt(L, t); v.rx[k] = i >= 0 && t - L[i].t <= 14 ? L[i] : null; }
  for (let i = d.ctl.length - 1; i >= 0; i--){
    const c = d.ctl[i]; if (c.t1 < t - 400) break;
    const to = REVTO[c.dir], from = REVFROM[c.dir]; if (!to) continue;
    if (!v.cin[to] && c.fate === "ok" && c.arrive <= t && t - c.arrive < 16) v.cin[to] = c;
    if (!v.last[from] && c.t1 <= t) v.last[from] = c;
  }
  v.swq = d.swq.filter(i => i.tin <= t && (i.tout == null || t < i.tout));
  v.nq = []; v.wr = null;
  for (const i of d.nq){ if (i.tin > t) continue; if (i.ts == null || t < i.ts) v.nq.push(i); else if (t < i.te) v.wr = i; }
  const li = lastAt(d.lat, t); v.li = li;
  v.next = countLE(d.firsts, t) + 1; v.deliv = countLE(d.deliv, t); v.fwd = countLE(d.fwdT, t);
  v.down = [isDown(d, 0, t), isDown(d, 1, t)];
  v.rep = {A:countLE(d.replays.A, t), S7:countLE(d.replays.S7, t)}; v.drop = {S1:countLE(d.drops.S1, t), B:countLE(d.drops.B, t)};
  return v;
}
function noteIdx(d, t){ let r = -1; for (let i = 0; i < d.notes.length; i++){ if (d.notes[i].t <= t + 1e-6) r = i; else break; } return r; }

// one frame's journey through the path, as dated steps (for the inspector)
function frameHistory(d, fid){
  const steps = [], add = (t, at, kind, text) => steps.push({t, at, kind, text});
  const fate = f => f.fate === "ok" ? "" : (f.fate === "bad" ? " · corrupted on the cable" : " · lost: cable down");
  const verdict = {accept:"accepted", bad:"FCS bad: discarded", ooo:"out of order: discarded", dup:"duplicate: dropped"};
  for (const [dir, h, tx, rx] of [["a2s", 1, "A", "S1"], ["s2b", 2, "S7", "B"]]){
    for (const f of d.frames[dir]) if (f.fid === fid && f.kind === "data"){
      add(f.t0, tx, f.replay ? "replay" : "send", `${f.replay ? "replayed" : "sent"} on hop ${h} as LLR seq ${f.seq}${fate(f)}`);
      if (f.fate !== "down") add(f.arrive, rx, "arrive", `last bit arrives at ${WHERE[rx][0]}`);
    }
    for (const r of d.rx[rx]) if (r.fid === fid && r.kind === "data") add(r.t, rx, r.res === "accept" ? "ok" : "bad", verdict[r.res]);
  }
  const q = d.swqBy.get(fid); if (q && q.tout != null) add(q.tout, "S7", "fwd", "port 7 takes it out of the switch buffer; XPU A's credits for it are freed");
  const n = d.nqBy.get(fid); if (n && n.ts != null){ add(n.ts, "B", "dma", "DMA write into HBM starts"); add(n.te, "B", "deliver", "in XPU B's HBM"); }
  const dl = d.lat.find(e => e.fid === fid); if (dl) add(dl.t, "B", "lat", `end-to-end latency ${dl.lat.toFixed(1)} ns from XPU A's queue`);
  steps.sort((a, b) => a.t - b.t);
  return steps;
}

return {ALL1, SENDER, REVTO, REVFROM, WHERE, PROB, lastAt, countLE, isDown, newData, ingest, addNotes, prune, view, noteIdx, frameHistory};
})();
