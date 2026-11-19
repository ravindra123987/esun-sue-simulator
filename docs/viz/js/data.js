// Data layer: turns simulator events (traces.js, or batches from tools/live.py) into what the
// pictures and panels need at a given time. No DOM here.
window.SUE = window.SUE || {};
SUE.data = (function(){
"use strict";
const ALL1 = (1 << 20) - 1;
const SENDER = {a2s:"A", s2b:"S7", s2a:"S1", b2s:"B"}, REVTO = {s2a:"A", b2s:"S7"}, REVFROM = {s2a:"S1", b2s:"B"};
const WHERE = {A:["XPU A", "dev-a"], S1:["Switch · port 1", "dev-s"], S7:["Switch · port 7", "dev-s"], B:["XPU B", "dev-b"],
  h1:["Hop 1 cable", "muted"], h2:["Hop 2 cable", "muted"], cmd:["You", "accent"]};
const PROB = new Set(["bad", "nack", "ooo", "timer", "flush", "overflow", "stall", "down", "cc", "fill", "gap", "goback", "fatal", "fail", "rnack", "rtimer"]);

const lastAt = (arr, t) => { let lo = 0, hi = arr.length - 1, r = -1; while (lo <= hi){ const m = (lo + hi) >> 1; if (arr[m].t <= t){ r = m; lo = m + 1; } else hi = m - 1; } return r; };
const countLE = (arr, t) => { let lo = 0, hi = arr.length; while (lo < hi){ const m = (lo + hi) >> 1; if (arr[m] <= t) lo = m + 1; else hi = m; } return lo; };
const isDown = (d, h, t) => d.cfg.hops[h].down.some(([a, b]) => a <= t && t < b);

function newData(meta, cfg){
  return {id:meta.id, title:meta.title, summary:meta.summary, watch:meta.watch, result:meta.result || null, cfg, kind:cfg.kind || "link",
    frames:{a2s:[], s2b:[], s2a:[], b2s:[]}, ctl:[], snaps:{A:[], S1:[], S7:[], B:[]}, rx:{S1:[], B:[], S7:[], A:[]},
    swq:[], swqBy:new Map(), swq2:[], swq2By:new Map(), nq:[], nqBy:new Map(), seqFid:{a2s:new Map(), s2b:new Map(), s2a:new Map(), b2s:new Map()},
    firsts:[], deliv:[], lat:[], lastCtl:new Map(), replays:{A:[], S7:[], S1:[], B:[]}, drops:{S1:[], B:[], S7:[], A:[]}, fwdT:[], notes:[], dur:cfg.sim_ns || 0,
    // endpoint scenarios (sim/suet.py events)
    pk:new Map(), pkts:[], pktRx:[], txns:new Map(), txnList:[], txnDone:[], rodl:[],
    epBase:{A:epZero(), B:epZero()}};          // live mode: totals of what prune() has forgotten
}
function epZero(){
  return {nextPsn:0, sent:0, acked:-1, expect:0, accepted:0, received:0, done:0, failed:0, retx:0, nacksTx:0, acksTx:0, acksData:0,
    lastDone:null, pay:0, wire:0, nreq:0, npdu:0, pkts:0};
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
          if (e.mac === "S7" && !d.swq2By.has(e.fid)){ const it = {fid:e.fid, tin:e.t, tout:null}; d.swq2.push(it); d.swq2By.set(e.fid, it); }
          if (e.mac === "B" && !d.nqBy.has(e.fid)){ const it = {fid:e.fid, tin:e.t, ts:null, te:null}; d.nq.push(it); d.nqBy.set(e.fid, it); }
        }
        break; }
      case "fwd": { const it = (e.mac === "S7" ? d.swq2By : d.swqBy).get(e.fid); if (it) it.tout = e.t; if (e.mac !== "S7") d.fwdT.push(e.t); break; }
      case "egress": { const it = e.mac === "B" ? d.nqBy.get(e.fid) : null; if (it){ it.ts = e.t; it.te = e.t_end; } break; }
      case "deliver": d.deliv.push(e.t); d.lat.push(e); break;
      case "txn_in": { const x = {in:e, pk:null, done:null}; d.txns.set(e.id, x); d.txnList.push(x); break; }
      case "pkt_tx": { d.pk.set(e.fid, e); d.pkts.push(e); for (const id of e.pdus){ const x = d.txns.get(id); if (x && !x.pk) x.pk = e; } break; }
      case "pkt_rx": d.pktRx.push(e); break;
      case "rodl": d.rodl.push(e); break;
      case "txn": { const x = d.txns.get(e.id); if (x) x.done = e; d.txnDone.push(e); break; }
    }
  }
}
function addNotes(d, notes){ if (!notes.length) return false; d.notes.push(...notes); d.notes.sort((x, y) => x.t - y.t); return true; }
// live mode: forget what is far behind the playhead (counters only ever look back with countLE)
function prune(d, t){
  const cut = t - 2000, big = 1500;
  for (const k in d.frames) if (d.frames[k].length > big) d.frames[k] = d.frames[k].filter(f => f.arrive >= cut);
  if (d.ctl.length > big * 2) d.ctl = d.ctl.filter(c => c.arrive >= cut);
  for (const k in d.rx) if (d.rx[k].length > big) d.rx[k] = d.rx[k].filter(r => r.t >= cut);
  if (d.lat.length > big) d.lat = d.lat.slice(-300);
  if (d.swq.length > big){ d.swq = d.swq.filter(i => i.tout == null || i.tout >= cut); d.swqBy = new Map(d.swq.map(i => [i.fid, i])); }
  if (d.nq.length > big){ d.nq = d.nq.filter(i => i.te == null || i.te >= cut); d.nqBy = new Map(d.nq.map(i => [i.fid, i])); }
  for (const k in d.snaps){ const arr = d.snaps[k]; if (arr.length > big){ d.snaps[k] = arr.slice(Math.max(0, lastAt(arr, cut))); } }
  if (d.swq2.length > big){ d.swq2 = d.swq2.filter(i => i.tout == null || i.tout >= cut); d.swq2By = new Map(d.swq2.map(i => [i.fid, i])); }
  if (d.kind === "endpoint" && (d.pkts.length > big || d.txnList.length > big * 4)) pruneEp(d, cut);
}
// fold endpoint events older than `cut` into d.epBase so epState's totals stay right
function pruneEp(d, cut){
  for (const r of d.pktRx){
    if (r.t >= cut) continue;
    const b = d.epBase[r.xpu]; if (!b) continue;
    if (r.cack != null && r.cack > b.acked) b.acked = r.cack;
    if (r.res === "accept"){ b.expect = r.psn + 1; b.accepted++; const p = d.pk.get(r.fid); if (p) b.received += p.n; }
  }
  d.pktRx = d.pktRx.filter(r => r.t >= cut);
  const keep = [];
  for (const p of d.pkts){
    if (p.t >= cut){ keep.push(p); continue; }
    const b = d.epBase[p.xpu]; if (!b) continue;
    b.wire += p.size + 20; b.pkts++;
    if (p.kind === "ack"){ b.acksTx++; if (p.nack >= 0) b.nacksTx++; if (p.data) b.acksData++; b.pay += p.pay; }
    else if (p.retx) b.retx++;
    else { b.nextPsn = Math.max(b.nextPsn, p.psn + 1); b.sent++; b.nreq++; b.npdu += p.n; b.pay += p.pay; }
    d.pk.delete(p.fid);
  }
  d.pkts = keep;
  for (const e of d.txnDone){ if (e.t >= cut) continue; const b = d.epBase[e.xpu]; if (!b) continue; if (e.ok){ b.done++; b.lastDone = e; } else b.failed++; }
  d.txnDone = d.txnDone.filter(e => e.t >= cut);
  d.txnList = d.txnList.filter(x => { const old = x.pk && x.pk.t < cut && (!x.done || x.done.t < cut); if (old) d.txns.delete(x.in.id); return !old; });
  d.rodl = d.rodl.filter(e => e.t >= cut);
}
// the SUE-T endpoint at XPU x, as of time t (endpoint scenarios are small: a linear pass is fine)
function epState(d, x, t){
  const s = Object.assign({queued:[], lastRx:null}, d.epBase[x] || epZero());
  for (const q of d.txnList){ const i = q.in; if (i.xpu !== x || i.t > t) continue; if (!q.pk || q.pk.t > t) s.queued.push(i.id); }
  for (const p of d.pkts){
    if (p.xpu !== x || p.t > t) continue;
    s.wire += p.size + 20; s.pkts++;
    if (p.kind === "ack"){ s.acksTx++; if (p.nack >= 0) s.nacksTx++; if (p.data) s.acksData++; s.pay += p.pay; }
    else if (p.retx) s.retx++;
    else { s.nextPsn = Math.max(s.nextPsn, p.psn + 1); s.sent++; s.nreq++; s.npdu += p.n; s.pay += p.pay; }
  }
  for (const r of d.pktRx){
    if (r.xpu !== x || r.t > t) continue;
    if (r.cack != null && r.cack > s.acked) s.acked = r.cack;
    if (r.res === "accept"){ s.expect = r.psn + 1; s.accepted++; const p = d.pk.get(r.fid); if (p) s.received += p.n; }
    if (r.res !== "ack") s.lastRx = r;
  }
  for (const e of d.txnDone){ if (e.xpu !== x || e.t > t) continue; if (e.ok){ s.done++; s.lastDone = e; } else s.failed++; }
  s.unacked = Math.max(0, s.nextPsn - s.acked - 1);
  s.eff = s.wire ? s.pay / s.wire : 0; s.packAvg = s.nreq ? s.npdu / s.nreq : 0;
  return s;
}
// everything the pictures need at time t
function view(d, t){
  const snap = k => { const a = d.snaps[k]; return a[Math.max(0, lastAt(a, t))]; };
  const v = {t, A:snap("A"), S1:snap("S1"), S7:snap("S7"), B:snap("B"), ser:{}, rx:{}, cin:{A:null, S7:null}, last:{S1:null, B:null}};
  for (const dir in d.frames){
    const L = d.frames[dir]; let s = null;
    for (let i = L.length - 1; i >= 0; i--){ const f = L[i]; if (f.t1 < t - 40) break; if (f.t0 <= t && t < f.t1){ s = f; break; } }
    v.ser[dir] = s;
  }
  for (const k in d.rx){ const L = d.rx[k], i = lastAt(L, t); v.rx[k] = i >= 0 && t - L[i].t <= 14 ? L[i] : null; }
  for (let i = d.ctl.length - 1; i >= 0; i--){
    const c = d.ctl[i]; if (c.t1 < t - 400) break;
    const to = REVTO[c.dir], from = REVFROM[c.dir]; if (!to) continue;
    if (!v.cin[to] && c.fate === "ok" && c.arrive <= t && t - c.arrive < 16) v.cin[to] = c;
    if (!v.last[from] && c.t1 <= t) v.last[from] = c;
  }
  v.swq = d.swq.filter(i => i.tin <= t && (i.tout == null || t < i.tout));
  v.swq2 = d.swq2.filter(i => i.tin <= t && (i.tout == null || t < i.tout));
  v.nq = []; v.wr = null;
  for (const i of d.nq){ if (i.tin > t) continue; if (i.ts == null || t < i.ts) v.nq.push(i); else if (t < i.te) v.wr = i; }
  const li = lastAt(d.lat, t); v.li = li;
  v.next = countLE(d.firsts, t) + 1; v.deliv = countLE(d.deliv, t); v.fwd = countLE(d.fwdT, t);
  v.down = [isDown(d, 0, t), isDown(d, 1, t)];
  v.rep = {A:countLE(d.replays.A, t), S7:countLE(d.replays.S7, t), S1:countLE(d.replays.S1, t), B:countLE(d.replays.B, t)};
  v.drop = {S1:countLE(d.drops.S1, t), B:countLE(d.drops.B, t), S7:countLE(d.drops.S7, t), A:countLE(d.drops.A, t)};
  if (d.kind === "endpoint") v.ep = {A:epState(d, "A", t), B:epState(d, "B", t)};
  return v;
}
function noteIdx(d, t){ let r = -1; for (let i = 0; i < d.notes.length; i++){ if (d.notes[i].t <= t + 1e-6) r = i; else break; } return r; }

// what a frame carries in an endpoint scenario: {kind:"req"|"ack", label, psn, n, ...} or null
function pktOf(d, fid){ return d.kind === "endpoint" ? d.pk.get(fid) || null : null; }
function pktLabel(p, long){
  if (!p) return null;
  if (p.kind === "ack") return p.nack >= 0 ? `NACK ${p.nack}` : (p.data ? `ACK+${p.data}` : `ACK ${p.cack}`);
  return `PSN ${p.psn}` + (long ? ` ×${p.n}` : "");
}

// one frame's journey through the path, as dated steps (for the inspector)
function frameHistory(d, fid){
  const steps = [], add = (t, at, kind, text) => steps.push({t, at, kind, text});
  const fate = f => f.fate === "ok" ? "" : (f.fate === "bad" ? " · corrupted on the cable" : " · lost: cable down");
  const verdict = {accept:"accepted", bad:"FCS bad: discarded", ooo:"out of order: discarded", dup:"duplicate: dropped"};
  const p = pktOf(d, fid);
  if (p) add(p.t, p.xpu, "pack", p.kind === "ack" ? `${pktLabel(p)} packet (${p.size} B)${p.data ? `: data of ${p.data} load(s)` : ""} to XPU ${p.dst}`
    : `${p.retx ? "resent as" : "sent as"} PSN ${p.psn} to XPU ${p.dst}: ${p.n} transaction(s), ${p.size} B` + (p.cack >= 0 ? `, carrying ACK ${p.cack}` : "") + (p.nack >= 0 ? `, carrying NACK ${p.nack}` : ""));
  for (const [dir, h, tx, rx] of [["a2s", 1, "A", "S1"], ["s2b", 2, "S7", "B"], ["b2s", 2, "B", "S7"], ["s2a", 1, "S1", "A"]]){
    for (const f of d.frames[dir]) if (f.fid === fid && f.kind === "data"){
      add(f.t0, tx, f.replay ? "replay" : "send", `${f.replay ? "replayed" : "sent"} on hop ${h} as LLR seq ${f.seq}${fate(f)}`);
      if (f.fate !== "down") add(f.arrive, rx, "arrive", `last bit arrives at ${WHERE[rx][0]}`);
    }
    for (const r of d.rx[rx]) if (r.fid === fid && r.kind === "data") add(r.t, rx, r.res === "accept" ? "ok" : "bad", verdict[r.res]);
  }
  const q = d.swqBy.get(fid); if (q && q.tout != null) add(q.tout, "S7", "fwd", "port 7 takes it out of the switch buffer; XPU A's credits for it are freed");
  const q2 = d.swq2By.get(fid); if (q2 && q2.tout != null) add(q2.tout, "S1", "fwd", "port 1 takes it out of port 7's buffer; XPU B's credits for it are freed");
  const n = d.nqBy.get(fid); if (n && n.ts != null){ add(n.ts, "B", "dma", "DMA write into HBM starts"); add(n.te, "B", "deliver", d.kind === "endpoint" ? "handed to XPU B's SUE-T" : "in XPU B's HBM"); }
  for (const r of d.pktRx) if (r.fid === fid){
    const txt = {accept:`RODL accepts PSN ${r.psn}: in order`, dup:`RODL drops PSN ${r.psn}: duplicate, ACK repeated`, gap:`RODL drops PSN ${r.psn}: it expects ${r.expect} (NACK once)`, ack:`ACK state applied: cack ${r.cack}${r.nack >= 0 ? `, NACK ${r.nack}` : ""}`}[r.res];
    add(r.t, r.xpu, r.res === "gap" ? "bad" : "ok", txt);
  }
  const dl = d.lat.find(e => e.fid === fid); if (dl) add(dl.t, "B", "lat", `end-to-end latency ${dl.lat.toFixed(1)} ns from XPU A's queue`);
  steps.sort((a, b) => a.t - b.t);
  return steps;
}
// one transaction's life (endpoint scenarios): issued, packed, sent, accepted, completed
function txnHistory(d, id){
  const x = d.txns.get(id); if (!x) return [];
  const steps = [], add = (t, at, kind, text) => steps.push({t, at, kind, text});
  const i = x.in;
  add(i.t, i.xpu, "issue", i.kind === "resp" ? `XPU ${i.xpu}'s response to #${i.ref} queued as a ${i.op === "load" ? i.size + " B data" : "16 B"} command for XPU ${i.dst}`
    : `${i.op} of ${i.size} B to XPU ${i.dst} issued by the XPU, queued per {destination, TC ${i.tc}}`);
  for (const p of d.pkts) if (p.pdus.includes(id)) add(p.t, p.xpu, p.retx ? "replay" : "pack", `${p.retx ? "resent" : "packed"} in PSN ${p.psn} (frame #${p.fid}) with ${p.n - 1} other${p.n === 2 ? "" : "s"}, ${p.size} B`);
  for (const p of d.pkts) if (p.pdus.includes(id)) for (const r of d.pktRx) if (r.fid === p.fid && r.res !== "ack")
    add(r.t, r.xpu, r.res === "accept" ? "ok" : "bad", {accept:`PSN ${p.psn} accepted at XPU ${r.xpu}; the transaction goes to its XPU`, dup:`PSN ${p.psn} arrived again: duplicate dropped`, gap:`PSN ${p.psn} arrived out of order: dropped, NACK`}[r.res]);
  if (x.done) add(x.done.t, x.done.xpu, x.done.ok ? "done" : "fail", x.done.ok ? `complete: ${x.done.lat.toFixed(0)} ns after issue` : "failed: the PDC was closed");
  steps.sort((a, b) => a.t - b.t);
  return steps;
}

return {ALL1, SENDER, REVTO, REVFROM, WHERE, PROB, lastAt, countLE, isDown, newData, ingest, addNotes, prune, view, noteIdx, frameHistory, txnHistory, pktOf, pktLabel};
})();
