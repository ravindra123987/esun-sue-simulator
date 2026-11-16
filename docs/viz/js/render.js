// Canvas rendering: the path picture (XPU A -> switch -> XPU B), the flow graph and the timeline
// marks. drawPath also records hit regions so the app can tell what was clicked.
window.SUE = window.SUE || {};
SUE.render = (function(){
"use strict";
const {ALL1, view, noteIdx, PROB, pktOf, pktLabel} = SUE.data;

// ---------------------------------------------------------------- theme + helpers
let C = {};
const TOK = ["bg","surface","surface-2","fg","muted","line","accent","canvas","grid","chassis","chassis-line","block","block-line","block-hd","data","cc","ack","cf","init","bad","down","ok","mem","dev-a","dev-s","dev-b"];
function readTheme(){ const cs = getComputedStyle(document.documentElement); for (const k of TOK) C[k] = cs.getPropertyValue("--" + k).trim(); }
const alpha = (hex, a) => { const m = hex.replace("#", ""); const n = parseInt(m.length === 3 ? m.split("").map(x => x + x).join("") : m, 16); return `rgba(${n>>16&255},${n>>8&255},${n&255},${a})`; };
const MONO = "'JetBrains Mono', ui-monospace, Menlo, monospace", BODY = "Inter, system-ui, sans-serif";

function fit(cv, lw, lh){
  const r = cv.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.round(r.width * dpr)), h = Math.max(1, Math.round(r.height * dpr));
  if (cv.width !== w || cv.height !== h){ cv.width = w; cv.height = h; }
  const g = cv.getContext("2d");
  if (lw) g.setTransform(dpr * r.width / lw, 0, 0, dpr * r.height / lh, 0, 0); else g.setTransform(dpr, 0, 0, dpr, 0, 0);
  return [g, lw || r.width, lh || r.height];
}
function rr(g, x, y, w, h, r){ g.beginPath(); g.roundRect ? g.roundRect(x, y, w, h, r) : g.rect(x, y, w, h); }
function T(g, s, x, y, o = {}){
  g.font = `${o.w || 400} ${o.s || 12}px ${o.m ? MONO : BODY}`;
  g.fillStyle = o.c || C.fg; g.textAlign = o.a || "left"; g.textBaseline = o.b || "alphabetic";
  g.fillText(s, x, y);
}
function tw(g, s, size, weight, mono){ g.font = `${weight || 400} ${size}px ${mono ? MONO : BODY}`; return g.measureText(s).width; }
function chassis(g, [x, y, w, h], name, sub, col){
  rr(g, x, y, w, h, 14); g.fillStyle = C.chassis; g.fill(); g.strokeStyle = C["chassis-line"]; g.lineWidth = 1.2; g.stroke();
  rr(g, x, y, w, 4, [14, 14, 0, 0]); g.fillStyle = col; g.fill();
  g.beginPath(); g.arc(x + 20, y + 22, 5, 0, 7); g.fillStyle = col; g.fill();
  T(g, name, x + 32, y + 27, {s:16, w:700});
  T(g, sub, x + 32 + tw(g, name, 16, 700) + 10, y + 27, {s:11.5, c:C.muted});
}
function region(g, [x, y, w, h], label){
  rr(g, x, y, w, h, 10); g.strokeStyle = alpha(C["chassis-line"], .8); g.lineWidth = 1; g.setLineDash([5, 4]); g.stroke(); g.setLineDash([]);
  T(g, label, x + 10, y + 15, {s:11, w:600, c:C.muted});
}
function stage(g, key, title, sub, o = {}){
  const [x, y, w, h] = R[key];
  HIT.blocks.push({key, x, y, w, h});
  rr(g, x + .5, y + .5, w - 1, h - 1, 8);
  g.fillStyle = C.block; g.fill(); if (o.fill){ g.fillStyle = o.fill; g.fill(); }
  const hov = cur.hover && cur.hover.kind === "block" && cur.hover.key === key, sel = cur.sel && cur.sel.kind === "block" && cur.sel.key === key;
  g.strokeStyle = sel ? C.accent : (o.hot || (hov ? C["chassis-line"] : C["block-line"])); g.lineWidth = sel ? 2 : (o.hot ? 2 : 1); g.setLineDash(o.dim ? [4, 3] : []); g.stroke(); g.setLineDash([]);
  if (o.hot || sel){ g.save(); rr(g, x + .5, y + .5, w - 1, h - 1, 8); g.clip(); g.fillStyle = alpha(sel ? C.accent : o.hot, .07); g.fillRect(x, y, w, h); g.restore(); }
  T(g, title, x + 10, y + 21, {s:13, w:700, c:o.dim ? C.muted : C.fg});
  if (sub) T(g, sub, x + 10, y + 37, {s:11, c:C.muted});
}
function pill(g, cx, cy, s, col, o = {}){
  const fs = o.s || 11, w = tw(g, s, fs, 700, o.m) + 16, h = fs + 9;
  rr(g, cx - w/2, cy - h/2, w, h, h/2); g.fillStyle = alpha(col, o.solid ? .9 : .14); g.fill(); g.strokeStyle = col; g.lineWidth = 1.2; g.stroke();
  T(g, s, cx, cy + .5, {s:fs, w:700, a:"center", b:"middle", c:o.solid ? C.surface : col, m:o.m});
  return w;
}
function gauge(g, x, y, w, h, frac, col){
  rr(g, x, y, w, h, h/2); g.fillStyle = C["surface-2"]; g.fill(); g.strokeStyle = C["block-line"]; g.lineWidth = 1; g.stroke();
  if (frac > 0){ rr(g, x, y, Math.max(h, w * Math.min(1, frac)), h, h/2); g.fillStyle = col; g.fill(); }
}
function bar(g, x, y, w, p, col){ rr(g, x, y, w, 4, 2); g.fillStyle = C["surface-2"]; g.fill(); rr(g, x, y, w * Math.max(0, Math.min(1, p)), 4, 2); g.fillStyle = col; g.fill(); }
// a packet: body plus a solid header band at the leading edge; o.fid makes it clickable and selectable
function pkt(g, x, y, w, h, col, label, o = {}){
  const dir = o.dir || 1;
  if (o.fid != null) HIT.frames.push({fid:o.fid, x, y, w:Math.max(8, w), h});
  const sel = o.fid != null && cur.sel && cur.sel.kind === "frame" && cur.sel.fid === o.fid;
  if (sel){ rr(g, x - 3, y - 3, Math.max(2, w) + 6, h + 6, 5); g.fillStyle = alpha(C.accent, .22); g.fill(); }
  rr(g, x, y, Math.max(2, w), h, 3); g.fillStyle = alpha(col, o.op != null ? o.op : .22); g.fill();
  g.setLineDash(o.dash ? [4, 2.5] : []); g.strokeStyle = sel ? C.accent : col; g.lineWidth = sel ? 2 : 1.3; g.stroke(); g.setLineDash([]);
  const hw = Math.min(6, w * .2);
  if (w > 7){ g.fillStyle = col; dir > 0 ? g.fillRect(x + w - hw, y + 1, hw - 1, h - 2) : g.fillRect(x + 1, y + 1, hw - 1, h - 2); }
  if (label && w > 24) T(g, label, x + w/2 - dir * hw/2, y + h/2 + .5, {s:o.fs || 11, w:600, a:"center", b:"middle", m:true, c:o.tc || C.fg});
}
function cell(g, x, y, w, h, lab, fid, fill, stroke, tc){
  if (fid != null) HIT.frames.push({fid, x, y, w, h});
  const sel = fid != null && cur.sel && cur.sel.kind === "frame" && cur.sel.fid === fid;
  rr(g, x, y, w, h, 3); g.fillStyle = sel ? alpha(C.accent, .35) : fill; g.fill();
  g.strokeStyle = sel ? C.accent : stroke; g.lineWidth = sel ? 2 : 1; g.stroke();
  T(g, lab, x + w/2, y + h/2 + .5, {s:10, w:600, a:"center", b:"middle", m:true, c:tc});
}
function line(g, x0, y0, x1, y1, col, wdt, dash){ g.strokeStyle = col; g.lineWidth = wdt || 1; g.setLineDash(dash || []); g.beginPath(); g.moveTo(x0, y0); g.lineTo(x1, y1); g.stroke(); g.setLineDash([]); }
function head(g, x, y, col, dir = 1){ g.fillStyle = col; g.beginPath(); g.moveTo(x + 4 * dir, y); g.lineTo(x - 3 * dir, y - 4.5); g.lineTo(x - 3 * dir, y + 4.5); g.closePath(); g.fill(); }
const ctlStyle = k => ({LLR_ACK:["ack", "ACK"], LLR_NACK:["ack", "NACK"], CF_UPDATE:["cf", "CF"], LLR_INIT:["init", "INIT"], LLR_INIT_ECHO:["init", "ECHO"]}[k] || ["muted", k]);
const ctlLabel = c => { const [, lab] = ctlStyle(c.kind); return c.kind === "CF_UPDATE" ? (c.cf != null ? `CF ${c.cf}` : "CF") : `${lab} ${c.seq === ALL1 ? "–" : c.seq}`; };
const fidOf = (d, dir, seq) => { const f = d.seqFid[dir].get(seq); return f == null ? null : f; };
// endpoint scenarios label frames by what they carry (PSN ×n, ACK) and colour ACKs and response commands; link scenarios use the frame id
const fl = (d, fid, long) => { const p = pktOf(d, fid); return p ? pktLabel(p, long) : "#" + fid; };
const fcol = (d, fid, dflt) => { const p = pktOf(d, fid); return !p ? dflt : (p.kind === "ack" ? C.ack : (p.tc % 2 ? C.mem : dflt)); };
// a transaction waiting in a SUE-T queue (endpoint scenarios); clickable and selectable like a frame
function txcell(g, x, y, w, h, id, op){
  HIT.txns.push({id, x, y, w, h});
  const sel = cur.sel && cur.sel.kind === "txn" && cur.sel.id === id;
  if (sel){ rr(g, x - 3, y - 3, w + 6, h + 6, 5); g.fillStyle = alpha(C.accent, .22); g.fill(); }
  rr(g, x, y, w, h, 3); g.fillStyle = alpha(C.mem, op); g.fill(); g.strokeStyle = sel ? C.accent : C.mem; g.lineWidth = sel ? 2 : 1.2; g.stroke();
  T(g, "#" + id, x + w/2, y + h/2 + .5, {s:10.5, w:600, a:"center", b:"middle", m:true});
}

// ---------------------------------------------------------------- layout (logical 1440 x 540)
const W = 1440, H = 540, LT = 184, LR = 262;
const CH = {A:[16, 44, 300, 484], S:[516, 44, 408, 484], B:[1124, 44, 300, 484]};
const R = {
  nicA:[108, 74, 202, 446], hbmA:[30, 96, 70, 416], cred:[118, 96, 88, 204], llrA:[212, 96, 90, 204], rbA:[118, 312, 184, 200],
  p1:[528, 96, 100, 204], c1:[528, 312, 100, 200], sbuf:[638, 96, 126, 416], p7:[774, 96, 138, 204], rb7:[774, 312, 138, 200],
  nicB:[1132, 74, 202, 446], rxB:[1140, 96, 90, 204], cB:[1140, 312, 90, 200], bufB:[1236, 96, 90, 416], hbmB:[1338, 96, 74, 416],
  h1:[316, LT - 56, 200, LR - LT + 116], h2:[924, LT - 56, 200, LR - LT + 116],
};
const BLOCK_NAMES = {hbmA:"XPU A · HBM send queue", cred:"XPU A · credit gate", llrA:"XPU A · LLR transmit", rbA:"XPU A · replay buffer",
  p1:"Switch · port 1 RX", c1:"Switch · port 1 control TX", sbuf:"Switch · ingress buffer", p7:"Switch · port 7 TX", rb7:"Switch · port 7 replay buffer",
  rxB:"XPU B · port RX", cB:"XPU B · control TX", bufB:"XPU B · RX buffer", hbmB:"XPU B · HBM", h1:"Hop 1 cable", h2:"Hop 2 cable"};
const EP_NAMES = {hbmA:"XPU A · SUE-T transmit queue", hbmB:"XPU B · SUE-T receive", sbuf:"Switch · ingress buffers"};
const blockName = (d, key) => (d.kind === "endpoint" && EP_NAMES[key]) || BLOCK_NAMES[key] || key;
const STATE_COL = s => ({ADVANCE:C.ok, REPLAY:C.ack, INIT:C.init, FLUSH:C.bad}[s] || C.muted);
const STATE_TXT = {ADVANCE:"normal", REPLAY:"replaying", INIT:"re-syncing", FLUSH:"gave up"};
const stateTxt = (s, det) => det ? s : (STATE_TXT[s] || s);

let cur = {mode:"simple", sel:null, hover:null};
const HIT = {blocks:[], frames:[], txns:[]};

function drawPath(cv, d, t, opts){
  cur = opts;
  HIT.blocks.length = 0; HIT.frames.length = 0; HIT.txns.length = 0;
  const [g] = fit(cv, W, H);
  g.fillStyle = C.canvas; g.fillRect(0, 0, W, H);
  g.fillStyle = C.grid; for (let x = 12; x < W; x += 24) for (let y = 12; y < H; y += 24) g.fillRect(x, y, 1.3, 1.3);
  const v = view(d, t), det = opts.mode === "detail", llrOn = d.cfg.llr.enabled;

  const ep = d.kind === "endpoint";
  chassis(g, CH.A, "XPU A", ep ? "SUE-T instance" : "sender", C["dev-a"]);
  chassis(g, CH.S, "Switch", ep ? "store-and-forward · both directions" : "store-and-forward · lookup XPU B → port 7", C["dev-s"]);
  chassis(g, CH.B, "XPU B", ep ? "SUE-T instance" : "receiver", C["dev-b"]);
  region(g, R.nicA, "NIC · port 0 · 800G");
  region(g, R.nicB, "NIC · port 0 · 800G");
  for (const k of ["h1", "h2"]){ const [x, y, w, h] = R[k]; HIT.blocks.push({key:k, x, y, w, h}); }

  for (const [x0, x1, on] of [[100, 316, !!v.ser.a2s], [516, 924, v.swq.length > 0 || !!v.ser.s2b], [1124, 1338, v.nq.length > 0 || !!v.wr]])
    line(g, x0, LT, x1, LT, on ? alpha(C.data, .55) : alpha(C.muted, .35), 1.5);
  for (const [x, on] of [[109, v.ser.a2s && !v.ser.a2s.replay], [209, !!v.ser.a2s], [633, v.swq.length > 0], [769, !!v.ser.s2b], [1233, v.nq.length > 0], [1332, !!v.wr]])
    head(g, x, LT, on ? C.data : alpha(C.muted, .6));

  drawSender(g, d, t, v, "A", det, llrOn);
  drawReceiver(g, d, t, v, "S1", det, llrOn);
  drawSender(g, d, t, v, "S7", det, llrOn);
  drawReceiver(g, d, t, v, "B", det, llrOn);
  drawSwitchBuffer(g, d, t, v, det);
  drawNicB(g, d, t, v, det);
  drawHbmA(g, d, v);
  drawCable(g, d, t, v, 0, 316, 516, det);
  drawCable(g, d, t, v, 1, 924, 1124, det);
  drawPulse(g, d, t);
  return v;
}

function drawHbmA(g, d, v){
  const [x, y, w, h] = R.hbmA;
  if (d.kind === "endpoint"){
    const e = v.ep.A, ids = e.queued;
    stage(g, "hbmA", "SUE-T", "TX queue", {fill:alpha(C.mem, .05)});
    T(g, `${ids.length} queued`, x + 10, y + 51, {s:11, c:C.muted});
    let i = 0;
    for (; i < ids.length; i++){ const yy = LT - 11 + i * 26; if (yy + 22 > y + h - 78) break; txcell(g, x + 8, yy, w - 16, 22, ids[i], i === 0 ? .32 : .12); }
    if (i < ids.length) T(g, `+${ids.length - i}`, x + w/2, LT - 11 + i * 26 + 15, {s:11, w:600, a:"center", c:C.muted});
    if (!ids.length) T(g, "empty", x + w/2, LT + 4, {s:11.5, a:"center", c:C.muted});
    T(g, "next PSN", x + w/2, y + h - 60, {s:10, a:"center", c:C.muted}); T(g, String(e.nextPsn), x + w/2, y + h - 46, {s:12, w:700, a:"center", m:true});
    T(g, `${e.unacked} unacked`, x + w/2, y + h - 32, {s:10, a:"center", c:e.unacked ? C.fg : C.muted});
    T(g, `done ${e.done}`, x + w/2, y + h - 20, {s:10, a:"center", c:C.muted});
    if (e.failed) T(g, `failed ${e.failed}`, x + w/2, y + h - 8, {s:10, w:700, a:"center", c:C.bad});
    return;
  }
  stage(g, "hbmA", "HBM", "", {fill:alpha(C.mem, .05)});
  T(g, "send", x + 10, y + 37, {s:11, c:C.muted}); T(g, "queue", x + 10, y + 51, {s:11, c:C.muted});
  for (let i = 0; ; i++){
    const yy = LT - 11 + i * 26; if (yy + 22 > y + h - 40) break;
    pkt(g, x + 8, yy, w - 16, 22, C.data, "#" + (v.next + i), {op:i === 0 ? .32 : .1, fs:10.5, fid:v.next + i});
  }
  T(g, "always", x + w/2, y + h - 22, {s:10.5, a:"center", c:C.muted}); T(g, "full", x + w/2, y + h - 9, {s:10.5, a:"center", c:C.muted});
}

// XPU A's NIC (credits + LLR TX, two blocks) or switch port 7 (one block): the sender of a hop
function drawSender(g, d, t, v, k, det, llrOn){
  const a = v[k], dir = k === "A" ? "a2s" : "s2b", ser = v.ser[dir], cin = v.cin[k], st = a.stalled;
  const sc = STATE_COL(a.llr);
  const credLine = (x, y, w) => {
    T(g, "credits", x, y, {s:11, c:C.muted}); T(g, `${a.cr_used} / ${a.cl}`, x + w, y, {s:12, w:700, a:"right", m:true, c:st ? C.bad : C.fg});
    gauge(g, x, y + 6, w, 8, a.cr_used / a.cl, st ? C.bad : (a.cr_used / a.cl > .75 ? C.init : C.cf));
  };
  const serDraw = (x, w) => {
    if (ser){
      const col = ser.kind === "cc_update" ? C.cc : fcol(d, ser.fid, C.data);
      pkt(g, x, LT - 11, w, 22, col, ser.kind === "cc_update" ? "CC" : fl(d, ser.fid), {dash:ser.replay, fs:11, fid:ser.kind === "data" ? ser.fid : null});
      bar(g, x, LT + 16, w, (t - ser.t0) / (ser.t1 - ser.t0), ser.replay ? C.ack : col);
    } else T(g, "idle", x + w/2, LT + 4, {s:11, a:"center", c:C.muted});
  };
  const statusTxt = () => ser ? (ser.replay ? [`resending ${fl(d, ser.fid)}`, C.ack] : [ser.kind === "cc_update" ? "sending CC_Update" : `sending ${fl(d, ser.fid)}`, C.data])
    : (st ? ["waiting for credits", C.bad] : (llrOn && a.llr === "INIT" ? ["INIT sent", C.init] : ["", C.muted]));
  const cinTxt = () => { if (!cin) return null; const [kk] = ctlStyle(cin.kind);
    return [cin.kind === "CF_UPDATE" ? "← CF_Update: credits back" : cin.kind === "LLR_ACK" ? `← ACK ${cin.seq}: buffer freed` :
      cin.kind === "LLR_NACK" ? `← NACK ${cin.seq}: replay!` : `← ${ctlLabel(cin)}`, C[kk]]; };
  const llrRows = (x, y, w) => {
    const rows = [["next seq", a.tx_seq], ["acked", a.acked === ALL1 ? "–" : a.acked], ["retries", `${a.replay_ct}/${d.cfg.llr.replay_ct_max}`]];
    rows.forEach(([kk, vv], i) => { T(g, kk, x, y + i * 15, {s:10.5, c:C.muted}); T(g, String(vv), x + w, y + i * 15, {s:10.5, w:700, a:"right", m:true}); });
    g.beginPath(); g.arc(x + 4, y + 3 * 15 - 4, 3.5, 0, 7); g.fillStyle = a.timer ? C.init : alpha(C.muted, .3); g.fill();
    T(g, a.timer ? "timer running" : "timer idle", x + 12, y + 3 * 15, {s:10.5, c:a.timer ? C.init : C.muted});
  };

  if (k === "A"){
    { const [x, y, w, h] = R.cred;
      stage(g, "cred", "Credits", "CBFC gate", {hot:st ? C.bad : null});
      T(g, `${a.cr_used}`, x + w/2, y + 64, {s:18, w:700, a:"center", m:true, c:st ? C.bad : C.fg});
      gauge(g, x + 10, y + 72, w - 20, 7, a.cr_used / a.cl, st ? C.bad : (a.cr_used / a.cl > .75 ? C.init : C.cf));
      pill(g, x + w/2, LT + 2, st ? "STOP" : "GO", st ? C.bad : C.ok, {s:11.5});
      T(g, `of ${a.cl} in use`, x + w/2, y + 122, {s:11, a:"center", c:C.muted});
      const ci = cin && cin.kind === "CF_UPDATE";
      if (ci) T(g, "← CF_Update", x + w/2, y + 142, {s:11, w:700, a:"center", c:C.cf});
      else if (st) T(g, "wait for CF", x + w/2, y + 142, {s:11, w:600, a:"center", c:C.bad});
      if (det){ T(g, "1 KB frame", x + w/2, y + 172, {s:10.5, a:"center", c:C.muted}); T(g, "= 16 credits", x + w/2, y + 184, {s:10.5, a:"center", c:C.muted}); }
    }
    { const [x, y, w, h] = R.llrA;
      stage(g, "llrA", "LLR TX", "retry · MAC", {hot:llrOn && a.llr !== "ADVANCE" ? sc : (ser ? alpha(C.data, .8) : null), dim:!llrOn});
      if (llrOn) pill(g, x + w/2, y + 62, stateTxt(a.llr, det), sc, {s:det ? 10 : 11, m:det});
      else T(g, "LLR off", x + w/2, y + 64, {s:12, w:700, a:"center", c:C.muted});
      serDraw(x + 9, w - 18);
      const [s1, c1] = statusTxt(); if (s1) T(g, s1, x + w/2, y + 128, {s:11, w:600, a:"center", c:c1});
      const ci = cinTxt();
      if (det && llrOn) llrRows(x + 9, y + 146, w - 18);
      else if (ci && cin.kind !== "CF_UPDATE") T(g, ci[0].split(":")[0], x + w/2, y + 148, {s:11, w:700, a:"center", c:ci[1]});
    }
  } else {
    const [x, y, w, h] = R.p7;
    stage(g, "p7", "Port 7 TX", "to XPU B", {hot:st ? C.bad : (llrOn && a.llr !== "ADVANCE" ? sc : (ser ? alpha(C.data, .8) : null))});
    if (llrOn){ const s = stateTxt(a.llr, det), pw = tw(g, s, 10, 700, det) + 16; pill(g, x + w - 10 - pw/2, y + 33, s, sc, {s:10, m:det}); }
    else T(g, "LLR off", x + w - 10, y + 37, {s:11, w:700, a:"right", c:C.muted});
    credLine(x + 10, y + 58, w - 20);
    serDraw(x + 10, w - 20);
    const [s1, c1] = statusTxt(); if (s1) T(g, s1, x + w/2, y + 128, {s:11, w:600, a:"center", c:c1});
    const ci = cinTxt();
    if (det && llrOn) llrRows(x + 10, y + 146, w - 20);
    else if (ci) T(g, ci[0], x + w/2, y + 148, {s:11, w:700, a:"center", c:ci[1]});
  }
  // replay buffer
  const key = k === "A" ? "rbA" : "rb7", [x, y, w, h] = R[key];
  stage(g, key, "Replay buffer", llrOn ? `${a.nbuf} frame${a.nbuf === 1 ? "" : "s"} kept until ${k === "A" ? "port 1" : "XPU B"} ACKs` : "not used: LLR off",
    {dim:!llrOn, fill:llrOn ? alpha(C.mem, .04) : null, hot:llrOn && (a.llr === "REPLAY" || a.llr === "FLUSH") ? sc : null});
  if (!llrOn) return;
  const rep = a.llr === "REPLAY", cw = 27, ch = 20, gap = 3, cols = Math.floor((w - 20 + gap) / (cw + gap)), rows = Math.floor((h - 60 + gap) / (ch + gap));
  const n = a.nbuf, show = Math.min(n, cols * rows - (n > cols * rows ? 1 : 0));
  for (let i = 0; i < show; i++){
    const sq = (a.buf0 + i) & ALL1, cx = x + 10 + (i % cols) * (cw + gap), cy = y + 48 + Math.floor(i / cols) * (ch + gap);
    const fid = fidOf(d, dir, sq), isCC = fid === "CC", live = ser && ser.replay && ser.seq === sq, lab = det ? String(sq) : (fid == null ? "" : String(fid));
    cell(g, cx, cy, cw, ch, lab, isCC ? null : fid, live ? C.ack : alpha(rep ? C.ack : (isCC ? C.cc : C.data), .16), rep ? C.ack : alpha(isCC ? C.cc : C.data, .65), live ? C.surface : C.fg);
  }
  if (n > show) T(g, `+${n - show}`, x + 10 + (show % cols) * (cw + gap) + cw/2, y + 48 + Math.floor(show / cols) * (ch + gap) + ch/2 + .5, {s:10, w:700, a:"center", b:"middle", c:C.muted});
  if (!n) T(g, "empty", x + w/2, y + 80, {s:11.5, a:"center", c:C.muted});
  T(g, det ? "cells show LLR seq" : "cells show frame #", x + 10, y + h - 9, {s:10, c:C.muted});
}

// switch port 1 or XPU B's NIC port: the receiver of a hop, and the control blocks it sends back
function drawReceiver(g, d, t, v, k, det, llrOn){
  const b = v[k], rx = v.rx[k], rxKey = k === "S1" ? "p1" : "rxB", ctKey = k === "S1" ? "c1" : "cB", back = k === "S1" ? "XPU A" : "port 7";
  { const [x, y, w, h] = R[rxKey];
    const vc = rx ? ({accept:C.ok, bad:C.bad, ooo:C.ack, dup:C.muted}[rx.res]) : null;
    stage(g, rxKey, k === "S1" ? "Port 1 RX" : "Port RX", llrOn ? "FCS · LLR RX" : "FCS check", {hot:rx && rx.res !== "accept" ? vc : null});
    if (llrOn){ T(g, "next seq", x + 10, y + 60, {s:11, c:C.muted}); T(g, String(b.next_rx), x + w - 10, y + 60, {s:12, w:700, a:"right", m:true}); }
    if (rx){
      const op = Math.max(.35, 1 - (t - rx.t) / 14);
      g.globalAlpha = op;
      g.beginPath(); g.arc(x + w/2, LT, 14, 0, 7); g.fillStyle = alpha(vc, .16); g.fill(); g.strokeStyle = vc; g.lineWidth = 1.6; g.stroke();
      T(g, rx.res === "accept" ? "✓" : "✕", x + w/2, LT + 1, {s:16, w:700, a:"center", b:"middle", c:vc});
      const why = {accept:"accepted", bad:"FCS bad", ooo:"out of order", dup:"duplicate"}[rx.res];
      T(g, why, x + w/2, y + 124, {s:11, w:700, a:"center", c:vc}); T(g, rx.kind === "data" ? fl(d, rx.fid) : "CC", x + w/2, y + 138, {s:11, w:700, a:"center", m:true, c:vc});
      g.globalAlpha = 1;
      if (rx.kind === "data") HIT.frames.push({fid:rx.fid, x:x + 10, y:y + 112, w:w - 20, h:32});
    } else T(g, "listening", x + w/2, LT + 4, {s:11, a:"center", c:C.muted});
    if (llrOn && b.ack_state !== "SEND_ACKS") pill(g, x + w/2, y + 158, b.ack_state === "SEND_NACK" ? "NACK due" : "NACK sent", C.ack, {s:10.5});
    if (det && llrOn){ T(g, "acks", x + 10, y + 180, {s:10.5, c:C.muted}); T(g, b.ack_state.replace("SEND_", "").replace("_", " "), x + w - 10, y + 180, {s:10.5, w:700, a:"right", m:true});
      T(g, "drops", x + 10, y + 195, {s:10.5, c:C.muted}); T(g, String(v.drop[k]), x + w - 10, y + 195, {s:10.5, w:700, a:"right", m:true, c:v.drop[k] ? C.bad : C.fg}); }
  }
  { const [x, y, w, h] = R[ctKey], c = v.last[k];
    stage(g, ctKey, "Control TX", `back to ${back}`);
    if (c){
      const [kk] = ctlStyle(c.kind), fresh = t - c.t1 < 18;
      g.globalAlpha = fresh ? 1 : .55;
      pill(g, x + w/2, y + 62, ctlLabel(c), C[kk], {s:11.5, m:true, solid:fresh && c.news && c.kind !== "LLR_ACK"});
      g.globalAlpha = 1;
      const what = c.kind === "LLR_ACK" && c.seq === ALL1 ? ["nothing received", "yet (all ones)"] :
        !c.news ? ["repeat: nothing", "new to report"] : {LLR_ACK:["frees the replay", "buffer up to it"], LLR_NACK:["replay after", "this seq"], CF_UPDATE:["returns credits", "to the sender"],
        LLR_INIT_ECHO:["confirms the", "INIT"], LLR_INIT:["re-syncs", "sequence numbers"]}[c.kind] || ["", ""];
      T(g, what[0], x + w/2, y + 90, {s:10.5, a:"center", c:C.muted}); T(g, what[1], x + w/2, y + 104, {s:10.5, a:"center", c:C.muted});
      if (c.fate !== "ok") T(g, c.fate === "down" ? "lost: cable down" : "lost: corrupted", x + w/2, y + 124, {s:10.5, w:700, a:"center", c:C.bad});
    }
    T(g, "one 8 B block", x + w/2, y + h - 26, {s:10, a:"center", c:C.muted}); T(g, "every 20 ns", x + w/2, y + h - 12, {s:10, a:"center", c:C.muted});
  }
}

function stack(g, d, items, x, w, ymax, col = C.data){
  const rows = Math.floor((ymax - (LT - 11)) / 26);
  const n = Math.min(items.length, items.length > rows ? rows - 1 : rows);
  for (let i = 0; i < n; i++) pkt(g, x, LT - 11 + i * 26, w, 22, fcol(d, items[i].fid, col), fl(d, items[i].fid), {fs:11, fid:items[i].fid});
  if (items.length > n) T(g, `+${items.length - n} more`, x + w/2, LT - 11 + n * 26 + 15, {s:11, w:600, a:"center", c:C.muted});
}

function drawSwitchBuffer(g, d, t, v, det){
  const [x, y, w, h] = R.sbuf, tot = d.cfg.credits.S1, occ = v.S1.occ, frac = occ / tot;
  stage(g, "sbuf", "Ingress buffer", `port 1 · VC0 · ${(tot * d.cfg.credit_size / 1024).toFixed(0)} KB`, {fill:alpha(C.mem, .05), hot:frac > .75 ? C.init : null});
  T(g, `${occ} / ${tot}`, x + 10, y + 60, {s:11.5, w:700, m:true}); T(g, "credits", x + w - 10, y + 60, {s:11, a:"right", c:C.muted});
  gauge(g, x + 10, y + 68, w - 20, 8, frac, frac > .75 ? C.init : C.mem);
  stack(g, d, v.swq, x + 10, w - 20, y + h - 26);
  if (!v.swq.length) T(g, "empty", x + w/2, LT + 4, {s:11.5, a:"center", c:C.muted});
  if (d.kind === "endpoint" && v.swq2.length) T(g, `+ ${v.swq2.length} waiting the other way`, x + w/2, y + h - 24, {s:10.5, a:"center", c:C.mem});
  T(g, `forwarded ${v.fwd}`, x + w/2, y + h - 10, {s:10.5, a:"center", c:C.muted});
}

function drawNicB(g, d, t, v, det){
  const g8 = d.cfg.nic_gbps, slow = g8 < d.cfg.rate_gbps;
  { const [x, y, w, h] = R.bufB, tot = d.cfg.credits.B, occ = v.B.occ, frac = occ / tot;
    stage(g, "bufB", "RX buffer", `VC0 · ${(tot * d.cfg.credit_size / 1024).toFixed(0)} KB`, {fill:alpha(C.mem, .05), hot:frac > .75 ? C.init : null});
    T(g, `${occ}/${tot}`, x + 10, y + 60, {s:11, w:700, m:true});
    gauge(g, x + 10, y + 68, w - 20, 8, frac, frac > .75 ? C.init : C.mem);
    stack(g, d, v.nq, x + 8, w - 16, y + h - 64);
    if (!v.nq.length) T(g, "empty", x + w/2, LT + 4, {s:11.5, a:"center", c:C.muted});
    const dy = y + h - 54;
    line(g, x + 8, dy - 6, x + w - 8, dy - 6, C["block-line"]);
    T(g, "DMA → HBM", x + 10, dy + 9, {s:10.5, w:700});
    T(g, `${g8} Gb/s`, x + 10, dy + 24, {s:10.5, w:700, m:true, c:slow ? C.bad : C.muted});
    if (v.wr){ bar(g, x + 10, dy + 30, w - 20, (t - v.wr.ts) / (v.wr.te - v.wr.ts), C.mem); T(g, "writing #" + v.wr.fid, x + 10, dy + 46, {s:10, w:600, c:C.mem}); HIT.frames.push({fid:v.wr.fid, x:x + 8, y:dy + 28, w:w - 16, h:22}); }
  }
  { const [x, y, w, h] = R.hbmB;
    if (d.kind === "endpoint"){
      const e = v.ep.B;
      stage(g, "hbmB", "SUE-T", "RX · XPU", {fill:alpha(C.mem, .05)});
      T(g, "expects", x + w/2, y + 52, {s:10, a:"center", c:C.muted}); T(g, `PSN ${e.expect}`, x + w/2, y + 66, {s:12, w:700, a:"center", m:true});
      const acc = [];
      for (let i = d.pktRx.length - 1; i >= 0 && acc.length < 12; i--){ const r = d.pktRx[i]; if (r.t <= t && r.xpu === "B" && r.res === "accept") acc.push(r); }
      for (let i = 0; i < acc.length; i++){
        const yy = LT - 11 + i * 26; if (yy + 22 > y + h - 50) break;
        const p = d.pk.get(acc[i].fid), fresh = i === 0 && t - acc[i].t < 12;
        pkt(g, x + 8, yy, w - 16, 22, C.mem, p ? `P${p.psn}` : "#" + acc[i].fid, {op:fresh ? .45 : .14, fs:10.5, fid:acc[i].fid});
      }
      T(g, `${e.received} received`, x + w/2, y + h - 32, {s:10, a:"center", c:C.muted});
      if (e.done) T(g, `done ${e.done}`, x + w/2, y + h - 20, {s:10, a:"center", c:C.muted});
      if (e.lastRx && e.lastRx.res !== "accept" && t - e.lastRx.t < 60) pill(g, x + w/2, y + h - 8, e.lastRx.res === "gap" ? "GAP" : "DUP", C.bad, {s:10});
      return;
    }
    stage(g, "hbmB", "HBM", "frames in", {fill:alpha(C.mem, .05)});
    T(g, String(v.deliv), x + w/2, y + 64, {s:18, w:700, a:"center", m:true});
    for (let i = 0; i < 12 && v.li - i >= 0; i++){
      const e = d.lat[v.li - i], yy = LT - 11 + i * 26; if (yy + 22 > y + h - 42) break;
      const fresh = i === 0 && t - e.t < 12;
      pkt(g, x + 8, yy, w - 16, 22, C.mem, "#" + e.fid, {op:fresh ? .45 : .14, fs:10.5, fid:e.fid});
    }
    if (v.li >= 0){ T(g, "last", x + w/2, y + h - 24, {s:10, a:"center", c:C.muted}); T(g, `${d.lat[v.li].lat.toFixed(0)} ns`, x + w/2, y + h - 10, {s:10.5, w:700, a:"center", m:true}); }
  }
}

// one hop's cable: ports at both ends, frames left to right on the top lane, control blocks back on the bottom lane
function drawCable(g, d, t, v, h, xa, xb, det){
  const hc = d.cfg.hops[h], down = v.down[h], prop = hc.prop_ns, dir = h ? "s2b" : "a2s", rdir = h ? "b2s" : "s2a";
  const key = h ? "h2" : "h1", sel = cur.sel && cur.sel.kind === "block" && cur.sel.key === key;
  if (sel){ const [x, y, w, hh] = R[key]; rr(g, x, y, w, hh, 10); g.fillStyle = alpha(C.accent, .06); g.fill(); g.strokeStyle = C.accent; g.lineWidth = 1.5; g.stroke(); }
  for (const x of [xa, xb]){
    for (const y of [LT, LR]){ rr(g, x - 8, y - 12, 16, 24, 3); g.fillStyle = C["block-hd"]; g.fill(); g.strokeStyle = C["chassis-line"]; g.lineWidth = 1; g.stroke(); }
    g.beginPath(); g.arc(x, LT - 22, 3.6, 0, 7); g.fillStyle = down ? C.bad : C.ok; g.fill();
  }
  const cx = (xa + xb) / 2;
  T(g, `Hop ${h + 1}`, cx, LT - 40, {s:12.5, w:700, a:"center", c:down ? C.bad : C.fg});
  T(g, `${hc.cable_m} m · ${d.cfg.rate_gbps}G · ${prop.toFixed(0)} ns`, cx, LT - 25, {s:10.5, a:"center", c:C.muted});
  g.lineWidth = 2; g.strokeStyle = down ? alpha(C.bad, .7) : alpha(C["chassis-line"], .9); g.setLineDash(down ? [6, 5] : []);
  for (const y of [LT, LR]){ g.beginPath(); g.moveTo(xa + 8, y); g.lineTo(xb - 8, y); g.stroke(); }
  g.setLineDash([]);
  const ep = d.kind === "endpoint", yc = ep ? LR + 26 : LR;        // where the control blocks travel
  if (!down) T(g, ep ? "packets →" : "data →", xa + 14, LT + 46, {s:10.5, c:C.muted});
  if (ep){ T(g, "← ACKs · responses", xb - 14, LR - 18, {s:10.5, a:"right", c:C.muted}); line(g, xa + 8, yc, xb - 8, yc, alpha(C["chassis-line"], .5), 1, [2, 4]); }
  T(g, det ? "← ACK · NACK · CF (faded: repeats)" : "← ACK · NACK · CF (new info only)", xb - 14, yc + 30, {s:10.5, a:"right", c:C.muted});
  if (down) T(g, "CABLE DOWN", cx, LT + 50, {s:13, w:700, a:"center", c:C.bad});
  const L = xb - xa - 16, px = f => xa + 8 + f * L, fh = 24;
  for (const f of d.frames[dir]){
    if (f.t0 > t || f.arrive < t) continue;
    const front = (t - f.t0) / prop, back = (t - f.t1) / prop;
    if (front <= 0 || back >= 1) continue;
    const x0 = px(Math.max(0, back)), x1 = px(Math.min(1, front));
    let col = f.kind === "cc_update" ? C.cc : fcol(d, f.fid, C.data), op = .22, tc = C.fg;
    if (f.fate === "bad" && front > .5){ col = C.bad; tc = C.bad; }
    if (f.fate === "down"){ col = C.down; op = .1; tc = C.muted; g.globalAlpha = Math.max(.15, 1 - front); }
    pkt(g, x0, LT - fh/2, x1 - x0, fh, col, f.kind === "cc_update" ? "CC" : fl(d, f.fid), {dash:f.replay || f.fate === "down", op, tc, fs:11, fid:f.kind === "data" ? f.fid : null});
    if (f.fate === "bad" && front > .5 && back < .5) T(g, "⚡ bit error", px(.5), LT - fh/2 - 6, {s:11, w:700, a:"center", c:C.bad});
    g.globalAlpha = 1;
  }
  if (ep) for (const f of d.frames[rdir]){                          // packets going the other way, right to left
    if (f.t0 > t || f.arrive < t) continue;
    const front = (t - f.t0) / prop, back = (t - f.t1) / prop;
    if (front <= 0 || back >= 1) continue;
    const x0 = px(1 - Math.min(1, front)), x1 = px(1 - Math.max(0, back));
    let col = f.kind === "cc_update" ? C.cc : fcol(d, f.fid, C.data), tc = C.fg;
    if (f.fate === "bad" && front > .5){ col = C.bad; tc = C.bad; }
    pkt(g, x0, LR - fh/2, x1 - x0, fh, col, f.kind === "cc_update" ? "CC" : fl(d, f.fid), {dash:f.replay, op:.22, tc, fs:11, fid:f.kind === "data" ? f.fid : null, dir:-1});
    if (f.fate === "bad" && front > .5 && back < .5) T(g, "⚡ bit error", px(.5), LR + fh/2 + 12, {s:11, w:700, a:"center", c:C.bad});
  }
  for (const c of d.ctl){
    if (c.dir !== rdir && c.dir !== dir) continue;
    if (c.t1 > t || c.arrive < t) continue;
    const f = (t - c.t1) / prop; if (f < 0 || f > 1) continue;
    const fwd = c.dir === dir, quiet = !c.news;
    if (quiet && !det) continue;
    const [kk] = ctlStyle(c.kind), lab = ctlLabel(c);
    const x = fwd ? px(f) : px(1 - f), y = fwd ? LT + 22 : yc;
    const w = tw(g, lab, 10.5, 700, true) + 12, hh = 17;
    g.globalAlpha = quiet ? .28 : (c.fate === "ok" ? 1 : Math.max(.2, 1 - f));
    let col = C[kk]; if (c.fate !== "ok" && f > .5) col = c.fate === "down" ? C.down : C.bad;
    rr(g, x - w/2, y - hh/2, w, hh, 4); g.fillStyle = C.surface; g.fill(); g.fillStyle = alpha(col, .18); g.fill(); g.strokeStyle = col; g.lineWidth = 1.2; g.stroke();
    T(g, lab, x, y + .5, {s:10.5, w:700, a:"center", b:"middle", m:true});
    g.globalAlpha = 1;
  }
}

// a ring around the block the current caption is about, fading over ~25 ns
const PULSE = {A:{stall:"cred", _:"llrA", flush:"rbA"}, S1:{nack:"c1", init:"c1", fill:"sbuf", fwd:"sbuf", _:"p1"}, S7:{flush:"rb7", _:"p7"},
  B:{nack:"cB", init:"cB", fill:"bufB", deliver:"hbmB", _:"rxB"}, h1:{_:"h1"}, h2:{_:"h2"}};
const EP_KINDS = new Set(["issue", "pack", "retx", "ack", "rnack", "gap", "rdup", "goback", "fatal", "done", "fail", "accept", "rtimer"]), EP_BLOCK = {A:"hbmA", B:"hbmB"};
function drawPulse(g, d, t){
  const i = noteIdx(d, t); if (i < 0) return;
  const n = d.notes[i], age = t - n.t; if (age > 25) return;
  const m = PULSE[n.at]; if (!m) return;
  const r = R[(d.kind === "endpoint" && EP_KINDS.has(n.kind) && EP_BLOCK[n.at]) || m[n.kind] || m._]; if (!r) return;
  const k = PROB.has(n.kind) ? C.bad : C.accent, a = 1 - age / 25;
  g.save(); g.globalAlpha = a;
  rr(g, r[0] - 4, r[1] - 4, r[2] + 8, r[3] + 8, 11); g.strokeStyle = k; g.lineWidth = 2.5; g.stroke();
  rr(g, r[0] - 9, r[1] - 9, r[2] + 18, r[3] + 18, 15); g.strokeStyle = alpha(k, .25); g.lineWidth = 5; g.stroke();
  g.restore();
}

// what is under a pointer position (client coordinates) on the path canvas
function hitTest(cv, clientX, clientY){
  const r = cv.getBoundingClientRect(), x = (clientX - r.left) * W / r.width, y = (clientY - r.top) * H / r.height;
  for (let i = HIT.txns.length - 1; i >= 0; i--){ const f = HIT.txns[i]; if (x >= f.x - 2 && x <= f.x + f.w + 2 && y >= f.y - 2 && y <= f.y + f.h + 2) return {kind:"txn", id:f.id}; }
  for (let i = HIT.frames.length - 1; i >= 0; i--){ const f = HIT.frames[i]; if (x >= f.x - 2 && x <= f.x + f.w + 2 && y >= f.y - 2 && y <= f.y + f.h + 2) return {kind:"frame", fid:f.fid}; }
  for (let i = HIT.blocks.length - 1; i >= 0; i--){ const b = HIT.blocks[i]; if (x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h) return {kind:"block", key:b.key}; }
  return null;
}

// ---------------------------------------------------------------- flow graph: four cable ends, time runs down
function drawLadder(cv, d, t, span){
  const [g, Wd, Hd] = fit(cv);
  g.fillStyle = C.surface; g.fillRect(0, 0, Wd, Hd);
  const top = 34, bot = Hd - 16, m = 96, inner = Wd - 2 * m;
  const X = {A:m, S1:m + inner * .42, S7:m + inner * .58, B:Wd - m};
  const t0 = t - span, y = tt => top + (tt - t0) / span * (bot - top);
  T(g, "XPU A", X.A, 16, {s:12, w:700, a:"center"}); T(g, "NIC", X.A, 29, {s:10.5, a:"center", c:C.muted});
  T(g, "Switch", (X.S1 + X.S7)/2, 16, {s:12, w:700, a:"center"}); T(g, "port 1", X.S1, 29, {s:10.5, a:"center", c:C.muted}); T(g, "port 7", X.S7, 29, {s:10.5, a:"center", c:C.muted});
  T(g, "XPU B", X.B, 16, {s:12, w:700, a:"center"}); T(g, "NIC", X.B, 29, {s:10.5, a:"center", c:C.muted});
  const step = span <= 150 ? 25 : span <= 300 ? 50 : span <= 600 ? 100 : 200;
  for (let k = Math.ceil(Math.max(0, t0) / step) * step; k <= t; k += step){ const yy = y(k); line(g, X.A, yy, X.B, yy, alpha(C.muted, .14)); T(g, k + " ns", X.A - 14, yy + 4, {s:10.5, a:"right", c:C.muted, m:true}); }
  d.cfg.hops.forEach((hc, h) => { const [xa, xb] = h ? [X.S7, X.B] : [X.A, X.S1];
    for (const [a, b] of hc.down){ if (b < t0 || a > t) continue; g.fillStyle = alpha(C.bad, .08); g.fillRect(xa, y(Math.max(a, t0)), xb - xa, y(Math.min(b, t)) - y(Math.max(a, t0))); } });
  g.fillStyle = alpha(C["dev-s"], .06); g.fillRect(X.S1, top, X.S7 - X.S1, bot - top);
  for (const k of ["A", "S1", "S7", "B"]) line(g, X[k], top, X[k], bot, C["chassis-line"], 3);
  g.save(); g.beginPath(); g.rect(0, top, Wd, bot - top); g.clip();
  for (const tf of d.fwdT){ if (tf < t0 || tf > t) continue; line(g, X.S1, y(tf), X.S7, y(tf), alpha(C.data, .45), 1, [2, 3]); }
  const selFid = cur.sel && cur.sel.kind === "frame" ? cur.sel.fid : null;
  for (const [h, dir, rdir] of [[0, "a2s", "s2a"], [1, "s2b", "b2s"]]){
    const prop = d.cfg.hops[h].prop_ns, [xa, xb] = h ? [X.S7, X.B] : [X.A, X.S1];
    for (const f of d.frames[dir]){
      if (f.arrive < t0 || f.t0 > t) continue;
      const isSel = selFid != null && f.fid === selFid && f.kind === "data";
      const col = isSel ? C.accent : f.fate === "down" ? C.down : (f.fate === "bad" ? C.bad : (f.kind === "cc_update" ? C.cc : fcol(d, f.fid, C.data)));
      const endF = f.fate === "down" ? .5 : 1, xe = xa + (xb - xa) * endF;
      g.beginPath(); g.moveTo(xa, y(f.t0)); g.lineTo(xe, y(f.t0 + prop * endF)); g.lineTo(xe, y(f.t1 + prop * endF)); g.lineTo(xa, y(f.t1)); g.closePath();
      g.fillStyle = alpha(col, isSel ? .4 : (f.replay ? .1 : .22)); g.fill();
      g.setLineDash(f.replay || f.fate === "down" ? [4, 3] : []); g.strokeStyle = alpha(col, .9); g.lineWidth = isSel ? 2 : 1; g.stroke(); g.setLineDash([]);
      if (f.arrive <= t && f.fate === "bad") T(g, "✕ FCS", xb + 8, y(f.arrive) + 4, {s:10.5, w:700, c:C.bad});
      if (h === 0 && y(f.t1) - y(f.t0) > 10 && f.kind === "data") T(g, fl(d, f.fid), xa - 6, y((f.t0 + f.t1)/2) + 4, {s:10, a:"right", c:isSel ? C.accent : C.muted, m:true, w:isSel ? 700 : 400});
    }
    if (d.kind === "endpoint") for (const f of d.frames[rdir]){      // packets the other way: right to left
      if (f.arrive < t0 || f.t0 > t || f.kind !== "data") continue;
      const isSel = selFid != null && f.fid === selFid;
      const col = isSel ? C.accent : (f.fate === "bad" ? C.bad : fcol(d, f.fid, C.data));
      g.beginPath(); g.moveTo(xb, y(f.t0)); g.lineTo(xa, y(f.t0 + prop)); g.lineTo(xa, y(f.t1 + prop)); g.lineTo(xb, y(f.t1)); g.closePath();
      g.fillStyle = alpha(col, isSel ? .4 : (f.replay ? .1 : .22)); g.fill();
      g.setLineDash(f.replay ? [4, 3] : []); g.strokeStyle = alpha(col, .9); g.lineWidth = isSel ? 2 : 1; g.stroke(); g.setLineDash([]);
      if (h === 1 && y(f.t1) - y(f.t0) > 10) T(g, fl(d, f.fid), xb + 6, y((f.t0 + f.t1)/2) + 4, {s:10, c:isSel ? C.accent : C.muted, m:true, w:isSel ? 700 : 400});
    }
    for (const c of d.ctl){
      if (c.dir !== rdir && c.dir !== dir) continue;
      if (c.arrive < t0 || c.t1 > t) continue;
      if (!c.news && c.kind === "CF_UPDATE") continue;
      if (c.kind === "LLR_ACK" && c.seq === ALL1) continue;
      const [k] = ctlStyle(c.kind), col = c.fate === "ok" ? C[k] : (c.fate === "down" ? C.down : C.bad);
      const [x0, x1] = c.dir === rdir ? [xb, xa] : [xa, xb], endF = c.fate === "ok" ? 1 : .5;
      g.globalAlpha = c.kind === "LLR_ACK" ? .5 : 1;
      line(g, x0, y(c.t1), x0 + (x1 - x0) * endF, y(c.t1 + prop * endF), col, c.kind === "LLR_NACK" || c.kind.startsWith("LLR_INIT") ? 2 : 1, c.fate === "ok" ? [] : [3, 3]);
      if (c.kind !== "LLR_ACK" && c.kind !== "CF_UPDATE")
        T(g, ctlLabel(c) + (c.fate === "ok" ? "" : " (lost)"), x0 + (c.dir === rdir ? 6 : -6), y(c.t1) + 4, {s:10.5, w:700, c:col, a:c.dir === rdir ? "left" : "right", m:true});
      g.globalAlpha = 1;
    }
  }
  g.restore();
  line(g, X.A - 30, bot, X.B + 30, bot, C.accent, 1.5);
  T(g, "now", X.B + 34, bot + 4, {s:10.5, w:700, c:C.accent});
}

// event marks on the timeline strip
function drawMarks(cv, d){
  const [g, Wd, Hd] = fit(cv);
  g.clearRect(0, 0, Wd, Hd);
  if (!d.dur) return;
  for (const hc of d.cfg.hops) for (const [a, b] of hc.down){ g.fillStyle = alpha(C.bad, .16); g.fillRect(a / d.dur * Wd, 0, (b - a) / d.dur * Wd, Hd); }
  for (const n of d.notes){
    g.fillStyle = PROB.has(n.kind) ? C.bad : (n.kind === "replay" ? C.ack : (n.kind === "up" || n.kind === "deliver" ? C.ok : C.accent));
    g.fillRect(Math.round(n.t / d.dur * (Wd - 3)), 3, 3, Hd - 6);
  }
}

return {readTheme, drawPath, drawLadder, drawMarks, hitTest, BLOCK_NAMES, blockName, W, H, color:() => C};
})();
