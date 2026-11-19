// M5 pictures: N XPUs x P planes under one fault, for several recovery designs (tools/planes_trace.py).
// Two views of one scenario: all designs side by side (rows), or one design's fabric in detail.
window.SUE = window.SUE || {};
SUE.planes = (function(){
"use strict";
const W = 1440, H = 540;
const DCOL = {"sue-t":"dev-a", "sue-t+fo":"init", "metaroce":"ok", "mrc":"accent", "mrc+llr":"dev-b", "rodl-spray":"dev-a", "rud-spray":"ok"};
const LLR_COL = ["", "ack", "init", "bad"];          // REPLAY, INIT, FLUSH
let H$ = null, C = null;

function handles(d){ return d.kind === "planes"; }

// ---------------------------------------------------------------- per-design state at time t
function cum(arr2, b){ let s = 0; for (const row of arr2) for (let k = 0; k <= b && k < row.length; k++) s += row[k]; return s; }
function bin(d, t){ return Math.max(0, Math.floor(t / d.cfg.bin_us)); }
function wireDown(d, name, t){ return d.cfg.down.some(w => w.wire === name && w.a <= t && (w.b == null || t < w.b)); }
function stateAt(d, key, t){
  const x = d.extra.designs[key], s = x.series, b = Math.min(bin(d, t), s.bins - 1);
  const ev = x.events.filter(e => e.t <= t);
  const count = w => ev.filter(e => e.what === w).length;
  const done = cum(s.done, b), failed = cum(s.failed, b);
  const bad = {};                                  // "xpu>peer" -> set of bad ports now
  for (const e of ev){ const k = `${e.xpu}>${e.peer}`; if (e.what === "bad"){ (bad[k] = bad[k] || new Set()).add(e.port); } if (e.what === "restore" && bad[k]) bad[k].delete(e.port); }
  const rate = s.done.reduce((a, row) => a + (row[b] || 0), 0);
  return {x, s, b, done, failed, total:s.total, rate, timeouts:count("timeout"), moves:count("move"), bads:count("bad"), restores:count("restore"),
    fatal:count("fatal"), flushes:count("flush"), drops:ev.filter(e => e.what === "sw_drop").length, trims:ev.filter(e => e.what === "sw_trim").length,
    bad, finished:x.finished_us != null && t >= x.finished_us, recent:ev.slice(-6).reverse()};
}
function maxRate(d){
  if (d._maxRate) return d._maxRate;
  let m = 1;
  for (const k of d.extra.order){ const s = d.extra.designs[k].series; for (let b = 0; b < s.bins; b++){ const r = s.done.reduce((a, row) => a + (row[b] || 0), 0); if (r > m) m = r; } }
  return (d._maxRate = m);
}

// ---------------------------------------------------------------- drawing helpers
function spark(g, d, key, x, y, w, h, t){
  const {rr, alpha} = H$, s = d.extra.designs[key].series, mx = maxRate(d), dur = d.dur, col = C[DCOL[key]] || C.accent;
  rr(g, x, y, w, h, 6); g.fillStyle = C["surface-2"]; g.fill();
  const X = tt => x + Math.min(1, tt / dur) * w, Y = r => y + h - 3 - (h - 8) * r / mx;
  const spans = [...new Set(d.cfg.down.map(w0 => `${w0.a}|${w0.b}`))];          // one band per fault interval, not per cable
  for (const sp of spans){ const [a0, b0] = sp.split("|"); const a = X(+a0), b = X(b0 === "null" ? dur : +b0); g.fillStyle = alpha(C.bad, .7); g.fillRect(a, y, Math.max(2, b - a), 3); g.fillStyle = alpha(C.bad, .05); g.fillRect(a, y + 3, Math.max(2, b - a), h - 3);
    g.fillStyle = alpha(C.bad, .55); g.fillRect(a, y, 1, h); }
  g.fillStyle = alpha(C.muted, .35); const stepT = [1, 2, 5, 10, 20, 50, 100].find(v => dur / v <= 12) || 100;       // a tick per round number of µs
  for (let tt = stepT; tt < dur; tt += stepT) g.fillRect(X(tt), y + h - 4, 1, 4);
  for (const pass of [0, 1]){
    g.beginPath(); g.moveTo(X(0), y + h - 3);
    for (let b = 0; b < s.bins; b++){ const tt = b * d.cfg.bin_us; if (pass && tt > t) break; const r = s.done.reduce((a, row) => a + (row[b] || 0), 0); g.lineTo(X(tt), Y(r)); g.lineTo(X(tt + d.cfg.bin_us), Y(r)); }
    g.lineTo(pass ? X(Math.min(t, s.bins * d.cfg.bin_us)) : X(s.bins * d.cfg.bin_us), y + h - 3); g.closePath();
    g.fillStyle = alpha(col, pass ? .55 : .12); g.fill();
  }
  g.strokeStyle = C.accent; g.lineWidth = 1.5; g.beginPath(); g.moveTo(X(t), y + 1); g.lineTo(X(t), y + h - 1); g.stroke();
}
function grid(g, d, key, x, y, cw, chh, t){
  const {rr, alpha, T} = H$, s = d.extra.designs[key].series, b = Math.min(bin(d, t), s.bins - 1), n = d.cfg.n, P = d.cfg.p;
  for (let p = 0; p < P; p++) T(g, `P${p}`, x + p * (cw + 3) + cw/2, y - 4, {s:9.5, a:"center", c:C.muted, m:true});
  for (let i = 0; i < n; i++){
    T(g, `X${i}`, x - 6, y + i * (chh + 3) + chh/2 + 3, {s:9.5, a:"right", c:C.muted, m:true});
    for (let p = 0; p < P; p++){
      const cx = x + p * (cw + 3), cy = y + i * (chh + 3);
      const u = ((s.up[i][p][b] || 0) + (s.dn[i][p][b] || 0)) / 200;
      const dead = wireDown(d, `n${i}p${p}>s${p}`, t) || wireDown(d, `s${p}>n${i}p${p}`, t);
      const lr = Math.max((s.llr[`N${i}.${p}`] || [])[b] || 0, (s.llr[`S${p}.${i}`] || [])[b] || 0);
      rr(g, cx, cy, cw, chh, 2); g.fillStyle = C["surface-2"]; g.fill();
      if (u > 0){ rr(g, cx, cy, cw, chh, 2); g.fillStyle = alpha(C.data, .15 + .75 * Math.min(1, u)); g.fill(); }
      if (lr){ rr(g, cx, cy, cw, chh, 2); g.strokeStyle = C[LLR_COL[lr]]; g.lineWidth = 2; g.stroke(); }
      if (dead){ g.strokeStyle = C.bad; g.lineWidth = 1.5; g.beginPath(); g.moveTo(cx + 2, cy + 2); g.lineTo(cx + cw - 2, cy + chh - 2); g.moveTo(cx + cw - 2, cy + 2); g.lineTo(cx + 2, cy + chh - 2); g.stroke(); }
    }
  }
}
function status(d, st, key){
  if (st.finished) return [`done at ${d.extra.designs[key].finished_us} µs`, C.ok];
  if (st.failed) return [`${st.failed} failed`, C.bad];
  if (d.extra.designs[key].finished_us == null) return ["never finishes", C.bad];
  return ["running", C.muted];
}

// ---------------------------------------------------------------- all designs, one row each
function drawCompare(g, d, t, opts){
  const {T, pill, rr, alpha, HIT} = H$;
  const keys = d.extra.order, rowH = Math.min(100, (H - 56) / keys.length), top = 50;
  T(g, "Five designs, the same fault. Click one to see its fabric.", 24, 30, {s:12.5, c:C.muted});
  T(g, "cable use per XPU × plane", 470, top - 14, {s:11, a:"center", c:C.muted});
  T(g, `stores completed per µs, all XPUs · 0 to ${+d.dur.toFixed(0)} µs · red strip: fault`, 885, top - 14, {s:11, a:"center", c:C.muted});
  const stats = [], rows = {};
  keys.forEach((k, r) => {
    const y = top + r * rowH, st = stateAt(d, k, t), col = C[DCOL[k]] || C.accent;
    rows[k] = st;
    HIT.blocks.push({key:"design:" + k, x:12, y, w:W - 24, h:rowH - 6});
    const hov = opts.hover && opts.hover.kind === "block" && opts.hover.key === "design:" + k;
    rr(g, 12, y, W - 24, rowH - 6, 10); g.fillStyle = hov ? alpha(col, .07) : C.block; g.fill(); g.strokeStyle = hov ? col : C["block-line"]; g.lineWidth = hov ? 1.5 : 1; g.stroke();
    rr(g, 12, y, 5, rowH - 6, [10, 0, 0, 10]); g.fillStyle = col; g.fill();
    T(g, d.extra.designs[k].label, 30, y + 24, {s:14, w:700});
    T(g, d.extra.designs[k].how, 30, y + 42, {s:10.5, c:C.muted});
    const [txt, sc] = status(d, st, k); pill(g, 30 + H$.tw(g, txt, 11, 700) / 2 + 8, y + rowH - 26, txt, sc, {s:11});
    const gh = Math.max(9, (rowH - 30) / d.cfg.n - 3);
    grid(g, d, k, 400, y + 16, 34, gh, t);
    spark(g, d, k, 590, y + 10, 590, rowH - 26, t);
    const pct = Math.round(100 * st.done / st.total), cx = 1210;
    T(g, `${pct}%`, cx, y + 30, {s:20, w:700, m:true, c:st.failed ? C.bad : C.fg});
    T(g, "done", cx, y + 46, {s:10.5, c:C.muted});
    const line = [[`timeouts ${st.timeouts}`, st.timeouts], [st.moves ? `moves ${st.moves}` : `bad marks ${st.bads}`, st.moves + st.bads], [`failed ${st.failed}`, st.failed], [`FLUSH ${st.flushes}`, st.flushes]];
    const lh = Math.min(16, (rowH - 24) / 4);
    line.forEach(([s, v], i) => T(g, s, 1290, y + 22 + i * lh, {s:10.5, m:true, c:v ? (i >= 2 ? C.bad : C.fg) : C.muted}));
    stats.push([d.extra.designs[k].label, [["stores done", `${st.done} of ${st.total}`], ["failed", st.failed, st.failed > 0], ["transport timeouts", st.timeouts],
      ["PDC moves / bad-plane marks / restores", `${st.moves} / ${st.bads} / ${st.restores}`], ["PDCs given up", st.fatal, st.fatal > 0], ["LLR FLUSHes", st.flushes, st.flushes > 0],
      ["switch discards (dead port)", st.drops], ["finished", d.extra.designs[k].finished_us != null ? `${d.extra.designs[k].finished_us} µs` : "not in this run"]]]);
  });
  return {stats, blocks:key => key.startsWith("design:") ? designRows(d, key.slice(7), rows[key.slice(7)]) : null};
}
function designRows(d, k, st){
  const x = d.extra.designs[k];
  return [["design", x.label], ["mechanism", x.how], ["stores done", `${st.done} of ${st.total}`], ["failed", st.failed], ["finished", x.finished_us != null ? `${x.finished_us} µs` : "not in this run"],
    ["transport timeouts so far", st.timeouts], ["recovery so far", `${st.moves} moves · ${st.bads} bad marks · ${st.restores} restores · ${st.fatal} PDCs given up`],
    ["recent", st.recent.length ? st.recent.map(e => `${e.t} µs ${e.what} X${e.xpu ?? ""}${e.peer != null ? "→X" + e.peer : ""}${e.port != null ? " P" + e.port : ""}`).join(" · ") : "–"]];
}

// ---------------------------------------------------------------- one design's fabric
function drawDetail(g, d, t, opts, k){
  const {T, pill, rr, alpha, HIT} = H$;
  const st = stateAt(d, k, t), s = st.s, b = st.b, n = d.cfg.n, P = d.cfg.p, col = C[DCOL[k]] || C.accent;
  HIT.blocks.push({key:"focus:none", x:16, y:12, w:150, h:30});
  rr(g, 16, 12, 150, 30, 15); g.fillStyle = C["surface-2"]; g.fill(); g.strokeStyle = C["block-line"]; g.stroke();
  T(g, "← all designs", 91, 31, {s:12, w:600, a:"center"});
  T(g, d.extra.designs[k].label, 186, 32, {s:16, w:700, c:col}); T(g, d.extra.designs[k].how, 186 + H$.tw(g, d.extra.designs[k].label, 16, 700) + 12, 32, {s:11.5, c:C.muted});
  const xb = [30, 300], sb = [880, 1020], rowH = (H - 70) / n, top = 58;
  const xpY = i => top + i * rowH, swY = p => top + p * ((H - 70) / P);
  // links first (under the boxes)
  for (let i = 0; i < n; i++) for (let p = 0; p < P; p++){
    const x0 = xb[1], y0 = xpY(i) + 22 + p * ((rowH - 34) / (P - 1 || 1)), x1 = sb[0], y1 = swY(p) + 22 + i * (((H - 70) / P - 34) / (n - 1 || 1));
    for (const [dir, off] of [["up", -2], ["dn", 2]]){
      const name = dir === "up" ? `n${i}p${p}>s${p}` : `s${p}>n${i}p${p}`, u = (s[dir][i][p][b] || 0) / 100, dead = wireDown(d, name, t);
      const lr = (s.llr[dir === "up" ? `N${i}.${p}` : `S${p}.${i}`] || [])[b] || 0;
      g.strokeStyle = dead ? alpha(C.bad, .8) : lr ? C[LLR_COL[lr]] : alpha(C.data, .12 + .8 * u);
      g.lineWidth = dead ? 1.2 : 1 + 3 * u; g.setLineDash(dead ? [5, 4] : (dir === "dn" ? [6, 2] : []));
      g.beginPath(); g.moveTo(x0, y0 + off); g.bezierCurveTo((x0 + x1) / 2, y0 + off, (x0 + x1) / 2, y1 + off, x1, y1 + off); g.stroke(); g.setLineDash([]);
    }
  }
  // XPUs
  const rows = {};
  for (let i = 0; i < n; i++){
    const y = xpY(i), h = rowH - 10, key = "xpu:" + i, done = s.done[i].slice(0, b + 1).reduce((a, v) => a + v, 0), fail = s.failed[i].slice(0, b + 1).reduce((a, v) => a + v, 0);
    HIT.blocks.push({key, x:xb[0], y, w:xb[1] - xb[0], h});
    rr(g, xb[0], y, xb[1] - xb[0], h, 10); g.fillStyle = C.chassis; g.fill(); g.strokeStyle = (opts.sel && opts.sel.key === key) ? C.accent : C["chassis-line"]; g.lineWidth = 1.2; g.stroke();
    rr(g, xb[0], y, 4, h, [10, 0, 0, 10]); g.fillStyle = C["dev-a"]; g.fill();
    T(g, `XPU ${i}`, xb[0] + 14, y + 20, {s:13, w:700}); T(g, `${done} done${fail ? ` · ${fail} failed` : ""}`, xb[0] + 80, y + 20, {s:11, c:fail ? C.bad : C.muted});
    const peers = [...Array(n).keys()].filter(j => j !== i);
    peers.forEach((j, r) => {
      const yy = y + 38 + r * 15, pr = s.port[i][j][b], bad = st.bad[`${i}>${j}`];
      T(g, `→ XPU ${j}`, xb[0] + 14, yy, {s:10.5, c:C.muted});
      const spray = k.includes("spray") || ["metaroce", "mrc", "mrc+llr"].includes(k);
      const txt = spray ? (bad && bad.size ? `all but P${[...bad].join(", P")}` : "all planes") : (pr >= 0 ? `port ${pr}` : "idle");
      T(g, txt, xb[0] + 90, yy, {s:10.5, w:600, m:true, c:bad && bad.size ? C.ack : C.fg});
    });
    rows[key] = [["XPU", i], ["stores completed", done], ["failed", fail], ...peers.map(j => [`towards XPU ${j}`, s.port[i][j][b] >= 0 ? `port ${s.port[i][j][b]} carries most packets now` : "nothing sent this µs"])];
    for (let p = 0; p < P; p++){ const yy = y + 22 + p * ((rowH - 34) / (P - 1 || 1)); g.beginPath(); g.arc(xb[1], yy, 3.5, 0, 7); g.fillStyle = C["chassis-line"]; g.fill(); }
  }
  // switches
  for (let p = 0; p < P; p++){
    const y = swY(p), h = (H - 70) / P - 10, key = "sw:" + p, dead = d.cfg.down.filter(w => w.wire.includes(`p${p}`) && w.a <= t && (w.b == null || t < w.b)).length;
    HIT.blocks.push({key, x:sb[0], y, w:sb[1] - sb[0], h});
    rr(g, sb[0], y, sb[1] - sb[0], h, 10); g.fillStyle = C.chassis; g.fill(); g.strokeStyle = (opts.sel && opts.sel.key === key) ? C.accent : C["chassis-line"]; g.lineWidth = 1.2; g.stroke();
    rr(g, sb[0], y, sb[1] - sb[0], 4, [10, 10, 0, 0]); g.fillStyle = C["dev-s"]; g.fill();
    T(g, `Switch · plane ${p}`, sb[0] + 12, y + 22, {s:12.5, w:700});
    const drops = st.x.events.filter(e => e.t <= t && e.what === "sw_drop" && e.plane === p).length;
    T(g, dead ? `${dead} cable${dead > 1 ? "s" : ""} down` : "all cables up", sb[0] + 12, y + 40, {s:10.5, c:dead ? C.bad : C.muted});
    if (drops) T(g, `${drops} discarded`, sb[0] + 12, y + 56, {s:10.5, c:C.bad});
    for (let i = 0; i < n; i++){ const yy = y + 22 + i * (((H - 70) / P - 34) / (n - 1 || 1)); g.beginPath(); g.arc(sb[0], yy, 3.5, 0, 7); g.fillStyle = C["chassis-line"]; g.fill(); }
    rows[key] = [["plane", p], ["cables down now", dead], ["frames discarded for a dead port", drops]];
  }
  // right panel: progress and what happened
  const rx = 1050, rw = W - rx - 20;
  T(g, "stores completed per µs", rx, 74, {s:11, c:C.muted});
  spark(g, d, k, rx, 82, rw, 90, t);
  const [txt, sc] = status(d, st, k); pill(g, rx + H$.tw(g, txt, 11.5, 700) / 2 + 8, 196, txt, sc, {s:11.5});
  const kv = [["done", `${Math.round(100 * st.done / st.total)}%`], ["transport timeouts", st.timeouts], ["PDC moves", st.moves], ["bad marks / restores", `${st.bads} / ${st.restores}`],
    ["PDCs given up", st.fatal], ["LLR FLUSHes", st.flushes]];
  kv.forEach(([a, v], i) => { T(g, a, rx, 226 + i * 18, {s:11, c:C.muted}); T(g, String(v), rx + rw, 226 + i * 18, {s:11, w:700, a:"right", m:true}); });
  T(g, "latest recovery events", rx, 350, {s:11, w:600, c:C.muted});
  st.recent.forEach((e, i) => {
    const txt2 = {timeout:"timeout", move:`moved P${e.frm}→P${e.to}`, bad:`P${e.port} marked bad`, restore:`P${e.port} back`, fatal:"PDC given up", flush:`FLUSH at ${e.mac}`, sw_drop:`sw ${e.plane} discards`, sw_trim:"trim"}[e.what] || e.what;
    T(g, `${e.t.toFixed(1)} µs`, rx, 370 + i * 17, {s:10.5, m:true, c:C.muted});
    T(g, `${e.xpu != null ? `X${e.xpu}→X${e.peer} ` : ""}${txt2}`, rx + 70, 370 + i * 17, {s:10.5, c:["fatal", "flush", "sw_drop"].includes(e.what) ? C.bad : C.fg});
  });
  // legend
  T(g, "solid: XPU → switch · dashed: switch → XPU · thickness = use · amber/red outline: LLR replaying / re-initialising or flushed · red dashes: cable down", W / 2, H - 6, {s:10, a:"center", c:C.muted});
  return {stats:[[d.extra.designs[k].label, kv.concat([["failed", st.failed, st.failed > 0], ["switch discards", st.drops]])]], blocks:key => rows[key] || null};
}

function draw(cv, d, t, opts, helpers){
  H$ = helpers; C = helpers.C;
  helpers.setCur(opts);
  const {fit, HIT} = helpers;
  HIT.blocks.length = 0; HIT.frames.length = 0; HIT.txns.length = 0;
  const [g] = fit(cv, W, H);
  g.fillStyle = C.canvas; g.fillRect(0, 0, W, H);
  g.fillStyle = C.grid; for (let x = 12; x < W; x += 24) for (let y = 12; y < H; y += 24) g.fillRect(x, y, 1.3, 1.3);
  const focus = opts.focus && d.extra.designs[opts.focus] ? opts.focus : null;
  const out = focus ? drawDetail(g, d, t, opts, focus) : drawCompare(g, d, t, opts);
  out.t = t;
  return out;
}

return {handles, draw};
})();
