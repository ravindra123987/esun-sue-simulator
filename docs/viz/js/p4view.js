// M6 picture: one test frame at a time through the P4 switch's pipeline, as bmv2 logged it (tools/p4_trace.py).
// Frame in -> parser -> ingress tables -> queues -> egress -> deparser -> what each XPU received.
window.SUE = window.SUE || {};
SUE.p4 = (function(){
"use strict";
const W = 1440, H = 540, X0 = 20, GAP = 16, BW = (W - 2 * X0 - 6 * GAP) / 7, BY = 76, BH = 296;
const SY = 412, SH = 104;
let H$ = null, C = null;

function handles(d){ return d.kind === "p4"; }
const idxAt = (d, t) => Math.max(0, Math.min(d.extra.frames.length - 1, Math.floor(t / d.cfg.step + 1e-9)));
function stageAt(d, t){ const i = idxAt(d, t); return Math.max(0, Math.min(6, Math.floor((t - i * d.cfg.step) / d.cfg.stage_steps + 1e-9))); }
const hex = v => typeof v === "number" ? v : v;
const FIELD = {dst:"dst id", src:"src id", dscp:"dscp", ecn:"ecn", syn:"syn", psn:"psn", stores:"stores", da:"DA", sa:"SA", cos:"CoS",
  ttl:"TTL", flow_label:"flow label", crc_ok:"CRC", ip_dst:"IP dst", ip_src:"IP src", dport:"UDP dport", ether_type:"ethertype"};
function fields(x){ return Object.keys(x).filter(k => k !== "kind" && k !== "len"); }
function fval(k, v){ return k === "crc_ok" ? (v ? "good" : "BAD") : k === "flow_label" ? "0x" + Number(v).toString(16) : String(hex(v)); }
const short = k => k.startsWith("UFH_16") ? "UFH_16" : k.startsWith("MAC control") ? "MAC ctl" : k.startsWith("UDP") ? "UDP/IP" : k;

// ---------------------------------------------------------------- what each stage shows, as rows [label, value, tone]
function stageRows(f, j){
  const r = [];
  if (j === 0){
    r.push(["kind", f.in.kind], ["length", `${f.in.len} B`], ["arrived on", `port ${f.port_in} (XPU ${f.src})`]);
    for (const k of fields(f.in)) r.push([FIELD[k] || k, fval(k, f.in[k])]);
  } else if (j === 1){
    f.states.forEach((s, i) => r.push([i ? "then" : "state", s]));
    r.push(["headers", f.headers.join(" + ") || "none"]);
    const m = f.msgs.find(x => x.startsWith("parsed ")); if (m) r.push(["log", m.replace(/^parsed /, "")]);
  } else if (j === 2){
    if (!f.tables.length && !f.ttl && !f.dropped) r.push(["tables", "none applied"]);
    for (const tb of f.tables){
      r.push(["table", tb.table], ["key", Object.entries(tb.key).map(([k, v]) => `${k}=${v}`).join(" ")],
        ["result", tb.hit ? `hit → ${tb.action}(${tb.params.join(", ")})` : `miss → default ${tb.action}`, tb.hit ? "ok" : "bad"]);
    }
    if (f.ttl != null) r.push(["TTL", `${f.in.ttl} → ${f.ttl}`, "chg"]);
    if (f.dropped) r.push(["drop", f.drop, "bad"]);
    else r.push(["sends to", `port ${f.egress}, priority ${f.queue}`]);
  } else if (j === 3){
    if (f.dropped) r.push(["port", "511: the drop port", "bad"], ["queued", "no"]);
    else r.push(["port", String(f.egress)], ["queue", `${f.queue} of 0–7`, f.queue ? "chg" : null]);
  } else if (j === 4){
    if (f.dropped) r.push(["reached", "no: dropped in ingress", "muted"]);
    else r.push(["ECN", f.ecn, f.ecn_marked ? "chg" : null]);
  } else if (j === 5){
    if (f.dropped) r.push(["reached", "no: dropped in ingress", "muted"]);
    else r.push(["emitted", f.deparsed.join(" + ") || "–"], ["payload", "carried through unparsed"]);
  } else {
    const ks = Object.keys(f.out);
    if (!ks.length) r.push(["received", "by no XPU", f.dropped ? "bad" : null]);
    for (const k of ks){
      const o = f.out[k];
      r.push([`XPU ${k}`, `${o.kind} · ${o.len} B`, "ok"]);
      for (const fk of fields(o)) r.push([FIELD[fk] || fk, fval(fk, o[fk]), o[fk] !== f.in[fk] ? "chg" : null]);
    }
  }
  return r;
}
const TITLES = [["Frame in", "the bytes the XPU sent"], ["Parser", "states taken, headers extracted"], ["Ingress", "match-action tables"],
  ["Queues", "traffic manager, 8 priorities"], ["Egress", "ECN marking"], ["Deparser", "headers written back"], ["Frame out", "what each XPU received"]];

// ---------------------------------------------------------------- drawing
function wrap(g, s, x, y, w, lh, o, maxLines){
  const {T, tw} = H$; const words = String(s).split(" "); let line = "", n = 0;
  for (const wd of words){
    const nx = line ? line + " " + wd : wd;
    if (line && tw(g, nx, o.s, o.w, o.m) > w){ if (maxLines && n === maxLines - 1){ T(g, line + " …", x, y, o); return y + lh; } T(g, line, x, y, o); y += lh; n++; line = wd; }
    else line = nx;
  }
  if (line){ T(g, line, x, y, o); y += lh; }
  return y;
}
function box(g, d, f, j, cur, opts){
  const {T, rr, alpha, HIT} = H$, x = X0 + j * (BW + GAP), y = BY;
  const past = j < cur, now = j === cur, skip = f.dropped && j >= 3 && j <= 5;
  const hov = opts.hover && opts.hover.kind === "block" && opts.hover.key === "stage:" + j;
  const selk = opts.sel && opts.sel.kind === "block" && opts.sel.key === "stage:" + j;
  HIT.blocks.push({key:"stage:" + j, x, y, w:BW, h:BH});
  rr(g, x, y, BW, BH, 10); g.fillStyle = now ? alpha(C.accent, .06) : C.block; g.fill();
  g.strokeStyle = now || selk ? C.accent : hov ? C.fg : C["block-line"]; g.lineWidth = now || selk ? 2 : 1; g.stroke();
  rr(g, x, y, BW, 4, [10, 10, 0, 0]); g.fillStyle = j === 0 || j === 6 ? C["dev-a"] : C["dev-s"]; g.fill();
  const dim = !(past || now);
  T(g, TITLES[j][0], x + 12, y + 26, {s:13.5, w:700, c:dim ? C.muted : C.fg});
  T(g, TITLES[j][1], x + 12, y + 42, {s:10, c:C.muted});
  if (dim){ T(g, "…", x + BW / 2, y + BH / 2, {s:16, a:"center", c:C.muted}); return; }
  if (skip){ g.globalAlpha = .55; }
  let yy = y + 64;
  if (j === 3 && !f.dropped){                         // the eight queues, the chosen one filled
    const qw = (BW - 24 - 7 * 4) / 8;
    for (let q = 0; q < 8; q++){
      const qx = x + 12 + q * (qw + 4); rr(g, qx, yy, qw, 44, 3);
      g.fillStyle = q === f.queue ? alpha(C.accent, .75) : C["surface-2"]; g.fill(); g.strokeStyle = C["block-line"]; g.lineWidth = 1; g.stroke();
      T(g, String(q), qx + qw / 2, yy + 58, {s:9.5, a:"center", m:true, c:q === f.queue ? C.fg : C.muted});
    }
    yy += 78;
  }
  const rows = stageRows(f, j), LW = 58, bottom = y + BH - 22;
  for (let r = 0; r < rows.length; r++){
    const [k, v, tone] = rows[r];
    if (yy > bottom){ T(g, `+${rows.length - r} more in the inspector`, x + 12, y + BH - 10, {s:9.5, c:C.muted}); break; }
    const col = tone === "bad" ? C.bad : tone === "ok" ? C.ok : tone === "chg" ? C.init : tone === "muted" ? C.muted : C.fg;
    T(g, k, x + 12, yy, {s:9.5, c:C.muted});
    yy = wrap(g, v, x + 12 + LW, yy, BW - 24 - LW, 13, {s:10, m:true, c:col, w:tone === "chg" || tone === "bad" ? 700 : 400}, 6) + 4;
  }
  g.globalAlpha = 1;
}
function arrow(g, j, on){
  const x = X0 + (j + 1) * (BW + GAP) - GAP + 2, y = BY + BH / 2;
  g.fillStyle = on ? C.accent : C["block-line"];
  g.beginPath(); g.moveTo(x, y - 6); g.lineTo(x + GAP - 4, y); g.lineTo(x, y + 6); g.closePath(); g.fill();
}
function strip(g, d, t, opts){
  const {T, rr, alpha, HIT, pill} = H$, fr = d.extra.frames, n = fr.length, cur = idxAt(d, t);
  const tw0 = (W - 2 * X0 - (n - 1) * 8) / n;
  T(g, "All test frames (click one to jump to it)", X0, SY - 10, {s:10.5, c:C.muted});
  fr.forEach((f, i) => {
    const x = X0 + i * (tw0 + 8), y = SY, seen = i < cur || (i === cur && stageAt(d, t) >= (f.dropped ? 2 : 6));
    const hov = opts.hover && opts.hover.kind === "block" && opts.hover.key === "frame:" + i;
    HIT.blocks.push({key:"frame:" + i, x, y, w:tw0, h:SH});
    rr(g, x, y, tw0, SH, 8); g.fillStyle = i === cur ? alpha(C.accent, .08) : C.block; g.fill();
    g.strokeStyle = i === cur ? C.accent : hov ? C.fg : C["block-line"]; g.lineWidth = i === cur ? 2 : 1; g.stroke();
    T(g, `#${i + 1}`, x + 8, y + 18, {s:11, w:700, m:true});
    T(g, short(f.in.kind), x + tw0 - 8, y + 18, {s:10, a:"right", c:C.muted});
    T(g, `from XPU ${f.src}`, x + 8, y + 36, {s:10, c:C.muted});
    if (seen){
      const [txt, col] = f.dropped ? ["dropped", C.bad] : [`→ XPU ${Object.keys(f.out).join(",") || "–"}`, C.ok];
      pill(g, x + tw0 / 2, y + 58, txt, col, {s:10});
      const tags = f.dropped ? "" : [f.queue ? `q${f.queue}` : "", f.ttl != null ? "TTL−1" : "", f.ecn_marked ? "CE" : ""].filter(Boolean).join(" · ");
      if (tags) T(g, tags, x + tw0 / 2, y + 86, {s:10, a:"center", c:C.init, w:700});
    }
  });
}
function draw(cv, d, t, opts, helpers){
  H$ = helpers; C = helpers.C; helpers.setCur(opts);
  const {fit, T, HIT, pill, tw} = helpers;
  HIT.blocks.length = 0; HIT.frames.length = 0; HIT.txns.length = 0;
  const [g] = fit(cv, W, H);
  g.fillStyle = C.canvas; g.fillRect(0, 0, W, H);
  g.fillStyle = C.grid; for (let x = 12; x < W; x += 24) for (let y = 12; y < H; y += 24) g.fillRect(x, y, 1.3, 1.3);
  const i = idxAt(d, t), f = d.extra.frames[i], cur = stageAt(d, t);
  T(g, `Frame ${i + 1} of ${d.extra.frames.length}`, X0, 30, {s:15, w:700});
  T(g, f.check, X0 + tw(g, `Frame ${i + 1} of ${d.extra.frames.length}`, 15, 700) + 14, 30, {s:13, c:C.fg});
  T(g, f.why, X0, 52, {s:10.5, c:C.muted});
  const done = cur >= (f.dropped ? 2 : 6);
  if (done){ const txt = f.dropped ? "dropped in ingress" : `forwarded to XPU ${Object.keys(f.out).join(", ")}`; pill(g, W - X0 - tw(g, txt, 11, 700) / 2 - 8, 30, txt, f.dropped ? C.bad : C.ok, {s:11}); }
  T(g, "bmv2 simple_switch · p4/esun_switch.p4 · read from its log", W - X0, 52, {s:10.5, a:"right", c:C.muted});
  for (let j = 0; j < 7; j++){ box(g, d, f, j, cur, opts); if (j < 6) arrow(g, j, j < cur && !(f.dropped && j >= 2)); }
  strip(g, d, t, opts);
  T(g, "Assumptions: time is steps (10 per frame), not a clock. Drops other than a table miss (TTL, MAC control) are named from the program's rules; bmv2 logs only port 511. " +
    "The ECN checks set the marking threshold so that any queue depth marks.", X0, H - 8, {s:9.5, c:C.muted});
  const all = d.extra.frames.slice(0, i + (done ? 1 : 0));
  const stats = [[`Frame ${i + 1}: ${f.check}`, frameRows(f)],
    ["All frames so far", [["frames through the switch", all.length], ["forwarded", all.filter(x => !x.dropped).length],
      ["dropped", all.filter(x => x.dropped).length, all.some(x => x.dropped)], ["TTL rewritten", all.filter(x => x.ttl != null).length],
      ["ECN set to CE", all.filter(x => x.ecn_marked).length], ["queues other than 0", all.filter(x => x.queue).length]]]];
  return {t, stats, blocks:key => {
    const [k, v] = key.split(":");
    if (k === "stage") return [["stage", TITLES[+v][0] + " · " + TITLES[+v][1]], ["frame", `${i + 1}: ${f.check}`]].concat(stageRows(f, +v).map(([a, b]) => [a, b]));
    if (k === "frame") return frameRows(d.extra.frames[+v]);
    return null;
  }};
}
function frameRows(f){
  return [["check", f.check], ["spec", f.why || "–"], ["frame", `${f.in.kind} · ${f.in.len} B from XPU ${f.src} on port ${f.port_in}`],
    ["parser", f.states.join(" → ")], ["tables", f.tables.map(tb => `${tb.table} ${tb.hit ? "hit" : "miss"} → ${tb.action}(${tb.params.join(",")})`).join(" · ") || "none"],
    ["result", f.dropped ? "dropped: " + f.drop : `port ${f.tx}, priority ${f.queue}`, f.dropped], ["ECN", f.ecn || "–"],
    ["received by", Object.keys(f.out).map(k => "XPU " + k).join(", ") || "nobody"], ["bmv2 log lines", f.msgs.join(" | ") || "–"]];
}

return {handles, draw, idxAt};
})();
