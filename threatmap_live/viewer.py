"""
Viewer generator.

Renders the scan store into a single self-contained, NN-branded HTML dashboard.
Everything (scan data + logo) is inlined, so the file opens by double-click on any
machine — no server, no build step, no network. This is the read-only "consumer
door": operators run scans into the store; non-technical users open this page.
"""
from __future__ import annotations

import base64
import json
import os
from typing import List, Optional

from threatmap_live.store import load_records

_ASSET_DIR = os.path.join(os.path.dirname(__file__), "assets")
_DEFAULT_LOGO = os.path.join(_ASSET_DIR, "nn-logo.jpg")


def _logo_data_uri(logo_path: Optional[str]) -> str:
    path = logo_path or _DEFAULT_LOGO
    with open(path, "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode("ascii")
    return f"data:image/jpeg;base64,{b64}"


def build_viewer(store_dir: str, output_path: Optional[str] = None, logo_path: Optional[str] = None) -> str:
    """Build the self-contained dashboard HTML. Writes to output_path if given; returns the HTML."""
    records = load_records(store_dir)
    data_json = json.dumps(records).replace("</", "<\\/")
    html = (
        _TEMPLATE
        .replace("__LOGO__", _logo_data_uri(logo_path))
        .replace("__DATA__", data_json)
    )
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(html)
    return html


# --------------------------------------------------------------------------- template
# NN brand palette sampled from the logo: amber #FEC901 -> orange #EE7F00 -> deep #E65A0B.
_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>threatmap-live — NN</title>
<style>
  :root {
    --nn-yellow:#FEC901; --nn-amber:#F5A004; --nn-orange:#EE7F00; --nn-deep:#E65A0B;
    --nn-grad: linear-gradient(135deg,#FEC901 0%,#EE7F00 55%,#E65A0B 100%);
    --bg:#F4F5F7; --panel:#FFFFFF; --border:#E3E6EA; --ink:#1F2328; --muted:#5B6470;
    --crit:#C8102E; --high:#E1500A; --med:#F5A004; --low:#2E9E4F; --info:#7A828C;
    --shadow:0 1px 2px rgba(16,24,40,.06),0 4px 12px rgba(16,24,40,.05);
  }
  * { box-sizing:border-box; }
  body {
    margin:0; background:var(--bg); color:var(--ink);
    font-family:-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    font-size:14px; line-height:1.5;
  }
  /* Header */
  header.app {
    background:var(--panel); border-bottom:1px solid var(--border);
    display:flex; align-items:center; gap:16px; padding:14px 24px;
  }
  header.app img.logo { height:42px; width:auto; display:block; }
  header.app .titles { display:flex; flex-direction:column; }
  header.app .titles .product { font-weight:700; font-size:18px; letter-spacing:.2px; }
  header.app .titles .sub { color:var(--muted); font-size:12.5px; }
  header.app .spacer { flex:1; }
  header.app .badge {
    font-size:12px; color:#fff; background:var(--nn-grad);
    padding:5px 12px; border-radius:999px; font-weight:600;
  }
  .accent-bar { height:4px; background:var(--nn-grad); }

  .layout { display:grid; grid-template-columns:340px 1fr; gap:0; min-height:calc(100vh - 100px); }
  /* Sidebar */
  aside {
    background:var(--panel); border-right:1px solid var(--border);
    padding:16px; overflow-y:auto;
  }
  aside h2 { font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:var(--muted); margin:4px 4px 12px; }
  .scan {
    border:1px solid var(--border); border-radius:10px; padding:12px 14px; margin-bottom:10px;
    cursor:pointer; transition:border-color .12s, box-shadow .12s, transform .04s; background:#fff;
  }
  .scan:hover { border-color:var(--nn-orange); box-shadow:var(--shadow); }
  .scan.active { border-color:var(--nn-orange); box-shadow:0 0 0 2px rgba(238,127,0,.18); }
  .scan .row1 { display:flex; align-items:center; gap:8px; }
  .scan .prov {
    font-size:11px; font-weight:700; text-transform:uppercase; color:#fff;
    background:var(--nn-orange); border-radius:5px; padding:2px 7px;
  }
  .scan .scope { font-weight:600; }
  .scan .when { color:var(--muted); font-size:12px; margin:6px 0 8px; }
  .chips { display:flex; flex-wrap:wrap; gap:5px; }
  .chip { font-size:11px; font-weight:700; border-radius:5px; padding:2px 7px; color:#fff; }
  .chip.zero { background:#EEF0F2; color:#9AA1A9; }
  .sev-crit{background:var(--crit);} .sev-high{background:var(--high);}
  .sev-med{background:var(--med);} .sev-low{background:var(--low);} .sev-info{background:var(--info);}

  /* Main */
  main { padding:24px 28px; overflow-y:auto; }
  .detail-head { display:flex; align-items:flex-end; gap:14px; flex-wrap:wrap; margin-bottom:18px; }
  .detail-head h1 { font-size:22px; margin:0; }
  .detail-head .meta { color:var(--muted); font-size:13px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin-bottom:20px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px 16px; box-shadow:var(--shadow); }
  .card .n { font-size:26px; font-weight:800; line-height:1; }
  .card .l { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); margin-top:6px; }
  .card.crit .n{color:var(--crit);} .card.high .n{color:var(--high);}
  .card.med .n{color:var(--med);} .card.low .n{color:var(--low);} .card.total .n{color:var(--nn-deep);}

  .toolbar { display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:12px; }
  .toolbar input[type=search] {
    flex:1; min-width:200px; padding:8px 12px; border:1px solid var(--border); border-radius:8px; font-size:13px;
  }
  .filters { display:flex; gap:6px; }
  .filters button {
    border:1px solid var(--border); background:#fff; border-radius:999px; padding:5px 12px;
    font-size:12px; font-weight:600; cursor:pointer; color:var(--muted);
  }
  .filters button.on { color:#fff; border-color:transparent; }
  .filters button.on.crit{background:var(--crit);} .filters button.on.high{background:var(--high);}
  .filters button.on.med{background:var(--med);} .filters button.on.low{background:var(--low);} .filters button.on.info{background:var(--info);}

  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:12px; overflow:hidden; box-shadow:var(--shadow); }
  thead th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); padding:11px 14px; border-bottom:1px solid var(--border); background:#FAFBFC; }
  tbody td { padding:11px 14px; border-bottom:1px solid var(--border); vertical-align:top; }
  tbody tr:last-child td { border-bottom:none; }
  tbody tr.finding { cursor:pointer; }
  tbody tr.finding:hover { background:#FCFCFD; }
  .pill { font-size:11px; font-weight:700; color:#fff; border-radius:5px; padding:2px 8px; white-space:nowrap; }
  .mono { font-family:ui-monospace,"SF Mono",Consolas,monospace; font-size:12.5px; }
  .expand td { background:#FAFBFC; }
  .expand .k { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); }
  .empty { color:var(--muted); text-align:center; padding:60px 20px; }
  @media (max-width:860px){ .layout{ grid-template-columns:1fr; } aside{ border-right:none; border-bottom:1px solid var(--border);} }
</style>
</head>
<body>
<header class="app">
  <img class="logo" src="__LOGO__" alt="NN">
  <div class="titles">
    <span class="product">threatmap-live</span>
    <span class="sub">Live cloud threat model — NN</span>
  </div>
  <div class="spacer"></div>
  <div class="badge">Security &amp; Risk</div>
</header>
<div class="accent-bar"></div>

<div class="layout">
  <aside>
    <h2>Scans</h2>
    <div id="scan-list"></div>
  </aside>
  <main id="detail"></main>
</div>

<script id="scan-data" type="application/json">__DATA__</script>
<script>
(function(){
  var DATA = JSON.parse(document.getElementById('scan-data').textContent || '[]');
  var SEV = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  var SEVCLS = {CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',INFO:'info'};
  var state = { idx: 0, filters: {}, q: '' };
  SEV.forEach(function(s){ state.filters[s] = true; });

  function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
  function fmtDate(iso){ if(!iso) return ''; return iso.replace('T',' ').replace('Z',' UTC'); }

  function chip(sev, n){
    var z = n>0 ? '' : ' zero';
    return '<span class="chip sev-'+SEVCLS[sev]+z+'">'+sev[0]+' '+n+'</span>';
  }

  function renderList(){
    var el = document.getElementById('scan-list');
    if(!DATA.length){ el.innerHTML = '<div class="empty">No scans yet.<br>Run a scan with <span class="mono">--store</span>.</div>'; return; }
    el.innerHTML = DATA.map(function(r,i){
      var s = r.summary||{};
      var chips = SEV.map(function(sev){ return chip(sev, s[sev]||0); }).join('');
      return '<div class="scan'+(i===state.idx?' active':'')+'" data-i="'+i+'">'+
        '<div class="row1"><span class="prov">'+esc(r.provider)+'</span><span class="scope">'+esc(r.scope)+'</span></div>'+
        '<div class="when">'+esc(fmtDate(r.generated))+' · '+(s.total||0)+' threats · '+(s.resources||0)+' resources</div>'+
        '<div class="chips">'+chips+'</div></div>';
    }).join('');
    Array.prototype.forEach.call(el.querySelectorAll('.scan'), function(node){
      node.addEventListener('click', function(){ state.idx = +node.getAttribute('data-i'); render(); });
    });
  }

  function renderDetail(){
    var el = document.getElementById('detail');
    var r = DATA[state.idx];
    if(!r){ el.innerHTML = '<div class="empty">Select a scan.</div>'; return; }
    var s = r.summary||{};
    var cards = [
      ['total','Total', s.total||0],
      ['crit','Critical', s.CRITICAL||0],
      ['high','High', s.HIGH||0],
      ['med','Medium', s.MEDIUM||0],
      ['low','Low', s.LOW||0]
    ].map(function(c){ return '<div class="card '+c[0]+'"><div class="n">'+c[2]+'</div><div class="l">'+c[1]+'</div></div>'; }).join('');

    var filters = SEV.map(function(sev){
      return '<button class="'+SEVCLS[sev]+(state.filters[sev]?' on':'')+'" data-sev="'+sev+'">'+sev+'</button>';
    }).join('');

    var rows = (r.threats||[]).filter(function(t){
      if(!state.filters[t.severity]) return false;
      if(state.q){
        var hay = (t.resource_name+' '+t.resource_type+' '+t.description+' '+(t.stride_category||'')).toLowerCase();
        if(hay.indexOf(state.q.toLowerCase())<0) return false;
      }
      return true;
    });

    var body = rows.length ? rows.map(function(t,i){
      var cls = SEVCLS[t.severity]||'info';
      var main = '<tr class="finding" data-r="'+i+'">'+
        '<td class="mono">'+esc(t.threat_id)+'</td>'+
        '<td><span class="pill sev-'+cls+'">'+esc(t.severity)+'</span></td>'+
        '<td>'+esc(t.stride_category)+'</td>'+
        '<td class="mono">'+esc(t.resource_name)+'<br><span style="color:var(--muted)">'+esc(t.resource_type)+'</span></td>'+
        '<td>'+esc(t.description)+'</td></tr>';
      var exp = '<tr class="expand" id="exp-'+i+'" style="display:none"><td></td><td colspan="4">'+
        '<div class="k">Mitigation</div><div>'+esc(t.mitigation||'—')+'</div>'+
        (t.remediation?'<div class="k" style="margin-top:8px">Remediation</div><div class="mono">'+esc(t.remediation)+'</div>':'')+
        '</td></tr>';
      return main+exp;
    }).join('') : '<tr><td colspan="5" class="empty">No findings match the current filter.</td></tr>';

    el.innerHTML =
      '<div class="detail-head"><h1>'+esc(r.scope)+'</h1>'+
        '<span class="meta">'+esc(r.provider)+' · '+esc(r.framework||'stride').toUpperCase()+' · '+esc(fmtDate(r.generated))+'</span></div>'+
      '<div class="cards">'+cards+'</div>'+
      '<div class="toolbar"><input type="search" id="q" placeholder="Filter by resource, type, or description…" value="'+esc(state.q)+'">'+
        '<div class="filters">'+filters+'</div></div>'+
      '<table><thead><tr><th>ID</th><th>Severity</th><th>STRIDE</th><th>Resource</th><th>Description</th></tr></thead>'+
      '<tbody>'+body+'</tbody></table>';

    var q = document.getElementById('q');
    q.addEventListener('input', function(){ state.q = q.value; var p=q.selectionStart; renderDetail(); var nq=document.getElementById('q'); nq.focus(); try{nq.setSelectionRange(p,p);}catch(e){} });
    Array.prototype.forEach.call(el.querySelectorAll('.filters button'), function(b){
      b.addEventListener('click', function(){ var sev=b.getAttribute('data-sev'); state.filters[sev]=!state.filters[sev]; renderDetail(); });
    });
    Array.prototype.forEach.call(el.querySelectorAll('tr.finding'), function(tr){
      tr.addEventListener('click', function(){ var ex=document.getElementById('exp-'+tr.getAttribute('data-r')); if(ex) ex.style.display = ex.style.display==='none'?'table-row':'none'; });
    });
  }

  function render(){ renderList(); renderDetail(); }
  render();
})();
</script>
</body>
</html>
"""
