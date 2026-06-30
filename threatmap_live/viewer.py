"""
Viewer generator.

Renders the scan store into a single self-contained, NN-branded HTML dashboard.
Everything (scan data + logos) is inlined, so the file opens by double-click on any
machine — no server, no build step, no network. This is the read-only "consumer
door": operators run scans into the store; non-technical users open this page.

All charts are hand-built inline SVG/DOM (no chart-library CDN) to keep the page
fully offline and self-contained.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Optional

from threatmap_live.store import load_records

_ASSET_DIR = os.path.join(os.path.dirname(__file__), "assets")
_DEFAULT_LOGO = os.path.join(_ASSET_DIR, "nn-logo.jpg")
_WORDMARK = os.path.join(_ASSET_DIR, "threatmap-live-logo.png")


def _data_uri(path: str, mime: str) -> str:
    with open(path, "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode("ascii")
    return f"data:{mime};base64,{b64}"


def build_viewer(store_dir: str, output_path: Optional[str] = None, logo_path: Optional[str] = None) -> str:
    """Build the self-contained dashboard HTML. Writes to output_path if given; returns the HTML."""
    records = load_records(store_dir)
    data_json = json.dumps(records).replace("</", "<\\/")
    html = (
        _TEMPLATE
        .replace("__LOGO__", _data_uri(logo_path or _DEFAULT_LOGO, "image/jpeg"))
        .replace("__WORDMARK__", _data_uri(_WORDMARK, "image/png"))
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
  :root{
    --nn-yellow:#FEC901; --nn-amber:#F5A004; --nn-orange:#EE7F00; --nn-deep:#E65A0B;
    --nn-grad:linear-gradient(135deg,#FEC901 0%,#EE7F00 55%,#E65A0B 100%);
    --bg:#EEF1F5; --panel:#FFFFFF; --panel-2:#F8FAFC; --border:#E4E8EE;
    --ink:#15202B; --muted:#64727F; --faint:#94A2B0;
    --crit:#C8102E; --high:#E1500A; --med:#F5A004; --low:#2E9E4F; --info:#7A828C;
    --r:14px; --shadow:0 1px 2px rgba(16,24,40,.05),0 8px 24px rgba(16,24,40,.06);
    --ring:0 0 0 3px rgba(238,127,0,.16);
  }
  *{box-sizing:border-box;}
  html,body{margin:0;}
  body{
    background:
      radial-gradient(1200px 360px at 80% -120px, rgba(238,127,0,.10), transparent 70%),
      var(--bg);
    color:var(--ink);
    font-family:-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    font-size:14px; line-height:1.5; -webkit-font-smoothing:antialiased;
  }
  .mono{font-family:ui-monospace,"SF Mono",Consolas,"Liberation Mono",monospace;}
  .micro{font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:var(--muted); font-weight:600;}

  /* Header */
  header.app{ background:rgba(255,255,255,.85); backdrop-filter:blur(8px);
    border-bottom:1px solid var(--border); display:flex; align-items:center; gap:16px;
    padding:12px 26px; position:sticky; top:0; z-index:20; }
  header.app img.logo{ height:46px; width:auto; display:block; }
  header.app img.wordmark{ height:40px; width:auto; display:block; background:#0F1523; border-radius:9px; padding:5px 13px; box-shadow:var(--shadow); }
  header.app .spacer{ flex:1; }
  header.app .hbtn{ display:inline-flex; align-items:center; gap:7px; border:1px solid var(--border);
    background:#fff; color:var(--ink); border-radius:9px; padding:8px 13px; font-weight:600; font-size:13px;
    cursor:pointer; transition:.12s; }
  header.app .hbtn:hover{ border-color:var(--nn-orange); box-shadow:var(--ring); }
  header.app .hbtn.primary{ border:none; color:#fff; background:var(--nn-grad); }
  header.app .badge{ font-size:12px; color:#fff; background:#15202B; padding:6px 13px; border-radius:999px; font-weight:600; letter-spacing:.2px; }
  .accent-bar{ height:3px; background:var(--nn-grad); }

  .layout{ display:grid; grid-template-columns:330px 1fr; align-items:start; }
  /* Sidebar */
  aside{ padding:18px 16px; position:sticky; top:74px; max-height:calc(100vh - 74px); overflow-y:auto; }
  aside .micro{ margin:2px 6px 12px; }
  .scan{ border:1px solid var(--border); border-radius:13px; padding:13px 14px; margin-bottom:11px;
    cursor:pointer; background:#fff; transition:.12s; box-shadow:0 1px 2px rgba(16,24,40,.04); }
  .scan:hover{ transform:translateY(-1px); box-shadow:var(--shadow); }
  .scan.active{ border-color:var(--nn-orange); box-shadow:var(--ring); }
  .scan .row1{ display:flex; align-items:center; gap:8px; }
  .scan .prov{ font-size:10.5px; font-weight:800; letter-spacing:.4px; text-transform:uppercase; color:#fff;
    background:var(--nn-grad); border-radius:6px; padding:3px 8px; }
  .scan .scope{ font-weight:700; }
  .scan .when{ color:var(--muted); font-size:12px; margin:7px 0 9px; }
  .mini{ display:flex; height:8px; border-radius:6px; overflow:hidden; background:#EEF0F2; }
  .mini i{ display:block; height:100%; }
  .scan .legend{ display:flex; gap:10px; margin-top:8px; font-size:11px; color:var(--muted); }
  .scan .legend b{ color:var(--ink); }

  /* Main */
  main{ padding:22px 26px 40px; }
  .detail-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:18px; }
  .detail-head h1{ font-size:23px; margin:0; letter-spacing:-.2px; }
  .detail-head .pmeta{ color:var(--muted); font-size:13px; }
  .detail-head .grow{ flex:1; }
  .btn{ display:inline-flex; align-items:center; gap:7px; border:1px solid var(--border); background:#fff;
    color:var(--ink); border-radius:9px; padding:8px 12px; font-weight:600; font-size:13px; cursor:pointer; transition:.12s; }
  .btn:hover{ border-color:var(--nn-orange); box-shadow:var(--ring); }
  .btn svg{ width:15px; height:15px; }

  .grid{ display:grid; gap:16px; }
  .panel{ background:var(--panel); border:1px solid var(--border); border-radius:var(--r); box-shadow:var(--shadow); }
  .panel .ph{ display:flex; align-items:center; justify-content:space-between; padding:14px 16px 0; }
  .panel .pb{ padding:16px; }

  .overview{ grid-template-columns:300px 1fr; margin-bottom:16px; }
  /* Donut */
  .donut-wrap{ display:flex; align-items:center; gap:18px; }
  .donut{ position:relative; width:160px; height:160px; flex:none; }
  .donut .ctr{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }
  .donut .ctr b{ font-size:30px; font-weight:800; line-height:1; }
  .donut .ctr span{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.6px; margin-top:3px; }
  .dlegend{ display:flex; flex-direction:column; gap:7px; }
  .dlegend .it{ display:flex; align-items:center; gap:8px; font-size:13px; cursor:pointer; padding:2px 4px; border-radius:6px; }
  .dlegend .it:hover{ background:var(--panel-2); }
  .dlegend .sw{ width:11px; height:11px; border-radius:3px; flex:none; }
  .dlegend .it .v{ margin-left:auto; font-weight:700; }
  .dlegend .it.off{ opacity:.4; }

  /* KPI tiles */
  .kpis{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; }
  .kpi{ border:1px solid var(--border); border-radius:12px; padding:13px 14px; cursor:pointer; background:#fff;
    position:relative; overflow:hidden; transition:.12s; }
  .kpi:before{ content:""; position:absolute; left:0; top:0; bottom:0; width:4px; background:var(--c,#ccc); }
  .kpi:hover{ box-shadow:var(--shadow); transform:translateY(-1px); }
  .kpi.solo{ box-shadow:var(--ring); border-color:var(--nn-orange); }
  .kpi .n{ font-size:25px; font-weight:800; line-height:1; color:var(--c,var(--ink)); }
  .kpi .l{ font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); margin-top:6px; }
  .kpi .d{ font-size:11px; margin-top:4px; color:var(--faint); }

  /* Bars */
  .bars{ display:flex; flex-direction:column; gap:10px; }
  .bar{ display:grid; grid-template-columns:150px 1fr 34px; align-items:center; gap:10px; cursor:pointer; }
  .bar:hover .bl{ color:var(--ink); }
  .bl{ font-size:12.5px; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .bt{ height:10px; background:var(--panel-2); border-radius:6px; overflow:hidden; }
  .bf{ height:100%; border-radius:6px; transition:width .5s cubic-bezier(.2,.8,.2,1); }
  .bn{ font-size:12.5px; font-weight:700; text-align:right; }
  .bar.off{ opacity:.45; }

  .charts{ grid-template-columns:1fr 1fr; margin-bottom:16px; }

  /* Tabs + toolbar */
  .tabs{ display:flex; gap:4px; border-bottom:1px solid var(--border); margin-bottom:14px; }
  .tab{ padding:10px 14px; font-weight:700; font-size:13.5px; color:var(--muted); cursor:pointer; border-bottom:2px solid transparent; }
  .tab:hover{ color:var(--ink); }
  .tab.on{ color:var(--ink); border-bottom-color:var(--nn-orange); }
  .toolbar{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:12px; }
  .search{ position:relative; flex:1; min-width:220px; }
  .search svg{ position:absolute; left:11px; top:50%; transform:translateY(-50%); width:15px; height:15px; color:var(--faint); }
  .search input{ width:100%; padding:9px 12px 9px 33px; border:1px solid var(--border); border-radius:9px; font-size:13px; background:#fff; }
  .search input:focus{ outline:none; border-color:var(--nn-orange); box-shadow:var(--ring); }
  /* Segmented control */
  .seg{ display:inline-flex; border:1px solid var(--border); border-radius:9px; overflow:hidden; background:#fff; }
  .seg button{ border:none; background:#fff; padding:8px 11px; font-size:12px; font-weight:700; cursor:pointer;
    color:var(--muted); border-right:1px solid var(--border); display:flex; align-items:center; gap:6px; }
  .seg button:last-child{ border-right:none; }
  .seg button .c{ font-size:10.5px; background:var(--panel-2); border-radius:5px; padding:1px 6px; color:var(--ink); }
  .seg button.on{ color:#fff; }
  .seg button.on .c{ background:rgba(255,255,255,.28); color:#fff; }
  .seg button.on.crit{ background:var(--crit);} .seg button.on.high{ background:var(--high);}
  .seg button.on.med{ background:var(--med);} .seg button.on.low{ background:var(--low);} .seg button.on.info{ background:var(--info);}

  /* Table */
  table{ width:100%; border-collapse:collapse; }
  thead th{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted);
    padding:11px 14px; border-bottom:1px solid var(--border); background:var(--panel-2); cursor:pointer; user-select:none; white-space:nowrap; }
  thead th .ca{ color:var(--nn-orange); }
  tbody td{ padding:11px 14px; border-bottom:1px solid var(--border); vertical-align:top; }
  tbody tr:last-child td{ border-bottom:none; }
  tbody tr.finding{ cursor:pointer; }
  tbody tr.finding:hover{ background:#FCFDFE; }
  .sev{ display:inline-flex; align-items:center; gap:6px; font-size:11px; font-weight:800; letter-spacing:.3px;
    padding:3px 9px 3px 7px; border-radius:7px; color:#fff; white-space:nowrap; }
  .sev:before{ content:""; width:6px; height:6px; border-radius:50%; background:rgba(255,255,255,.85); }
  .sv-crit{ background:var(--crit);} .sv-high{ background:var(--high);} .sv-med{ background:var(--med);} .sv-low{ background:var(--low);} .sv-info{ background:var(--info);}
  .exp-badge{ font-size:11px; font-weight:700; padding:2px 8px; border-radius:6px; }
  .e-public{ background:#FDECEC; color:#C8102E; } .e-private{ background:#E9F7EE; color:#1E7B3C; } .e-unknown{ background:#EEF0F2; color:#64727F; }
  .expand td{ background:var(--panel-2); }
  .expand .k{ font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); margin-bottom:3px; }
  .empty{ color:var(--muted); text-align:center; padding:54px 20px; }
  @media (max-width:1080px){ .overview,.charts{ grid-template-columns:1fr; } .kpis{ grid-template-columns:repeat(2,1fr);} }
  @media (max-width:860px){ .layout{ grid-template-columns:1fr; } aside{ position:static; max-height:none; border-bottom:1px solid var(--border);} }
</style>
</head>
<body>
<header class="app">
  <img class="logo" src="__LOGO__" alt="NN">
  <img class="wordmark" src="__WORDMARK__" alt="threatmap-live">
  <div class="spacer"></div>
  <button class="hbtn" id="dl">Download JSON</button>
  <div class="badge">Security &amp; Risk</div>
</header>
<div class="accent-bar"></div>

<div class="layout">
  <aside><div class="micro">Scans</div><div id="scan-list"></div></aside>
  <main id="detail"></main>
</div>

<script id="scan-data" type="application/json">__DATA__</script>
<script>
(function(){
  var DATA = JSON.parse(document.getElementById('scan-data').textContent || '[]');
  var SEV = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  var CLS = {CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',INFO:'info'};
  var COL = {CRITICAL:'#C8102E',HIGH:'#E1500A',MEDIUM:'#F5A004',LOW:'#2E9E4F',INFO:'#7A828C'};
  var STRIDE = ['Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege'];
  var STRIDECOL = {'Spoofing':'#6366F1','Tampering':'#0EA5E9','Repudiation':'#14B8A6','Information Disclosure':'#F59E0B','Denial of Service':'#EF4444','Elevation of Privilege':'#A855F7'};
  var RANK = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};

  var st = { idx:0, tab:'findings', sev:{}, stride:null, q:'', sort:{c:'sev',d:1} };
  SEV.forEach(function(s){ st.sev[s]=true; });

  function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
  function date(iso){ return iso? iso.replace('T',' ').replace('Z',' UTC') : ''; }
  function rec(){ return DATA[st.idx]; }

  /* ---- charts (inline SVG, no libs) ---- */
  function donut(counts, total){
    var size=160, r=66, cx=80, cy=80, C=2*Math.PI*r, off=0, parts='';
    parts += '<circle cx="80" cy="80" r="66" fill="none" stroke="#EEF1F4" stroke-width="20"/>';
    SEV.forEach(function(s){
      var v=counts[s]||0; if(!v) return;
      var len=(v/(total||1))*C;
      parts += '<circle cx="80" cy="80" r="66" fill="none" stroke="'+COL[s]+'" stroke-width="20" '+
               'stroke-dasharray="'+len+' '+(C-len)+'" stroke-dashoffset="'+(-off)+'" transform="rotate(-90 80 80)"/>';
      off += len;
    });
    return '<svg width="'+size+'" height="'+size+'" viewBox="0 0 160 160">'+parts+'</svg>';
  }
  function barRows(pairs, colorFn, activeKey, onAttr){
    var max = pairs.reduce(function(m,p){ return Math.max(m,p[1]); }, 0) || 1;
    return pairs.map(function(p){
      var off = activeKey && activeKey!==p[0] ? ' off' : '';
      var w = Math.round(p[1]/max*100);
      return '<div class="bar'+off+'" '+onAttr(p[0])+'><div class="bl" title="'+esc(p[0])+'">'+esc(p[0])+'</div>'+
        '<div class="bt"><div class="bf" style="width:'+w+'%;background:'+colorFn(p[0])+'"></div></div>'+
        '<div class="bn">'+p[1]+'</div></div>';
    }).join('');
  }

  function counts(threats){ var c={}; SEV.forEach(function(s){c[s]=0;}); threats.forEach(function(t){ c[t.severity]=(c[t.severity]||0)+1; }); return c; }
  function byKey(threats, key){ var m={}; threats.forEach(function(t){ var k=t[key]||'—'; m[k]=(m[k]||0)+1; }); return m; }

  /* ---- sidebar ---- */
  function renderList(){
    var el=document.getElementById('scan-list');
    if(!DATA.length){ el.innerHTML='<div class="empty">No scans yet.<br>Run a scan with <span class="mono">--store</span>.</div>'; return; }
    el.innerHTML = DATA.map(function(r,i){
      var s=r.summary||{}, tot=s.total||0;
      var segs = SEV.map(function(sev){ var v=s[sev]||0; if(!v) return ''; return '<i style="width:'+(v/(tot||1)*100)+'%;background:'+COL[sev]+'"></i>'; }).join('');
      return '<div class="scan'+(i===st.idx?' active':'')+'" data-i="'+i+'">'+
        '<div class="row1"><span class="prov">'+esc(r.provider)+'</span><span class="scope">'+esc(r.scope)+'</span></div>'+
        '<div class="when">'+esc(date(r.generated))+'</div>'+
        '<div class="mini">'+segs+'</div>'+
        '<div class="legend"><span><b>'+tot+'</b> threats</span><span><b>'+(s.resources||0)+'</b> resources</span>'+
        '<span style="color:var(--crit)"><b>'+(s.CRITICAL||0)+'</b> crit</span></div></div>';
    }).join('');
    el.querySelectorAll('.scan').forEach(function(n){ n.addEventListener('click',function(){ st.idx=+n.dataset.i; st.stride=null; render(); }); });
  }

  /* ---- detail ---- */
  function visibleThreats(){
    var ts = (rec().threats||[]).filter(function(t){
      if(!st.sev[t.severity]) return false;
      if(st.stride && t.stride_category!==st.stride) return false;
      if(st.q){ var h=(t.resource_name+' '+t.resource_type+' '+t.description+' '+t.stride_category).toLowerCase(); if(h.indexOf(st.q.toLowerCase())<0) return false; }
      return true;
    });
    var c=st.sort.c, d=st.sort.d;
    ts.sort(function(a,b){
      var av,bv;
      if(c==='sev'){ av=RANK[a.severity]; bv=RANK[b.severity]; }
      else if(c==='id'){ av=a.threat_id; bv=b.threat_id; }
      else if(c==='stride'){ av=a.stride_category; bv=b.stride_category; }
      else { av=a.resource_name; bv=b.resource_name; }
      return av<bv?-d:av>bv?d:0;
    });
    return ts;
  }

  function render(){ renderList(); renderDetail(); }

  function renderDetail(){
    var el=document.getElementById('detail'); var r=rec();
    if(!r){ el.innerHTML='<div class="empty">Select a scan.</div>'; return; }
    var s=r.summary||{}, all=r.threats||[], cAll=counts(all), tot=all.length;
    var resPublic=(r.resources||[]).filter(function(x){return x.exposure==='public';}).length;
    var strideCounts=byKey(all,'stride_category');
    var strideStats=STRIDE.map(function(k){return [k, strideCounts[k]||0];}).filter(function(p){return p[1]>0;}).sort(function(a,b){return b[1]-a[1];});
    var typeCounts=byKey(all,'resource_type');
    var typeStats=Object.keys(typeCounts).map(function(k){return [k,typeCounts[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,8);

    var legend = SEV.map(function(sev){
      return '<div class="it'+(st.sev[sev]?'':' off')+'" data-sev="'+sev+'"><span class="sw" style="background:'+COL[sev]+'"></span>'+
        sev.charAt(0)+sev.slice(1).toLowerCase()+'<span class="v">'+(cAll[sev]||0)+'</span></div>';
    }).join('');

    var kpis = [['Total',tot,'var(--nn-deep)','TOTAL'],['CRITICAL',cAll.CRITICAL||0,COL.CRITICAL,'Critical'],
                ['HIGH',cAll.HIGH||0,COL.HIGH,'High'],['MEDIUM',cAll.MEDIUM||0,COL.MEDIUM,'Medium'],['LOW',cAll.LOW||0,COL.LOW,'Low']]
      .map(function(k){
        var solo = (k[0]!=='Total' && isSolo(k[0])) ? ' solo':'';
        return '<div class="kpi'+solo+'" data-k="'+k[0]+'" style="--c:'+k[2]+'"><div class="n">'+k[1]+'</div><div class="l">'+k[3]+'</div></div>';
      }).join('');

    var seg = SEV.map(function(sev){
      return '<button class="'+CLS[sev]+(st.sev[sev]?' on':'')+'" data-sev="'+sev+'">'+sev.charAt(0)+sev.slice(1).toLowerCase()+
        '<span class="c">'+(cAll[sev]||0)+'</span></button>';
    }).join('');

    var rows = renderRows();

    el.innerHTML =
      '<div class="detail-head"><h1>'+esc(r.scope)+'</h1>'+
        '<span class="pheader pmeta micro" style="text-transform:none;font-weight:500">'+esc(r.provider)+' · '+esc((r.framework||'stride').toUpperCase())+' · '+esc(date(r.generated))+'</span>'+
        '<span class="grow"></span>'+
        (st.stride?'<button class="btn" id="clr">Clear filter: '+esc(st.stride)+' ✕</button>':'')+
      '</div>'+

      '<div class="grid overview">'+
        '<div class="panel"><div class="ph"><span class="micro">Severity</span></div><div class="pb">'+
          '<div class="donut-wrap"><div class="donut">'+donut(cAll,tot)+
            '<div class="ctr"><b>'+tot+'</b><span>threats</span></div></div>'+
            '<div class="dlegend">'+legend+'</div></div></div></div>'+
        '<div class="panel"><div class="ph"><span class="micro">Posture</span><span class="micro" style="font-weight:500">'+(s.resources||0)+' resources scanned</span></div>'+
          '<div class="pb"><div class="kpis">'+kpis+'</div>'+
          '<div style="margin-top:13px;display:flex;gap:18px;flex-wrap:wrap;font-size:12.5px;color:var(--muted)">'+
            '<span>Public-facing resources <b style="color:var(--crit)">'+resPublic+'</b></span>'+
            '<span>Top category <b style="color:var(--ink)">'+(strideStats[0]?esc(strideStats[0][0]):'—')+'</b></span>'+
            '<span>Distinct resource types <b style="color:var(--ink)">'+Object.keys(typeCounts).length+'</b></span>'+
          '</div></div></div>'+
      '</div>'+

      '<div class="grid charts">'+
        '<div class="panel"><div class="ph"><span class="micro">Threats by STRIDE category</span></div><div class="pb"><div class="bars">'+
          (strideStats.length? barRows(strideStats,function(k){return STRIDECOL[k]||'#999';}, st.stride, function(k){return 'data-stride="'+esc(k)+'"';}) : '<div class="empty">No data</div>')+
        '</div></div></div>'+
        '<div class="panel"><div class="ph"><span class="micro">Most-affected resource types</span></div><div class="pb"><div class="bars">'+
          (typeStats.length? barRows(typeStats,function(){return 'var(--nn-orange)';}, null, function(){return '';}) : '<div class="empty">No data</div>')+
        '</div></div></div>'+
      '</div>'+

      '<div class="panel"><div class="pb">'+
        '<div class="tabs"><div class="tab'+(st.tab==='findings'?' on':'')+'" data-tab="findings">Findings <span class="mono" style="color:var(--faint)">'+tot+'</span></div>'+
          '<div class="tab'+(st.tab==='resources'?' on':'')+'" data-tab="resources">Resources <span class="mono" style="color:var(--faint)">'+(r.resources||[]).length+'</span></div></div>'+
        '<div id="tabbody">'+rows+'</div>'+
      '</div></div>';

    wire();
  }

  function renderRows(){
    if(st.tab==='resources') return renderResources();
    var ts=visibleThreats();
    var car=function(c){ return st.sort.c===c? ' <span class="ca">'+(st.sort.d>0?'▲':'▼')+'</span>':''; };
    var head='<div class="toolbar">'+
      '<div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>'+
        '<input id="q" type="search" placeholder="Filter by resource, type, or description…" value="'+esc(st.q)+'"></div>'+
      '<div class="seg">'+SEV.map(function(sev){return '<button class="'+CLS[sev]+(st.sev[sev]?' on':'')+'" data-sev="'+sev+'">'+sev.charAt(0)+'<span class="c">'+(counts(rec().threats||[])[sev]||0)+'</span></button>';}).join('')+'</div>'+
      '<button class="btn" id="expall">Expand all</button></div>';
    var body = ts.length ? ts.map(function(t,i){
      var c=CLS[t.severity]||'info';
      return '<tr class="finding" data-r="'+i+'"><td class="mono">'+esc(t.threat_id)+'</td>'+
        '<td><span class="sev sv-'+c+'">'+esc(t.severity)+'</span></td>'+
        '<td>'+esc(t.stride_category)+'</td>'+
        '<td class="mono">'+esc(t.resource_name)+'<br><span style="color:var(--muted)">'+esc(t.resource_type)+'</span></td>'+
        '<td>'+esc(t.description)+'</td></tr>'+
        '<tr class="expand" id="ex-'+i+'" style="display:none"><td></td><td colspan="4">'+
          '<div class="k">Mitigation</div><div>'+esc(t.mitigation||'—')+'</div>'+
          (t.remediation?'<div class="k" style="margin-top:9px">Remediation</div><div class="mono">'+esc(t.remediation)+'</div>':'')+'</td></tr>';
    }).join('') : '<tr><td colspan="5" class="empty">No findings match the current filter.</td></tr>';
    return head+'<table><thead><tr>'+
      '<th data-sort="id">ID'+car('id')+'</th><th data-sort="sev">Severity'+car('sev')+'</th>'+
      '<th data-sort="stride">STRIDE'+car('stride')+'</th><th data-sort="res">Resource'+car('res')+'</th><th>Description</th>'+
      '</tr></thead><tbody>'+body+'</tbody></table>';
  }

  function renderResources(){
    var rs=(rec().resources||[]).slice().sort(function(a,b){return (a.type+a.name)<(b.type+b.name)?-1:1;});
    var body = rs.length ? rs.map(function(x){
      var e=(x.exposure||'unknown'); return '<tr><td class="mono">'+esc(x.name)+'</td><td class="mono">'+esc(x.type)+'</td>'+
        '<td>'+esc(x.provider)+'</td><td><span class="exp-badge e-'+esc(e)+'">'+esc(e)+'</span></td></tr>';
    }).join('') : '<tr><td colspan="4" class="empty">No resources.</td></tr>';
    return '<div style="height:6px"></div><table><thead><tr><th>Name</th><th>Type</th><th>Provider</th><th>Exposure</th></tr></thead><tbody>'+body+'</tbody></table>';
  }

  function isSolo(sev){ var on=SEV.filter(function(s){return st.sev[s];}); return on.length===1 && on[0]===sev; }
  function setSolo(sev){ if(isSolo(sev)){ SEV.forEach(function(s){st.sev[s]=true;}); } else { SEV.forEach(function(s){st.sev[s]=(s===sev);}); } }

  function wire(){
    var el=document.getElementById('detail');
    el.querySelectorAll('.dlegend .it').forEach(function(n){ n.addEventListener('click',function(){ var s=n.dataset.sev; st.sev[s]=!st.sev[s]; renderDetail(); }); });
    el.querySelectorAll('.kpi').forEach(function(n){ n.addEventListener('click',function(){ var k=n.dataset.k; if(k==='Total'){ SEV.forEach(function(s){st.sev[s]=true;}); } else { setSolo(k); } renderDetail(); }); });
    el.querySelectorAll('.bar[data-stride]').forEach(function(n){ n.addEventListener('click',function(){ var k=n.dataset.stride; st.stride=(st.stride===k?null:k); renderDetail(); }); });
    el.querySelectorAll('.tab').forEach(function(n){ n.addEventListener('click',function(){ st.tab=n.dataset.tab; renderDetail(); }); });
    el.querySelectorAll('.seg button[data-sev]').forEach(function(n){ n.addEventListener('click',function(){ var s=n.dataset.sev; st.sev[s]=!st.sev[s]; renderDetail(); }); });
    el.querySelectorAll('thead th[data-sort]').forEach(function(n){ n.addEventListener('click',function(){ var c=n.dataset.sort; if(st.sort.c===c) st.sort.d*=-1; else st.sort={c:c,d:1}; renderDetail(); }); });
    var clr=document.getElementById('clr'); if(clr) clr.addEventListener('click',function(){ st.stride=null; renderDetail(); });
    var ea=document.getElementById('expall'); if(ea) ea.addEventListener('click',function(){ var rows=el.querySelectorAll('tr.expand'); var anyHidden=Array.prototype.some.call(rows,function(r){return r.style.display==='none';}); rows.forEach(function(r){ r.style.display=anyHidden?'table-row':'none'; }); ea.textContent=anyHidden?'Collapse all':'Expand all'; });
    el.querySelectorAll('tr.finding').forEach(function(tr){ tr.addEventListener('click',function(){ var ex=document.getElementById('ex-'+tr.dataset.r); if(ex) ex.style.display=ex.style.display==='none'?'table-row':'none'; }); });
    var q=document.getElementById('q'); if(q){ q.addEventListener('input',function(){ st.q=q.value; var p=q.selectionStart; renderDetail(); var nq=document.getElementById('q'); if(nq){ nq.focus(); try{nq.setSelectionRange(p,p);}catch(e){} } }); }
  }

  document.getElementById('dl').addEventListener('click',function(){
    var r=rec(); if(!r) return;
    var blob=new Blob([JSON.stringify(r,null,2)],{type:'application/json'});
    var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=r.id+'.json'; a.click();
  });

  render();
})();
</script>
</body>
</html>
"""
