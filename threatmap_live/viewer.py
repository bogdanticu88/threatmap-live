"""
Viewer generator.

Renders the scan store into a single self-contained, NN-branded HTML dashboard.
Everything (scan data + logos) is inlined, so the file opens by double-click on any
machine — no server, no build step, no network. This is the read-only "consumer
door": operators run scans into the store; non-technical users open this page.

All charts (severity donut, STRIDE/resource bars, trend line, attack-surface
hub-and-spoke) are hand-built inline SVG/DOM — no chart-library CDN — to keep the
page fully offline and self-contained.
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
    --bg:#EEF1F5; --panel:#FFFFFF; --panel-2:#F4F6F9; --border:#E4E8EE;
    --header-bg:rgba(255,255,255,.85);
    --ink:#15202B; --muted:#64727F; --faint:#94A2B0;
    --crit:#C8102E; --high:#E1500A; --med:#F5A004; --low:#2E9E4F; --info:#7A828C;
    --r:14px; --shadow:0 1px 2px rgba(16,24,40,.05),0 8px 24px rgba(16,24,40,.06);
    --ring:0 0 0 3px rgba(238,127,0,.16);
  }
  html[data-theme="dark"]{
    --bg:#0E1621; --panel:#15212E; --panel-2:#1B2836; --border:#26333F;
    --header-bg:rgba(15,21,35,.82);
    --ink:#E7EDF3; --muted:#90A0AE; --faint:#6B7A88;
    --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 26px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box;}
  html,body{margin:0;}
  body{
    background:radial-gradient(1200px 360px at 80% -120px, rgba(238,127,0,.10), transparent 70%), var(--bg);
    color:var(--ink); font-family:-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    font-size:14px; line-height:1.5; -webkit-font-smoothing:antialiased;
  }
  .mono{font-family:ui-monospace,"SF Mono",Consolas,"Liberation Mono",monospace;}
  .micro{font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:var(--muted); font-weight:600;}

  header.app{ background:var(--header-bg); backdrop-filter:blur(8px); border-bottom:1px solid var(--border);
    display:flex; align-items:center; gap:14px; padding:12px 26px; position:sticky; top:0; z-index:20; }
  header.app img.logo{ height:46px; width:auto; display:block; }
  html[data-theme="dark"] header.app img.logo{ background:#fff; border-radius:9px; padding:3px 5px; }
  header.app img.wordmark{ height:40px; width:auto; display:block; background:#0F1523; border-radius:9px; padding:5px 13px; box-shadow:var(--shadow); }
  header.app .spacer{ flex:1; }
  header.app .hbtn{ display:inline-flex; align-items:center; gap:7px; border:1px solid var(--border);
    background:var(--panel); color:var(--ink); border-radius:9px; padding:8px 13px; font-weight:600; font-size:13px; cursor:pointer; transition:.12s; }
  header.app .hbtn:hover{ border-color:var(--nn-orange); box-shadow:var(--ring); }
  header.app .icon{ padding:8px 11px; font-size:15px; line-height:1; }
  header.app .badge{ font-size:12px; color:#fff; background:#15202B; padding:6px 13px; border-radius:999px; font-weight:600; }
  html[data-theme="dark"] header.app .badge{ background:#0A1018; border:1px solid var(--border); }
  .accent-bar{ height:3px; background:var(--nn-grad); }

  .layout{ display:grid; grid-template-columns:330px 1fr; align-items:start; }
  aside{ padding:18px 16px; position:sticky; top:74px; max-height:calc(100vh - 74px); overflow-y:auto; }
  aside .micro{ margin:2px 6px 12px; }
  .scan{ border:1px solid var(--border); border-radius:13px; padding:13px 14px; margin-bottom:11px; cursor:pointer;
    background:var(--panel); transition:.12s; box-shadow:0 1px 2px rgba(16,24,40,.04); }
  .scan:hover{ transform:translateY(-1px); box-shadow:var(--shadow); }
  .scan.active{ border-color:var(--nn-orange); box-shadow:var(--ring); }
  .scan .row1{ display:flex; align-items:center; gap:8px; }
  .scan .prov{ font-size:10.5px; font-weight:800; letter-spacing:.4px; text-transform:uppercase; color:#fff; background:var(--nn-grad); border-radius:6px; padding:3px 8px; }
  .scan .scope{ font-weight:700; }
  .scan .when{ color:var(--muted); font-size:12px; margin:7px 0 9px; }
  .mini{ display:flex; height:8px; border-radius:6px; overflow:hidden; background:var(--panel-2); }
  .mini i{ display:block; height:100%; }
  .scan .legend{ display:flex; gap:10px; margin-top:8px; font-size:11px; color:var(--muted); }
  .scan .legend b{ color:var(--ink); }

  main{ padding:22px 26px 40px; }
  .detail-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:18px; }
  .detail-head h1{ font-size:23px; margin:0; letter-spacing:-.2px; }
  .detail-head .pmeta{ color:var(--muted); font-size:13px; }
  .detail-head .grow{ flex:1; }
  .btn{ display:inline-flex; align-items:center; gap:7px; border:1px solid var(--border); background:var(--panel);
    color:var(--ink); border-radius:9px; padding:8px 12px; font-weight:600; font-size:13px; cursor:pointer; transition:.12s; }
  .btn:hover{ border-color:var(--nn-orange); box-shadow:var(--ring); }
  .btn svg{ width:15px; height:15px; }

  .grid{ display:grid; gap:16px; }
  .panel{ background:var(--panel); border:1px solid var(--border); border-radius:var(--r); box-shadow:var(--shadow); }
  .panel .ph{ display:flex; align-items:center; justify-content:space-between; padding:14px 16px 0; }
  .panel .pb{ padding:16px; }

  .overview{ grid-template-columns:300px 1fr; margin-bottom:16px; }
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

  .kpis{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; }
  .kpi{ border:1px solid var(--border); border-radius:12px; padding:13px 14px; cursor:pointer; background:var(--panel); position:relative; overflow:hidden; transition:.12s; }
  .kpi:before{ content:""; position:absolute; left:0; top:0; bottom:0; width:4px; background:var(--c,#ccc); }
  .kpi:hover{ box-shadow:var(--shadow); transform:translateY(-1px); }
  .kpi.solo{ box-shadow:var(--ring); border-color:var(--nn-orange); }
  .kpi .n{ font-size:25px; font-weight:800; line-height:1; color:var(--c,var(--ink)); }
  .kpi .l{ font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); margin-top:6px; }

  .bars{ display:flex; flex-direction:column; gap:10px; }
  .bar{ display:grid; grid-template-columns:150px 1fr 34px; align-items:center; gap:10px; cursor:pointer; }
  .bl{ font-size:12.5px; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .bt{ height:10px; background:var(--panel-2); border-radius:6px; overflow:hidden; }
  .bf{ height:100%; border-radius:6px; transition:width .5s cubic-bezier(.2,.8,.2,1); }
  .bn{ font-size:12.5px; font-weight:700; text-align:right; }
  .bar.off{ opacity:.45; }
  .charts{ grid-template-columns:1fr 1fr; margin-bottom:16px; }

  .tabs{ display:flex; gap:4px; border-bottom:1px solid var(--border); margin-bottom:14px; }
  .tab{ padding:10px 14px; font-weight:700; font-size:13.5px; color:var(--muted); cursor:pointer; border-bottom:2px solid transparent; }
  .tab:hover{ color:var(--ink); }
  .tab.on{ color:var(--ink); border-bottom-color:var(--nn-orange); }
  .toolbar{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:12px; }
  .search{ position:relative; flex:1; min-width:220px; }
  .search svg{ position:absolute; left:11px; top:50%; transform:translateY(-50%); width:15px; height:15px; color:var(--faint); }
  .search input{ width:100%; padding:9px 12px 9px 33px; border:1px solid var(--border); border-radius:9px; font-size:13px; background:var(--panel); color:var(--ink); }
  .search input:focus{ outline:none; border-color:var(--nn-orange); box-shadow:var(--ring); }
  .seg{ display:inline-flex; border:1px solid var(--border); border-radius:9px; overflow:hidden; background:var(--panel); }
  .seg button{ border:none; background:var(--panel); padding:8px 11px; font-size:12px; font-weight:700; cursor:pointer; color:var(--muted); border-right:1px solid var(--border); display:flex; align-items:center; gap:6px; }
  .seg button:last-child{ border-right:none; }
  .seg button .c{ font-size:10.5px; background:var(--panel-2); border-radius:5px; padding:1px 6px; color:var(--ink); }
  .seg button.on{ color:#fff; } .seg button.on .c{ background:rgba(255,255,255,.28); color:#fff; }
  .seg button.on.crit{ background:var(--crit);} .seg button.on.high{ background:var(--high);} .seg button.on.med{ background:var(--med);} .seg button.on.low{ background:var(--low);} .seg button.on.info{ background:var(--info);}

  table{ width:100%; border-collapse:collapse; }
  thead th{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); padding:11px 14px; border-bottom:1px solid var(--border); background:var(--panel-2); cursor:pointer; user-select:none; white-space:nowrap; }
  thead th .ca{ color:var(--nn-orange); }
  tbody td{ padding:11px 14px; border-bottom:1px solid var(--border); vertical-align:top; }
  tbody tr:last-child td{ border-bottom:none; }
  tbody tr.finding{ cursor:pointer; } tbody tr.finding:hover{ background:var(--panel-2); }
  .sev{ display:inline-flex; align-items:center; gap:6px; font-size:11px; font-weight:800; letter-spacing:.3px; padding:3px 9px 3px 7px; border-radius:7px; color:#fff; white-space:nowrap; }
  .sev:before{ content:""; width:6px; height:6px; border-radius:50%; background:rgba(255,255,255,.85); }
  .sv-crit{ background:var(--crit);} .sv-high{ background:var(--high);} .sv-med{ background:var(--med);} .sv-low{ background:var(--low);} .sv-info{ background:var(--info);}
  .exp-badge{ font-size:11px; font-weight:700; padding:2px 8px; border-radius:6px; }
  .e-public{ background:#FDECEC; color:#C8102E; } .e-private{ background:#E9F7EE; color:#1E7B3C; } .e-unknown{ background:var(--panel-2); color:var(--muted); }
  .expand td{ background:var(--panel-2); }
  .expand .k{ font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); margin-bottom:3px; }
  .legend-row{ display:flex; gap:16px; margin-top:8px; font-size:12px; color:var(--muted); }
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
  <button class="hbtn icon" id="themeb" title="Toggle light / dark">&#9790;</button>
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
  function trim(s,n){ s=String(s); return s.length>n? s.slice(0,n-1)+'…':s; }
  function rec(){ return DATA[st.idx]; }
  function counts(threats){ var c={}; SEV.forEach(function(s){c[s]=0;}); threats.forEach(function(t){ c[t.severity]=(c[t.severity]||0)+1; }); return c; }
  function byKey(threats, key){ var m={}; threats.forEach(function(t){ var k=t[key]||'—'; m[k]=(m[k]||0)+1; }); return m; }

  /* ----------------------------------------------------------- charts (SVG) */
  function donut(c, total){
    var r=66, C=2*Math.PI*r, off=0, parts='<circle cx="80" cy="80" r="66" fill="none" style="stroke:var(--panel-2)" stroke-width="20"/>';
    SEV.forEach(function(s){ var v=c[s]||0; if(!v) return; var len=(v/(total||1))*C;
      parts += '<circle cx="80" cy="80" r="66" fill="none" stroke="'+COL[s]+'" stroke-width="20" stroke-dasharray="'+len+' '+(C-len)+'" stroke-dashoffset="'+(-off)+'" transform="rotate(-90 80 80)"/>'; off+=len; });
    return '<svg width="160" height="160" viewBox="0 0 160 160">'+parts+'</svg>';
  }
  function barRows(pairs, colorFn, active, onAttr){
    var max = pairs.reduce(function(m,p){return Math.max(m,p[1]);},0)||1;
    return pairs.map(function(p){ var off=active&&active!==p[0]?' off':''; var w=Math.round(p[1]/max*100);
      return '<div class="bar'+off+'" '+onAttr(p[0])+'><div class="bl" title="'+esc(p[0])+'">'+esc(p[0])+'</div>'+
        '<div class="bt"><div class="bf" style="width:'+w+'%;background:'+colorFn(p[0])+'"></div></div><div class="bn">'+p[1]+'</div></div>';
    }).join('');
  }
  function trendSeries(){ var r=rec();
    return DATA.filter(function(x){return x.provider===r.provider && x.scope===r.scope;})
      .slice().sort(function(a,b){return (a.generated||'')<(b.generated||'')?-1:1;})
      .map(function(x){ var s=x.summary||{}; return {t:x.generated, total:s.total||0, crit:s.CRITICAL||0}; });
  }
  function trendSVG(series){
    if(!series.length) return '<div class="empty">No history.</div>';
    var W=760,H=200,pL=44,pR=18,pT=18,pB=34, n=series.length;
    var maxY=Math.max.apply(null, series.map(function(p){return p.total;}).concat([1]));
    function X(i){ return n<=1? pL+(W-pL-pR)/2 : pL+i*(W-pL-pR)/(n-1); }
    function Y(v){ return pT+(1-v/maxY)*(H-pT-pB); }
    var grid=''; for(var g=0; g<=4; g++){ var gy=pT+g*(H-pT-pB)/4;
      grid+='<line x1="'+pL+'" y1="'+gy+'" x2="'+(W-pR)+'" y2="'+gy+'" style="stroke:var(--border)" stroke-dasharray="3 4"/>'+
        '<text x="'+(pL-8)+'" y="'+(gy+4)+'" text-anchor="end" font-size="10" style="fill:var(--faint)">'+Math.round(maxY*(1-g/4))+'</text>'; }
    var pt=series.map(function(p,i){return X(i)+','+Y(p.total);});
    var pc=series.map(function(p,i){return X(i)+','+Y(p.crit);});
    var area='M'+pL+','+(H-pB)+' L'+pt.join(' L')+' L'+X(n-1)+','+(H-pB)+' Z';
    var dots=series.map(function(p,i){return '<circle cx="'+X(i)+'" cy="'+Y(p.total)+'" r="3.6" fill="#EE7F00"/><circle cx="'+X(i)+'" cy="'+Y(p.crit)+'" r="3" fill="#C8102E"/>';}).join('');
    var xl=series.map(function(p,i){return '<text x="'+X(i)+'" y="'+(H-12)+'" text-anchor="middle" font-size="10" style="fill:var(--faint)">'+esc((p.t||'').slice(5,10))+'</text>';}).join('');
    var svg='<svg width="100%" viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="xMidYMid meet">'+
      '<defs><linearGradient id="tg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#EE7F00" stop-opacity=".22"/><stop offset="1" stop-color="#EE7F00" stop-opacity="0"/></linearGradient></defs>'+
      grid+'<path d="'+area+'" fill="url(#tg)"/>'+
      '<path d="M'+pt.join(' L')+'" fill="none" stroke="#EE7F00" stroke-width="2.5"/>'+
      '<path d="M'+pc.join(' L')+'" fill="none" stroke="#C8102E" stroke-width="2" stroke-dasharray="5 4"/>'+dots+xl+'</svg>';
    return svg+'<div class="legend-row"><span><span style="display:inline-block;width:14px;height:3px;background:#EE7F00;vertical-align:middle"></span> Total</span>'+
      '<span><span style="display:inline-block;width:14px;border-top:2px dashed #C8102E;vertical-align:middle"></span> Critical</span>'+
      (n===1?'<span style="color:var(--faint)">single scan — trend builds as history accumulates</span>':'')+'</div>';
  }

  function exposedEntries(){
    var seen={}, out=[];
    (rec().threats||[]).forEach(function(t){ var d=(t.description||'').toLowerCase();
      if(/public|internet|0\.0\.0\.0\/0|ssh\/rdp/.test(d)){
        var k=t.resource_name+'|'+t.resource_type;
        if(!(k in seen)){ seen[k]=out.length; out.push({name:t.resource_name,type:t.resource_type,sev:t.severity}); }
        else { var o=out[seen[k]]; if(RANK[t.severity]<RANK[o.sev]) o.sev=t.severity; }
      }});
    out.sort(function(a,b){return RANK[a.sev]-RANK[b.sev];});
    return out;
  }
  function attackSVG(list){
    if(!list.length) return '<div class="empty">No internet-facing exposure detected in the current findings. 🎉</div>';
    var shown=list.slice(0,12), extra=list.length-shown.length;
    var W=760, cardH=52, gap=12, pT=18, nodeX=300, nodeW=446, cx=140;
    var H=Math.max(150, pT*2 + shown.length*cardH + (shown.length-1)*gap), cyc=H/2;
    var edges='', nodes='';
    shown.forEach(function(o,i){ var y=pT+i*(cardH+gap), mY=y+cardH/2, col=COL[o.sev]||'#999', x1=cx+58;
      edges+='<path d="M'+x1+' '+cyc+' C '+(x1+70)+' '+cyc+', '+(nodeX-70)+' '+mY+', '+nodeX+' '+mY+'" fill="none" stroke="'+col+'" stroke-width="2" opacity=".55"/>';
      nodes+='<rect x="'+nodeX+'" y="'+y+'" rx="10" width="'+nodeW+'" height="'+cardH+'" style="fill:var(--panel);stroke:var(--border)"/>'+
        '<rect x="'+nodeX+'" y="'+y+'" rx="3" width="6" height="'+cardH+'" fill="'+col+'"/>'+
        '<text x="'+(nodeX+18)+'" y="'+(y+21)+'" font-size="13" font-weight="600" style="fill:var(--ink)" font-family="ui-monospace,Consolas,monospace">'+esc(trim(o.name,40))+'</text>'+
        '<text x="'+(nodeX+18)+'" y="'+(y+39)+'" font-size="11.5" style="fill:var(--muted)" font-family="ui-monospace,Consolas,monospace">'+esc(o.type)+'</text>'+
        '<text x="'+(nodeX+nodeW-14)+'" y="'+(mY+4)+'" text-anchor="end" font-size="10.5" font-weight="800" fill="'+col+'">'+esc(o.sev)+'</text>';
    });
    var inode='<rect x="14" y="'+(cyc-34)+'" rx="14" width="124" height="68" fill="#15202B"/>'+
      '<circle cx="48" cy="'+cyc+'" r="13" fill="none" stroke="#EE7F00" stroke-width="1.8"/>'+
      '<line x1="35" y1="'+cyc+'" x2="61" y2="'+cyc+'" stroke="#EE7F00" stroke-width="1.2"/>'+
      '<ellipse cx="48" cy="'+cyc+'" rx="6" ry="13" fill="none" stroke="#EE7F00" stroke-width="1.2"/>'+
      '<text x="76" y="'+(cyc-2)+'" font-size="12" font-weight="800" fill="#fff">Internet</text>'+
      '<text x="76" y="'+(cyc+13)+'" font-size="9.5" fill="#9AA7B4">0.0.0.0/0</text>';
    return '<svg width="100%" viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="xMidYMid meet">'+edges+inode+nodes+'</svg>'+
      (extra>0?'<div class="micro" style="margin-top:6px">+ '+extra+' more entry point(s)</div>':'');
  }

  /* ----------------------------------------------------------- sidebar */
  function renderList(){
    var el=document.getElementById('scan-list');
    if(!DATA.length){ el.innerHTML='<div class="empty">No scans yet.<br>Run a scan with <span class="mono">--store</span>.</div>'; return; }
    el.innerHTML = DATA.map(function(r,i){ var s=r.summary||{}, tot=s.total||0;
      var segs=SEV.map(function(sev){var v=s[sev]||0; return v?'<i style="width:'+(v/(tot||1)*100)+'%;background:'+COL[sev]+'"></i>':'';}).join('');
      return '<div class="scan'+(i===st.idx?' active':'')+'" data-i="'+i+'"><div class="row1"><span class="prov">'+esc(r.provider)+'</span><span class="scope">'+esc(r.scope)+'</span></div>'+
        '<div class="when">'+esc(date(r.generated))+'</div><div class="mini">'+segs+'</div>'+
        '<div class="legend"><span><b>'+tot+'</b> threats</span><span><b>'+(s.resources||0)+'</b> resources</span><span style="color:var(--crit)"><b>'+(s.CRITICAL||0)+'</b> crit</span></div></div>';
    }).join('');
    el.querySelectorAll('.scan').forEach(function(n){ n.addEventListener('click',function(){ st.idx=+n.dataset.i; st.stride=null; render(); }); });
  }

  function visibleThreats(){
    var ts=(rec().threats||[]).filter(function(t){
      if(!st.sev[t.severity]) return false;
      if(st.stride && t.stride_category!==st.stride) return false;
      if(st.q){ var h=(t.resource_name+' '+t.resource_type+' '+t.description+' '+t.stride_category).toLowerCase(); if(h.indexOf(st.q.toLowerCase())<0) return false; }
      return true; });
    var c=st.sort.c,d=st.sort.d;
    ts.sort(function(a,b){ var av,bv;
      if(c==='sev'){av=RANK[a.severity];bv=RANK[b.severity];} else if(c==='id'){av=a.threat_id;bv=b.threat_id;}
      else if(c==='stride'){av=a.stride_category;bv=b.stride_category;} else {av=a.resource_name;bv=b.resource_name;}
      return av<bv?-d:av>bv?d:0; });
    return ts;
  }

  function render(){ renderList(); renderDetail(); }

  function renderDetail(){
    var el=document.getElementById('detail'), r=rec();
    if(!r){ el.innerHTML='<div class="empty">Select a scan.</div>'; return; }
    var all=r.threats||[], cAll=counts(all), tot=all.length, s=r.summary||{};
    var resPublic=(r.resources||[]).filter(function(x){return x.exposure==='public';}).length;
    var strideStats=STRIDE.map(function(k){return [k,byKey(all,'stride_category')[k]||0];}).filter(function(p){return p[1]>0;}).sort(function(a,b){return b[1]-a[1];});
    var tc=byKey(all,'resource_type'), typeStats=Object.keys(tc).map(function(k){return [k,tc[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,8);
    var series=trendSeries(), exposed=exposedEntries();

    var legend=SEV.map(function(sev){return '<div class="it'+(st.sev[sev]?'':' off')+'" data-sev="'+sev+'"><span class="sw" style="background:'+COL[sev]+'"></span>'+sev.charAt(0)+sev.slice(1).toLowerCase()+'<span class="v">'+(cAll[sev]||0)+'</span></div>';}).join('');
    var kpis=[['Total',tot,'var(--nn-deep)','Total'],['CRITICAL',cAll.CRITICAL||0,COL.CRITICAL,'Critical'],['HIGH',cAll.HIGH||0,COL.HIGH,'High'],['MEDIUM',cAll.MEDIUM||0,COL.MEDIUM,'Medium'],['LOW',cAll.LOW||0,COL.LOW,'Low']]
      .map(function(k){return '<div class="kpi'+((k[0]!=='Total'&&isSolo(k[0]))?' solo':'')+'" data-k="'+k[0]+'" style="--c:'+k[2]+'"><div class="n">'+k[1]+'</div><div class="l">'+k[3]+'</div></div>';}).join('');

    el.innerHTML =
      '<div class="detail-head"><h1>'+esc(r.scope)+'</h1>'+
        '<span class="pmeta">'+esc(r.provider)+' · '+esc((r.framework||'stride').toUpperCase())+' · '+esc(date(r.generated))+'</span>'+
        '<span class="grow"></span>'+(st.stride?'<button class="btn" id="clr">Filter: '+esc(st.stride)+' ✕</button>':'')+'</div>'+

      '<div class="grid overview">'+
        '<div class="panel"><div class="ph"><span class="micro">Severity</span></div><div class="pb"><div class="donut-wrap"><div class="donut">'+donut(cAll,tot)+
          '<div class="ctr"><b>'+tot+'</b><span>threats</span></div></div><div class="dlegend">'+legend+'</div></div></div></div>'+
        '<div class="panel"><div class="ph"><span class="micro">Posture</span><span class="micro" style="font-weight:500">'+(s.resources||0)+' resources scanned</span></div><div class="pb"><div class="kpis">'+kpis+'</div>'+
          '<div style="margin-top:13px;display:flex;gap:18px;flex-wrap:wrap;font-size:12.5px;color:var(--muted)">'+
            '<span>Internet entry points <b style="color:var(--crit)">'+exposed.length+'</b></span>'+
            '<span>Public-facing resources <b style="color:var(--crit)">'+resPublic+'</b></span>'+
            '<span>Top category <b style="color:var(--ink)">'+(strideStats[0]?esc(strideStats[0][0]):'—')+'</b></span></div></div></div>'+
      '</div>'+

      '<div class="grid charts">'+
        '<div class="panel"><div class="ph"><span class="micro">Threats by STRIDE category</span></div><div class="pb"><div class="bars">'+
          (strideStats.length?barRows(strideStats,function(k){return STRIDECOL[k]||'#999';},st.stride,function(k){return 'data-stride="'+esc(k)+'"';}):'<div class="empty">No data</div>')+'</div></div></div>'+
        '<div class="panel"><div class="ph"><span class="micro">Most-affected resource types</span></div><div class="pb"><div class="bars">'+
          (typeStats.length?barRows(typeStats,function(){return 'var(--nn-orange)';},null,function(){return '';}):'<div class="empty">No data</div>')+'</div></div></div>'+
      '</div>'+

      '<div class="panel" style="margin-bottom:16px"><div class="ph"><span class="micro">Trend over time — '+esc(r.scope)+'</span><span class="micro" style="font-weight:500">'+series.length+' scan(s)</span></div><div class="pb">'+trendSVG(series)+'</div></div>'+

      '<div class="panel"><div class="pb"><div class="tabs">'+
        '<div class="tab'+(st.tab==='findings'?' on':'')+'" data-tab="findings">Findings <span class="mono" style="color:var(--faint)">'+tot+'</span></div>'+
        '<div class="tab'+(st.tab==='attack'?' on':'')+'" data-tab="attack">Attack surface <span class="mono" style="color:var(--faint)">'+exposed.length+'</span></div>'+
        '<div class="tab'+(st.tab==='resources'?' on':'')+'" data-tab="resources">Resources <span class="mono" style="color:var(--faint)">'+(r.resources||[]).length+'</span></div>'+
      '</div><div id="tabbody">'+renderRows(exposed)+'</div></div></div>';

    wire();
  }

  function renderRows(exposed){
    if(st.tab==='resources') return renderResources();
    if(st.tab==='attack') return '<div class="micro" style="margin:2px 0 12px">'+exposed.length+' internet-facing entry point(s) derived from current findings</div>'+attackSVG(exposed);
    var ts=visibleThreats();
    var car=function(c){return st.sort.c===c?' <span class="ca">'+(st.sort.d>0?'▲':'▼')+'</span>':'';};
    var head='<div class="toolbar"><div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>'+
      '<input id="q" type="search" placeholder="Filter by resource, type, or description…" value="'+esc(st.q)+'"></div>'+
      '<div class="seg">'+SEV.map(function(sev){return '<button class="'+CLS[sev]+(st.sev[sev]?' on':'')+'" data-sev="'+sev+'">'+sev.charAt(0)+'<span class="c">'+(counts(rec().threats||[])[sev]||0)+'</span></button>';}).join('')+'</div>'+
      '<button class="btn" id="expall">Expand all</button></div>';
    var body=ts.length?ts.map(function(t,i){var c=CLS[t.severity]||'info';
      return '<tr class="finding" data-r="'+i+'"><td class="mono">'+esc(t.threat_id)+'</td><td><span class="sev sv-'+c+'">'+esc(t.severity)+'</span></td>'+
        '<td>'+esc(t.stride_category)+'</td><td class="mono">'+esc(t.resource_name)+'<br><span style="color:var(--muted)">'+esc(t.resource_type)+'</span></td><td>'+esc(t.description)+'</td></tr>'+
        '<tr class="expand" id="ex-'+i+'" style="display:none"><td></td><td colspan="4"><div class="k">Mitigation</div><div>'+esc(t.mitigation||'—')+'</div>'+
        (t.remediation?'<div class="k" style="margin-top:9px">Remediation</div><div class="mono">'+esc(t.remediation)+'</div>':'')+'</td></tr>';
    }).join(''):'<tr><td colspan="5" class="empty">No findings match the current filter.</td></tr>';
    return head+'<table><thead><tr><th data-sort="id">ID'+car('id')+'</th><th data-sort="sev">Severity'+car('sev')+'</th><th data-sort="stride">STRIDE'+car('stride')+'</th><th data-sort="res">Resource'+car('res')+'</th><th>Description</th></tr></thead><tbody>'+body+'</tbody></table>';
  }
  function renderResources(){
    var rs=(rec().resources||[]).slice().sort(function(a,b){return (a.type+a.name)<(b.type+b.name)?-1:1;});
    var body=rs.length?rs.map(function(x){var e=x.exposure||'unknown';
      return '<tr><td class="mono">'+esc(x.name)+'</td><td class="mono">'+esc(x.type)+'</td><td>'+esc(x.provider)+'</td><td><span class="exp-badge e-'+esc(e)+'">'+esc(e)+'</span></td></tr>';
    }).join(''):'<tr><td colspan="4" class="empty">No resources.</td></tr>';
    return '<div style="height:6px"></div><table><thead><tr><th>Name</th><th>Type</th><th>Provider</th><th>Exposure</th></tr></thead><tbody>'+body+'</tbody></table>';
  }

  function isSolo(sev){ var on=SEV.filter(function(s){return st.sev[s];}); return on.length===1&&on[0]===sev; }
  function setSolo(sev){ if(isSolo(sev)){SEV.forEach(function(s){st.sev[s]=true;});} else {SEV.forEach(function(s){st.sev[s]=(s===sev);});} }

  function wire(){
    var el=document.getElementById('detail');
    el.querySelectorAll('.dlegend .it').forEach(function(n){n.addEventListener('click',function(){st.sev[n.dataset.sev]=!st.sev[n.dataset.sev];renderDetail();});});
    el.querySelectorAll('.kpi').forEach(function(n){n.addEventListener('click',function(){var k=n.dataset.k;if(k==='Total'){SEV.forEach(function(s){st.sev[s]=true;});}else{setSolo(k);}renderDetail();});});
    el.querySelectorAll('.bar[data-stride]').forEach(function(n){n.addEventListener('click',function(){var k=n.dataset.stride;st.stride=(st.stride===k?null:k);renderDetail();});});
    el.querySelectorAll('.tab').forEach(function(n){n.addEventListener('click',function(){st.tab=n.dataset.tab;renderDetail();});});
    el.querySelectorAll('.seg button[data-sev]').forEach(function(n){n.addEventListener('click',function(){st.sev[n.dataset.sev]=!st.sev[n.dataset.sev];renderDetail();});});
    el.querySelectorAll('thead th[data-sort]').forEach(function(n){n.addEventListener('click',function(){var c=n.dataset.sort;if(st.sort.c===c)st.sort.d*=-1;else st.sort={c:c,d:1};renderDetail();});});
    var clr=document.getElementById('clr'); if(clr)clr.addEventListener('click',function(){st.stride=null;renderDetail();});
    var ea=document.getElementById('expall'); if(ea)ea.addEventListener('click',function(){var rows=el.querySelectorAll('tr.expand');var h=Array.prototype.some.call(rows,function(r){return r.style.display==='none';});rows.forEach(function(r){r.style.display=h?'table-row':'none';});ea.textContent=h?'Collapse all':'Expand all';});
    el.querySelectorAll('tr.finding').forEach(function(tr){tr.addEventListener('click',function(){var ex=document.getElementById('ex-'+tr.dataset.r);if(ex)ex.style.display=ex.style.display==='none'?'table-row':'none';});});
    var q=document.getElementById('q'); if(q){q.addEventListener('input',function(){st.q=q.value;var p=q.selectionStart;renderDetail();var nq=document.getElementById('q');if(nq){nq.focus();try{nq.setSelectionRange(p,p);}catch(e){}}});}
  }

  /* theme */
  function applyTheme(t){ document.documentElement.setAttribute('data-theme',t); try{localStorage.setItem('tmlive-theme',t);}catch(e){} var b=document.getElementById('themeb'); if(b) b.innerHTML = t==='dark'?'&#9728;':'&#9790;'; }
  var saved=null; try{saved=localStorage.getItem('tmlive-theme');}catch(e){}
  applyTheme(saved || ((window.matchMedia&&window.matchMedia('(prefers-color-scheme:dark)').matches)?'dark':'light'));
  document.getElementById('themeb').addEventListener('click',function(){ applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark'); });

  document.getElementById('dl').addEventListener('click',function(){ var r=rec(); if(!r)return;
    var blob=new Blob([JSON.stringify(r,null,2)],{type:'application/json'}); var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=r.id+'.json'; a.click(); });

  render();
})();
</script>
</body>
</html>
"""
