import json
import os
import threading
from queue import Queue
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from common import _save_alert
import uvicorn

ALERTS_FILE = "alerts.json"
RULES_FILE  = "rules.json"

alert_queue = Queue()

app = FastAPI(title="Система обнаружения вторжений (IDS)")
app.mount("/static", StaticFiles(directory="."), name="static")

def read_json_file(filename: str):
    if not os.path.exists(filename):
        return [] if "alerts" in filename else {}
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return [] if "alerts" in filename else {}
    if data is None:
        return [] if "alerts" in filename else {}
    return data

def process_alert_queue():
    print("[Queue] Обработчик очереди алертов запущен")
    while True:
        alert = alert_queue.get()
        _save_alert(alert)
        alert_queue.task_done()
        print(f"[Queue] Алерт записан: {alert.get('rule_name', 'Unknown')} от {alert.get('src_ip', 'Unknown')}")


queue_thread = threading.Thread(target=process_alert_queue, daemon=True)
queue_thread.start()

CRITICALITY_MAP = {
    "SQLi": "high",
    "SYN Flood": "high",
    "Bruteforce": "medium",
    "UDP Flood": "medium",
    "Port scan detected": "low",
    "ICMP Flood": "low",
}

def get_criticality(rule_name: str) -> str:
    return CRITICALITY_MAP.get(rule_name, "low")

def get_stats():
    alerts = read_json_file(ALERTS_FILE)
    if not isinstance(alerts, list):
        alerts = []
    rules = read_json_file(RULES_FILE)

    total_alerts = len(alerts)
    total_rules = len(rules) if isinstance(rules, (list, dict)) else 0

    high = sum(1 for a in alerts if get_criticality(a.get('rule_name', '')) == 'high')
    medium = sum(1 for a in alerts if get_criticality(a.get('rule_name', '')) == 'medium')
    low = sum(1 for a in alerts if get_criticality(a.get('rule_name', '')) == 'low')

    attack_types = {}
    for a in alerts:
        rule = a.get('rule_name', 'Unknown')
        attack_types[rule] = attack_types.get(rule, 0) + 1

    ips = set(a.get('src_ip', '') for a in alerts if a.get('src_ip') and a.get('src_ip') != 'N/A')

    return {
        "total_alerts": total_alerts,
        "total_rules": total_rules,
        "high": high,
        "medium": medium,
        "low": low,
        "attack_types": attack_types,
        "unique_ips": len(ips),
        "alerts": alerts
    }

@app.get("/", response_class=HTMLResponse)
async def home_page(request: Request):
    stats = get_stats()
    alerts = stats['alerts']
    alerts = sorted(alerts, key=lambda x: x.get('timestamp', 0), reverse=True)
    alerts_json = json.dumps(alerts, ensure_ascii=False)

    total_alerts = stats['total_alerts']
    total_rules = stats['total_rules']

    recent = alerts[:5]
    alert_rows = ""
    for a in recent:
        crit = get_criticality(a.get('rule_name', ''))
        if crit == 'high':
            bg = '#fff5f5'; border = '#e74c3c'; badge_bg = '#fde8e8'; badge_color = '#c0392b'; badge_text = 'ВЫС'
        elif crit == 'medium':
            bg = '#fffdf5'; border = '#f39c12'; badge_bg = '#fef3e0'; badge_color = '#d68910'; badge_text = 'СРЕД'
        else:
            bg = '#f5faff'; border = '#3498db'; badge_bg = '#e0effb'; badge_color = '#2471a3'; badge_text = 'НИЗ'
        alert_rows += f"""<tr style="border-left:4px solid {border}; background:{bg};">
            <td>{a.get('timestamp','—')}</td>
            <td>{a.get('src_ip','—')}</td>
            <td>{a.get('dst_ip','—')}</td>
            <td>{a.get('rule_name','Unknown')}</td>
            <td><span class="badge" style="background:{badge_bg}; color:{badge_color};">{badge_text}</span></td>
            <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis;">{a.get('details','—')[:60]}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>IDS — Панель управления</title>
    <meta http-equiv="refresh" content="5">
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family:'Segoe UI',Arial,sans-serif;
            min-height:100vh;
            background:linear-gradient(160deg,#e8f0f8 0%,#d4e2f0 25%,#c5d8ec 50%,#d4e2f0 75%,#e8f0f8 100%);
            padding:15px;
        }}
        .stripe-top {{
            position:fixed; top:0; left:0; width:100%; height:4px;
            background:linear-gradient(90deg,transparent 10%,#8ab4e0 30%,#5b9bd5 50%,#8ab4e0 70%,transparent 90%);
            z-index:100;
        }}
        .stripe-bottom {{
            position:fixed; bottom:0; left:0; width:100%; height:4px;
            background:linear-gradient(90deg,transparent 10%,#8ab4e0 30%,#5b9bd5 50%,#8ab4e0 70%,transparent 90%);
            z-index:100;
        }}
        .header {{
            max-width:1400px; margin:0 auto 15px;
            display:flex; align-items:center; justify-content:space-between;
            flex-wrap:wrap; gap:10px;
        }}
        .header h1 {{ color:#1e3a5f; font-size:24px; }}
        .live-dot {{
            width:10px; height:10px; background:#2ecc71; border-radius:50%;
            animation:pulse 1.5s infinite; display:inline-block; margin-right:6px;
        }}
        @keyframes pulse {{ 0%,100%{{opacity:1;}} 50%{{opacity:0.3;}} }}
        .live-text {{ color:#2ecc71; font-size:13px; font-weight:600; }}
        
        .mini-stats {{
            max-width:1400px; margin:0 auto 15px;
            display:flex; gap:12px; flex-wrap:wrap;
        }}
        .stat-card {{
            flex:1 1 120px; min-width:100px;
            background:white; border-radius:12px; padding:14px 16px;
            text-align:center; box-shadow:0 2px 12px rgba(46,90,158,0.05);
            border:1px solid #e8eef5;
        }}
        .stat-card .num {{ font-size:28px; font-weight:700; color:#1e3a5f; }}
        .stat-card .lbl {{ font-size:11px; color:#8fa4b8; margin-top:4px; }}
        .stat-card.red .num {{ color:#c0392b; }}
        .stat-card.yellow .num {{ color:#d68910; }}
        .stat-card.blue .num {{ color:#2471a3; }}
        .stat-card.green .num {{ color:#27ae60; }}
        
        .main-layout {{
            max-width:1400px; margin:0 auto;
            display:flex; gap:15px; align-items:flex-start;
        }}
        .left-col {{
            flex:1 1 62%; min-width:0;
            display:flex; flex-direction:column; gap:15px;
        }}
        .right-col {{
            flex:0 0 280px;
            display:flex; flex-direction:column; gap:15px;
        }}
        
        .link-card {{
            background:white; border-radius:16px;
            box-shadow:0 4px 20px rgba(46,90,158,0.06);
            border:1px solid #e8eef5;
            text-decoration:none; color:inherit;
            display:block; transition:all 0.3s; cursor:pointer;
        }}
        .link-card:hover {{
            box-shadow:0 8px 30px rgba(46,90,158,0.10);
            border-color:#a0c4e6; transform:translateY(-2px);
        }}
        .link-card-header {{
            padding:14px 20px; display:flex; align-items:center;
            justify-content:space-between;
        }}
        .link-card-header .left {{ display:flex; align-items:center; gap:10px; }}
        .link-card-header .icon {{ font-size:24px; }}
        .link-card-header .title {{ color:#1e3a5f; font-size:16px; font-weight:600; }}
        .link-card-header .count {{ color:#8fa4b8; font-size:13px; }}
        .link-card-header .arrow {{ color:#8fa4b8; font-size:16px; }}
        .link-card-body {{ padding:0 20px 14px; overflow:hidden; }}
        
        .table-wrap {{ overflow-x:auto; }}
        table {{ width:100%; border-collapse:collapse; font-size:12px; min-width:600px; }}
        table th {{
            background:#f0f5fb; color:#1e3a5f; font-weight:600;
            padding:10px 8px; text-align:left; border-bottom:2px solid #dce8f2;
            white-space:nowrap;
        }}
        table td {{ padding:8px; border-bottom:1px solid #f0f4f8; white-space:nowrap; }}
        table tbody tr:hover {{ background:#f8fafe !important; }}
        .badge {{
            display:inline-block; padding:2px 8px; border-radius:10px;
            font-size:10px; font-weight:700;
        }}
        
        .chart-container {{
            position:relative; height:264px;
            border-left:2px solid #dce8f2; border-bottom:2px solid #dce8f2;
            padding:8px 0 0 40px;
        }}
        .chart-y-labels {{
            position:absolute; left:4px; top:8px; height:256px;
            display:flex; flex-direction:column; justify-content:space-between;
            font-size:10px; color:#8fa4b8;
        }}
        .chart-bars {{
            display:flex; align-items:flex-end; gap:3px;
            height:256px; flex-wrap:nowrap; overflow-x:auto;
        }}
        .legend {{
            display:flex; gap:10px; margin-top:20px; flex-wrap:wrap;
            font-size:10px; color:#5a7a9a;
        }}
        .legend-item {{ display:flex; align-items:center; gap:4px; }}
        .legend-color {{ width:10px; height:10px; border-radius:2px; }}
        
        .btn-rules {{
            display:block; width:100%; padding:16px; background:white;
            border-radius:16px; text-align:center; text-decoration:none;
            color:#2e5a8a; font-weight:600; font-size:16px;
            box-shadow:0 4px 20px rgba(46,90,158,0.06);
            border:1px solid #e8eef5; transition:all 0.3s;
        }}
        .btn-rules:hover {{
            background:#f0f5fb; transform:translateY(-3px);
            box-shadow:0 10px 30px rgba(46,90,158,0.12); border-color:#a0c4e6;
        }}
        .btn-rules .icon {{ font-size:30px; display:block; margin-bottom:6px; }}
        .btn-rules .count {{ font-size:12px; color:#8fa4b8; margin-top:4px; }}
        
        .shield-area {{
            position:relative; height:300px;
            display:flex; align-items:center; justify-content:center;
        }}
        .shield-ring-svg {{
            position:absolute; top:50%; left:50%; transform:translate(-50%,-50%);
            width:260px; height:260px; z-index:1; pointer-events:none;
        }}
        .shield-icon-wrap {{
            position:relative; z-index:2;
            width:130px; height:130px;
            background:linear-gradient(135deg,#4a90d9 0%,#2e6ab0 40%,#1e4d85 100%);
            clip-path:polygon(50% 0%,95% 15%,95% 55%,50% 100%,5% 55%,5% 15%);
            display:flex; align-items:center; justify-content:center;
            box-shadow:0 12px 40px rgba(30,77,133,0.4);
        }}
        .shield-icon-wrap img {{
            width:150px; height:auto;
            filter:drop-shadow(0 2px 3px rgba(0,0,0,0.3));
        }}
        
        .info-row {{
            padding:6px 20px 10px; font-size:11px; color:#8fa4b8;
            display:flex; justify-content:space-between;
        }}
        .footer-bar {{
            max-width:1400px; margin:10px auto 0;
            display:flex; justify-content:space-between;
            font-size:11px; color:#8fa4b8;
        }}
        .empty {{ text-align:center; padding:20px; color:#8fa4b8; }}
        @media (max-width:900px) {{
            .main-layout {{ flex-direction:column; }}
            .right-col {{ flex:1 1 auto; width:100%; }}
            .shield-area {{ height:220px; }}
        }}
    </style>
</head>
<body>
    <div class="stripe-top"></div>
    <div class="stripe-bottom"></div>
    
    <div class="header">
        <h1>🛡️ СИСТЕМА ОБНАРУЖЕНИЯ ВТОРЖЕНИЙ</h1>
        <div style="display:flex; align-items:center; gap:20px;">
            <span><span class="live-dot"></span><span class="live-text">LIVE</span></span>
            <span style="color:#1e3a5f; font-size:14px;">Алертов: <b>{total_alerts}</b></span>
        </div>
    </div>
    
    <div class="mini-stats">
        <div class="stat-card red">
            <div class="num">{stats['high']}</div>
            <div class="lbl">⚠️ Высокая</div>
        </div>
        <div class="stat-card yellow">
            <div class="num">{stats['medium']}</div>
            <div class="lbl">⚡ Средняя</div>
        </div>
        <div class="stat-card blue">
            <div class="num">{stats['low']}</div>
            <div class="lbl">ℹ️ Низкая</div>
        </div>
        <div class="stat-card green">
            <div class="num">{stats['unique_ips']}</div>
            <div class="lbl">🌐 Уникальных IP</div>
        </div>
        <div class="stat-card">
            <div class="num">{total_rules}</div>
            <div class="lbl">📜 Правил</div>
        </div>
    </div>
    
    <div class="main-layout">
        <div class="left-col">
            <a href="/alerts" class="link-card">
                <div class="link-card-header">
                    <div class="left">
                        <span class="icon">📋</span>
                        <span class="title">Журнал алертов</span>
                        <span class="count">{total_alerts} записей</span>
                    </div>
                    <span class="arrow">→</span>
                </div>
                <div class="link-card-body">
                    <div class="table-wrap">
                        {f'''<table>
                            <thead><tr><th>Время</th><th>IP ист.</th><th>IP цели</th><th>Правило</th><th>Крит.</th><th>Детали</th></tr></thead>
                            <tbody>{alert_rows}</tbody>
                        </table>''' if total_alerts > 0 else '<div class="empty"><span style="font-size:30px;">🛡️</span><p>Алертов пока нет</p></div>'}
                    </div>
                </div>
                <div class="info-row">
                    <span>Показаны последние 5 из {total_alerts}</span>
                    <span>Нажмите чтобы увидеть все →</span>
                </div>
            </a>
            
            <a href="/alerts" class="link-card">
                <div class="link-card-header">
                    <div class="left">
                        <span class="icon">📈</span>
                        <span class="title">Атаки по времени</span>
                        <span class="count">график</span>
                    </div>
                    <span class="arrow">→</span>
                </div>
                <div class="link-card-body">
                    <div class="chart-container">
                        <div class="chart-y-labels" id="yLabels"></div>
                        <div class="chart-bars" id="chartBars"></div>
                    </div>
                    <div class="legend" id="legend"></div>
                </div>
                <div class="info-row">
                    <span>Распределение по категориям</span>
                    <span>Нажмите чтобы увидеть все →</span>
                </div>
            </a>
        </div>
        
        <div class="right-col">
            <a href="/rules" class="btn-rules">
                <span class="icon">📜</span>
                Загруженные правила
                <span class="count">Всего: {total_rules}</span>
            </a>
            
            <div class="shield-area">
                <svg class="shield-ring-svg" viewBox="0 0 260 260" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="130" cy="130" r="108" fill="none" stroke="#5b9bd5" stroke-width="4" stroke-dasharray="180 46" stroke-linecap="round" transform="rotate(-16 130 130)"/>
                </svg>
                <div class="shield-icon-wrap">
                    <img src="/static/shield.png" alt="Щит">
                </div>
            </div>
        </div>
    </div>
    
    <div class="footer-bar">
        <span>IDS v1.0 | Python 3.14 | FastAPI</span>
        <span>🛡️ Система активна</span>
    </div>
    
    <script>
        var alertsData = {alerts_json};
        var categories = {{
            'SQLi': {{color:'#e74c3c',criticality:'high'}},
            'SYN Flood': {{color:'#e74c3c',criticality:'high'}},
            'TCP Flood': {{color:'#e74c3c',criticality:'high'}},
            'Bruteforce': {{color:'#f39c12',criticality:'medium'}},
            'UDP Flood': {{color:'#f39c12',criticality:'medium'}},
            'Port scan detected': {{color:'#3498db',criticality:'low'}},
            'ICMP Flood': {{color:'#3498db',criticality:'low'}}
        }};
        
        function buildChart(){{
            if(!alertsData||alertsData.length===0)return;
            var intervals=10,timeLabels=[],dataByCategory={{}},maxVal=1;
            for(var i=0;i<intervals;i++)timeLabels.push('-'+(intervals-i)*5+'м');
            alertsData.forEach(function(a){{
                var cat=categories[a.rule_name]?a.rule_name:'Other';
                if(!categories[cat])categories[cat]={{color:'#95a5a6',criticality:'low'}};
                if(!dataByCategory[cat])dataByCategory[cat]=new Array(intervals).fill(0);
                var diff=Math.floor((new Date()-new Date(a.timestamp*1000))/60000);
                var idx=intervals-1-Math.floor(diff/5);
                if(idx>=0&&idx<intervals)dataByCategory[cat][idx]++;
            }});
            Object.values(dataByCategory).forEach(function(arr){{arr.forEach(function(v){{if(v>maxVal)maxVal=v;}});}});
            var bars=document.getElementById('chartBars');bars.innerHTML='';
            for(var i=0;i<intervals;i++){{
                var g=document.createElement('div');
                g.style.cssText='display:flex;flex-direction:column-reverse;align-items:center;gap:2px;flex:1;min-width:28px;position:relative;';
                Object.keys(dataByCategory).forEach(function(cat){{
                    var h=Math.max((dataByCategory[cat][i]/maxVal)*256,2);
                    var b=document.createElement('div');
                    b.style.cssText='height:'+h+'px;background:'+categories[cat].color+';width:18px;border-radius:4px 4px 0 0;';
                    b.title=cat+': '+dataByCategory[cat][i];g.appendChild(b);
                }});
                var l=document.createElement('span');
                l.style.cssText='position:absolute;bottom:-18px;left:50%;transform:translateX(-50%);font-size:9px;color:#8fa4b8;';
                l.textContent=timeLabels[i];g.appendChild(l);bars.appendChild(g);
            }}
            var yl=document.getElementById('yLabels');yl.innerHTML='';
            for(var i=5;i>=0;i--){{var s=document.createElement('span');s.textContent=Math.round((maxVal/5)*i);yl.appendChild(s);}}
            var lg=document.getElementById('legend');lg.innerHTML='';
            Object.keys(dataByCategory).forEach(function(cat){{
                var it=document.createElement('div');it.className='legend-item';
                var ic=categories[cat].criticality==='high'?'⚠️':categories[cat].criticality==='medium'?'⚡':'ℹ️';
                it.innerHTML='<span class="legend-color" style="background:'+categories[cat].color+';"></span> '+cat+' '+ic;
                lg.appendChild(it);
            }});
        }}
        buildChart();
    </script>
</body>
</html>"""
    return HTMLResponse(content=html)

@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    alerts = read_json_file(ALERTS_FILE)
    if not isinstance(alerts, list):
        alerts = []
    alerts = sorted(alerts, key=lambda x: x.get('timestamp', 0), reverse=True)

    rows = ""
    for a in alerts:
        crit = get_criticality(a.get('rule_name', ''))
        if crit == 'high':
            bg = '#fff5f5'; border = '#e74c3c'; badge_bg = '#fde8e8'; badge_color = '#c0392b'; badge_text = 'ВЫС'
        elif crit == 'medium':
            bg = '#fffdf5'; border = '#f39c12'; badge_bg = '#fef3e0'; badge_color = '#d68910'; badge_text = 'СРЕД'
        else:
            bg = '#f5faff'; border = '#3498db'; badge_bg = '#e0effb'; badge_color = '#2471a3'; badge_text = 'НИЗ'
        rows += f"""<tr style="border-left:4px solid {border}; background:{bg};">
            <td>{a.get('timestamp','—')}</td>
            <td>{a.get('src_ip','—')}</td>
            <td>{a.get('dst_ip','—')}</td>
            <td>{a.get('rule_name','Unknown')}</td>
            <td><span class="badge" style="background:{badge_bg}; color:{badge_color};">{badge_text}</span></td>
            <td>{a.get('details','—')[:100]}</td>
        </tr>"""

    total = len(alerts)

    html = f"""
    <html>
        <head>
            <title>Все алерты</title>
            <meta charset="utf-8">
            <meta http-equiv="refresh" content="5">
            <style>
                body {{ font-family:Arial; margin:20px; background:#e8f0f8; color:#1e3a5f; }}
                h1 {{ color:#2e5a8a; }}
                .box {{ background:white; padding:15px; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.05); overflow-x:auto; }}
                table {{ width:100%; border-collapse:collapse; font-size:13px; min-width:700px; }}
                th {{ background:#f0f5fb; padding:10px; text-align:left; border-bottom:2px solid #dce8f2; position:sticky; top:0; }}
                td {{ padding:8px; border-bottom:1px solid #f0f4f8; }}
                .badge {{ display:inline-block; padding:2px 8px; border-radius:10px; font-size:10px; font-weight:700; }}
                a {{ color:#4da6ff; }}
            </style>
        </head>
        <body>
            <h1>📋 Все алерты ({total})</h1>
            <div class="box">
                {f'<table><thead><tr><th>Время</th><th>IP ист.</th><th>IP цели</th><th>Правило</th><th>Крит.</th><th>Детали</th></tr></thead><tbody>{rows}</tbody></table>' if total > 0 else '<p>Алертов пока нет</p>'}
            </div>
            <p style="margin-top:15px;"><a href="/">← На главную</a></p>
        </body>
    </html>
    """
    return HTMLResponse(content=html)


# ============================================================
# СТРАНИЦА ПРАВИЛ
# ============================================================
@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    rules = read_json_file(RULES_FILE)
    if not isinstance(rules, (list, dict)):
        rules = {}

    rule_rows = ""
    if isinstance(rules, list):
        for r in rules:
            rule_rows += f"""<tr>
                <td>{r.get('id','—')}</td>
                <td>{r.get('name','—')}</td>
                <td><code>{r.get('pattern','—')}</code></td>
                <td>{r.get('protocol','—')}</td>
                <td>{', '.join(map(str, r.get('ports',[]))) if r.get('ports') else '—'}</td>
            </tr>"""
    elif isinstance(rules, dict) and rules:
        for k, v in rules.items():
            rule_rows += f"""<tr><td>{k}</td><td colspan="4"><pre>{json.dumps(v, ensure_ascii=False)}</pre></td></tr>"""

    rules_count = len(rules) if isinstance(rules, list) else len(rules) if isinstance(rules, dict) else 0

    html = f"""
    <html>
        <head>
            <title>Правила IDS</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family:Arial; margin:20px; background:#e8f0f8; color:#1e3a5f; }}
                h1 {{ color:#2e5a8a; }}
                .box {{ background:white; padding:15px; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.05); overflow-x:auto; }}
                table {{ width:100%; border-collapse:collapse; font-size:13px; }}
                th {{ background:#f0f5fb; padding:10px; text-align:left; border-bottom:2px solid #dce8f2; }}
                td {{ padding:8px; border-bottom:1px solid #f0f4f8; }}
                code {{ background:#f0f4f8; padding:1px 5px; border-radius:3px; }}
                a {{ color:#4da6ff; }}
            </style>
        </head>
        <body>
            <h1>📜 Загруженные правила ({rules_count})</h1>
            <div class="box">
                {f'<table><thead><tr><th>ID</th><th>Название</th><th>Паттерн</th><th>Протокол</th><th>Порты</th></tr></thead><tbody>{rule_rows}</tbody></table>' if rules_count > 0 else '<p>Правила не загружены</p>'}
            </div>
            <p style="margin-top:15px;"><a href="/">← На главную</a></p>
        </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/stats", response_class=HTMLResponse)
async def stats_page(request: Request):
    stats = get_stats()
    alerts = stats['alerts']
    alerts_json = json.dumps(alerts, ensure_ascii=False)

    attack_types = stats['attack_types']
    top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:5]
    top_html = ""
    for name, count in top_attacks:
        crit = get_criticality(name)
        icon = '⚠️' if crit == 'high' else '⚡' if crit == 'medium' else 'ℹ️'
        top_html += f"<tr><td>{icon} {name}</td><td>{count}</td></tr>"

    html = f"""
    <html>
        <head>
            <title>Статистика IDS</title>
            <meta charset="utf-8">
            <meta http-equiv="refresh" content="5">
            <style>
                body {{ font-family:Arial; margin:20px; background:#e8f0f8; color:#1e3a5f; }}
                h1 {{ color:#2e5a8a; }}
                .stats-grid {{ display:flex; gap:15px; flex-wrap:wrap; margin-bottom:20px; }}
                .stat-card {{
                    flex:1 1 150px; min-width:120px;
                    background:white; border-radius:12px; padding:20px;
                    text-align:center; box-shadow:0 2px 12px rgba(46,90,158,0.05);
                }}
                .stat-card .num {{ font-size:36px; font-weight:700; color:#1e3a5f; }}
                .stat-card .lbl {{ font-size:12px; color:#8fa4b8; margin-top:6px; }}
                .stat-card.red .num {{ color:#c0392b; }}
                .stat-card.yellow .num {{ color:#d68910; }}
                .stat-card.blue .num {{ color:#2471a3; }}
                .stat-card.green .num {{ color:#27ae60; }}
                .box {{ background:white; padding:15px; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.05); overflow-x:auto; margin-bottom:15px; }}
                table {{ width:100%; border-collapse:collapse; font-size:13px; }}
                th {{ background:#f0f5fb; padding:10px; text-align:left; border-bottom:2px solid #dce8f2; }}
                td {{ padding:8px; border-bottom:1px solid #f0f4f8; }}
                a {{ color:#4da6ff; }}
                .chart-container {{
                    position:relative; height:300px;
                    border-left:2px solid #dce8f2; border-bottom:2px solid #dce8f2;
                    padding:8px 0 0 40px;
                }}
                .chart-y-labels {{
                    position:absolute; left:4px; top:8px; height:292px;
                    display:flex; flex-direction:column; justify-content:space-between;
                    font-size:10px; color:#8fa4b8;
                }}
                .chart-bars {{
                    display:flex; align-items:flex-end; gap:3px;
                    height:292px; flex-wrap:nowrap; overflow-x:auto;
                }}
                .legend {{
                    display:flex; gap:10px; margin-top:20px; flex-wrap:wrap;
                    font-size:10px; color:#5a7a9a;
                }}
                .legend-item {{ display:flex; align-items:center; gap:4px; }}
                .legend-color {{ width:10px; height:10px; border-radius:2px; }}
            </style>
        </head>
        <body>
            <h1>📊 Статистика IDS</h1>
            
            <div class="stats-grid">
                <div class="stat-card red">
                    <div class="num">{stats['high']}</div>
                    <div class="lbl">⚠️ Высокая критичность</div>
                </div>
                <div class="stat-card yellow">
                    <div class="num">{stats['medium']}</div>
                    <div class="lbl">⚡ Средняя критичность</div>
                </div>
                <div class="stat-card blue">
                    <div class="num">{stats['low']}</div>
                    <div class="lbl">ℹ️ Низкая критичность</div>
                </div>
                <div class="stat-card green">
                    <div class="num">{stats['unique_ips']}</div>
                    <div class="lbl">🌐 Уникальных IP</div>
                </div>
                <div class="stat-card">
                    <div class="num">{stats['total_alerts']}</div>
                    <div class="lbl">📋 Всего алертов</div>
                </div>
                <div class="stat-card">
                    <div class="num">{stats['total_rules']}</div>
                    <div class="lbl">📜 Всего правил</div>
                </div>
            </div>
            
            <div style="display:flex; gap:15px; flex-wrap:wrap;">
                <div class="box" style="flex:1 1 60%; min-width:300px;">
                    <h2>📈 Атаки по времени</h2>
                    <div class="chart-container">
                        <div class="chart-y-labels" id="yLabels"></div>
                        <div class="chart-bars" id="chartBars"></div>
                    </div>
                    <div class="legend" id="legend"></div>
                </div>
                
                <div class="box" style="flex:1 1 30%; min-width:200px;">
                    <h2>🔥 Топ-5 атак</h2>
                    {f'<table><thead><tr><th>Тип атаки</th><th>Кол-во</th></tr></thead><tbody>{top_html}</tbody></table>' if top_html else '<p>Нет данных</p>'}
                </div>
            </div>
            
            <p style="margin-top:15px;"><a href="/">← На главную</a></p>
            
            <script>
                var alertsData = {alerts_json};
                var categories = {{
                    'SQLi': {{color:'#e74c3c',criticality:'high'}},
                    'SYN Flood': {{color:'#e74c3c',criticality:'high'}},
                    'TCP Flood': {{color:'#e74c3c',criticality:'high'}},
                    'Bruteforce': {{color:'#f39c12',criticality:'medium'}},
                    'UDP Flood': {{color:'#f39c12',criticality:'medium'}},
                    'Port scan detected': {{color:'#3498db',criticality:'low'}},
                    'ICMP Flood': {{color:'#3498db',criticality:'low'}}
                }};
                function buildChart(){{
                    if(!alertsData||alertsData.length===0)return;
                    var intervals=10,timeLabels=[],dataByCategory={{}},maxVal=1;
                    for(var i=0;i<intervals;i++)timeLabels.push('-'+(intervals-i)*5+'м');
                    alertsData.forEach(function(a){{
                        var cat=categories[a.rule_name]?a.rule_name:'Other';
                        if(!categories[cat])categories[cat]={{color:'#95a5a6',criticality:'low'}};
                        if(!dataByCategory[cat])dataByCategory[cat]=new Array(intervals).fill(0);
                        var diff=Math.floor((new Date()-new Date(a.timestamp*1000))/60000);
                        var idx=intervals-1-Math.floor(diff/5);
                        if(idx>=0&&idx<intervals)dataByCategory[cat][idx]++;
                    }});
                    Object.values(dataByCategory).forEach(function(arr){{arr.forEach(function(v){{if(v>maxVal)maxVal=v;}});}});
                    var bars=document.getElementById('chartBars');bars.innerHTML='';
                    for(var i=0;i<intervals;i++){{
                        var g=document.createElement('div');
                        g.style.cssText='display:flex;flex-direction:column-reverse;align-items:center;gap:2px;flex:1;min-width:28px;position:relative;';
                        Object.keys(dataByCategory).forEach(function(cat){{
                            var h=Math.max((dataByCategory[cat][i]/maxVal)*292,2);
                            var b=document.createElement('div');
                            b.style.cssText='height:'+h+'px;background:'+categories[cat].color+';width:18px;border-radius:4px 4px 0 0;';
                            b.title=cat+': '+dataByCategory[cat][i];g.appendChild(b);
                        }});
                        var l=document.createElement('span');
                        l.style.cssText='position:absolute;bottom:-18px;left:50%;transform:translateX(-50%);font-size:9px;color:#8fa4b8;';
                        l.textContent=timeLabels[i];g.appendChild(l);bars.appendChild(g);
                    }}
                    var yl=document.getElementById('yLabels');yl.innerHTML='';
                    for(var i=5;i>=0;i--){{var s=document.createElement('span');s.textContent=Math.round((maxVal/5)*i);yl.appendChild(s);}}
                    var lg=document.getElementById('legend');lg.innerHTML='';
                    Object.keys(dataByCategory).forEach(function(cat){{
                        var it=document.createElement('div');it.className='legend-item';
                        var ic=categories[cat].criticality==='high'?'⚠️':categories[cat].criticality==='medium'?'⚡':'ℹ️';
                        it.innerHTML='<span class="legend-color" style="background:'+categories[cat].color+';"></span> '+cat+' '+ic;
                        lg.appendChild(it);
                    }});
                }}
                buildChart();
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/api/alerts")
async def api_alerts():
    alerts = read_json_file(ALERTS_FILE)
    count = len(alerts) if isinstance(alerts, list) else 0
    return {"count": count, "alerts": alerts}


@app.get("/api/rules")
async def api_rules():
    return read_json_file(RULES_FILE)


@app.get("/api/stats")
async def api_stats():
    return get_stats()