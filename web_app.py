import json
import os
import threading
from queue import Queue
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn

# ----- НАСТРОЙКИ -----
ALERTS_FILE = "alerts.json"
RULES_FILE  = "rules.json"

# ----- ОЧЕРЕДЬ ДЛЯ БЕЗОПАСНОЙ ЗАПИСИ -----
# Queue — потокобезопасная очередь 
alert_queue = Queue()

# ----- ПРИЛОЖЕНИЕ -----
app = FastAPI(title="Система обнаружения вторжений (IDS)")
app.mount("/static", StaticFiles(directory="."), name="static")
templates = Jinja2Templates(directory="templates")

# ----- ФУНКЦИИ -----

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


def write_alert_to_file(alert: dict):
 
   
    alerts = read_json_file(ALERTS_FILE)
    
    # Если read_json_file вернула словарь (ошибка) — создаём новый список
    if not isinstance(alerts, list):
        alerts = []
    
    alerts.append(alert)
    
    with open(ALERTS_FILE, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)


def process_alert_queue():
   
    print("[Queue] Обработчик очереди алертов запущен")
    while True:
        alert = alert_queue.get()
        
        write_alert_to_file(alert)
        
        alert_queue.task_done()
        
        print(f"[Queue] Алерт записан: {alert.get('rule_name', 'Unknown')} от {alert.get('src_ip', 'Unknown')}")


# ----- ЗАПУСК ФОНОВОГО ОБРАБОТЧИКА -----
queue_thread = threading.Thread(target=process_alert_queue, daemon=True)
queue_thread.start()

# ----- ЭНДПОИНТЫ -----

@app.get("/")
async def home_page():
    """Главная страница с PNG-щитом."""
    html = """
    <html>
        <head>
            <title>IDS — Панель управления</title>
            <meta charset="utf-8">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    min-height: 100vh;
                    background: linear-gradient(160deg, #e8f0f8 0%, #d4e2f0 25%, #c5d8ec 50%, #d4e2f0 75%, #e8f0f8 100%);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    position: relative;
                    overflow: hidden;
                }
                
                body::before {
                    content: '';
                    position: absolute;
                    top: -150px;
                    right: -100px;
                    width: 500px;
                    height: 500px;
                    background: radial-gradient(circle, rgba(70, 130, 200, 0.06) 0%, transparent 70%);
                    border-radius: 50%;
                    z-index: 0;
                }
                
                body::after {
                    content: '';
                    position: absolute;
                    bottom: -150px;
                    left: -100px;
                    width: 400px;
                    height: 400px;
                    background: radial-gradient(circle, rgba(50, 100, 180, 0.05) 0%, transparent 70%);
                    border-radius: 50%;
                    z-index: 0;
                }
                
                .stripe-top {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 4px;
                    background: linear-gradient(90deg, transparent 10%, #8ab4e0 30%, #5b9bd5 50%, #8ab4e0 70%, transparent 90%);
                    z-index: 0;
                }
                
                .stripe-bottom {
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    width: 100%;
                    height: 4px;
                    background: linear-gradient(90deg, transparent 10%, #8ab4e0 30%, #5b9bd5 50%, #8ab4e0 70%, transparent 90%);
                    z-index: 0;
                }
                
                .container {
                    text-align: center;
                    position: relative;
                    z-index: 1;
                }
                
                h1 {
                    color: #1e3a5f;
                    font-size: 32px;
                    font-weight: 600;
                    margin-bottom: 6px;
                    letter-spacing: 1px;
                }
                
                .subtitle {
                    color: #6b8aaa;
                    font-size: 15px;
                    margin-bottom: 70px;
                }
                
                .shield-wrapper {
                    position: relative;
                    width: 520px;
                    height: 520px;
                    margin: 0 auto;
                }
                
                .circle-connections {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    z-index: 1;
                    pointer-events: none;
                }
                
                /* Синий щит */
                .shield {
                    position: absolute;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    width: 150px;
                    height: 150px;
                    background: linear-gradient(135deg, #4a90d9 0%, #2e6ab0 40%, #1e4d85 100%);
                    clip-path: polygon(50% 0%, 95% 15%, 95% 55%, 50% 100%, 5% 55%, 5% 15%);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 12px 45px rgba(30, 77, 133, 0.35), inset 0 1px 0 rgba(255,255,255,0.2);
                    z-index: 2;
                }
                
                /* Картинка внутри щита */
                .shield-img {
                    width: 130px;
                    height: auto;
                    filter: drop-shadow(0 2px 3px rgba(0,0,0,0.3));
                }
                
                .card {
                    position: absolute;
                    width: 160px;
                    padding: 22px 14px;
                    background: white;
                    border-radius: 16px;
                    text-align: center;
                    text-decoration: none;
                    color: #3a5070;
                    box-shadow: 0 6px 25px rgba(46, 90, 158, 0.10);
                    transition: all 0.35s cubic-bezier(0.25, 0.8, 0.25, 1.2);
                    z-index: 3;
                    border: 1px solid #dce8f2;
                }
                
                .card:hover {
                    transform: translateY(-8px) scale(1.03);
                    box-shadow: 0 16px 40px rgba(46, 90, 158, 0.20);
                    border-color: #a0c4e6;
                    background: #fdfeff;
                }
                
                .card-alerts {
                    top: 0;
                    left: 50%;
                    transform: translateX(-50%);
                }
                .card-alerts:hover {
                    transform: translateX(-50%) translateY(-8px) scale(1.03);
                }
                
                .card-rules {
                    bottom: 0;
                    left: 5px;
                }
                
                .card-stats {
                    bottom: 0;
                    right: 5px;
                }
                
                .card .icon {
                    font-size: 30px;
                    display: block;
                    margin-bottom: 10px;
                }
                
                .card .title {
                    font-size: 16px;
                    font-weight: 600;
                    margin-bottom: 3px;
                    color: #2e5a8a;
                }
                
                .card .desc {
                    font-size: 11px;
                    color: #8fa4b8;
                    line-height: 1.4;
                }
            </style>
        </head>
        <body>
            <div class="stripe-top"></div>
            <div class="stripe-bottom"></div>
            
            <div class="container">
                <h1>СИСТЕМА ОБНАРУЖЕНИЯ ВТОРЖЕНИЙ</h1>
                <p class="subtitle">Панель управления безопасностью</p>
                
                <div class="shield-wrapper">
                    
                    <!-- Круг с разрывами -->
                    <svg class="circle-connections" viewBox="0 0 520 520" xmlns="http://www.w3.org/2000/svg">
                        <circle 
                            cx="260" 
                            cy="260" 
                            r="110" 
                            fill="none" 
                            stroke="#5b9bd5" 
                            stroke-width="4" 
                            stroke-dasharray="180 50"
                            stroke-linecap="round"
                            transform="rotate(-16 260 260)"
                        />
                    </svg>
                    
                    <!-- Синий щит с PNG внутри -->
                    <div class="shield">
                        <img src="/static/shield.png" alt="Щит" class="shield-img">
                    </div>
                    
                    <!-- Карточки -->
                    <a href="/alerts" class="card card-alerts">
                        <span class="icon">⚠️</span>
                        <span class="title">Алерты</span>
                        <span class="desc">Обнаруженные угрозы</span>
                    </a>
                    
                    <a href="/rules" class="card card-rules">
                        <span class="icon">📜</span>
                        <span class="title">Правила</span>
                        <span class="desc">Загруженные сигнатуры</span>
                    </a>
                    
                    <a href="/stats" class="card card-stats">
                        <span class="icon">📊</span>
                        <span class="title">Статистика</span>
                        <span class="desc">Пакеты, потоки, события</span>
                    </a>
                </div>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/api/alerts")
async def api_alerts():
   
    alerts = read_json_file(ALERTS_FILE)
    
    if isinstance(alerts, list):
        count = len(alerts)
    else:
        count = 0
    
    return {
        "count": count,
        "alerts": alerts
    }


@app.get("/api/rules")
async def api_rules():
   
    return read_json_file(RULES_FILE)


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    
    alerts = read_json_file(ALERTS_FILE)
    
    if isinstance(alerts, list):
        count = len(alerts)
    else:
        count = 0
    
    alerts_json = json.dumps(alerts, indent=2, ensure_ascii=False)
    
    html = f"""
    <html>
        <head>
            <title>Алерты IDS</title>
            <meta charset="utf-8">
            <meta http-equiv="refresh" content="5">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #1e1e1e;
                    color: #e0e0e0;
                }}
                h1 {{ color: #ff6b6b; }}
                .alert-box {{
                    background: #2d2d2d;
                    padding: 15px;
                    border-radius: 5px;
                    border: 1px solid #444;
                }}
                pre {{
                    color: #4da6ff;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }}
                a {{
                    color: #4da6ff;
                    text-decoration: none;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <h1>⚠️ Обнаруженные алерты</h1>
            <p>Всего алертов: <b>{count}</b></p>
            <div class="alert-box">
                <pre>{alerts_json}</pre>
            </div>
            <p><a href="/">← На главную</a></p>
        </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    
    rules = read_json_file(RULES_FILE)
    rules_json = json.dumps(rules, indent=2, ensure_ascii=False)
    
    html = f"""
    <html>
        <head>
            <title>Правила IDS</title>
            <meta charset="utf-8">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #1e1e1e;
                    color: #e0e0e0;
                }}
                h1 {{ color: #4da6ff; }}
                .rules-box {{
                    background: #2d2d2d;
                    padding: 15px;
                    border-radius: 5px;
                    border: 1px solid #444;
                }}
                pre {{
                    color: #4da6ff;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }}
                a {{
                    color: #4da6ff;
                    text-decoration: none;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <h1>📜 Загруженные правила</h1>
            <div class="rules-box">
                <pre>{rules_json}</pre>
            </div>
            <p><a href="/">← На главную</a></p>
        </body>
    </html>
    """
    return HTMLResponse(content=html)


# ===== НОВЫЙ ЭНДПОИНТ: ДОБАВЛЕНИЕ АЛЕРТА =====

@app.post("/api/alerts")
async def add_alert(alert: dict):
    """
    POST-эндпоинт для добавления нового алерта.
    
    Принимает JSON с алертом, добавляет в очередь на запись.
    
    Пример JSON для отправки:
    {
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "rule_name": "SQL Injection",
        "payload": "SELECT * FROM users"
    }
    """
    
    if "timestamp" not in alert:
        alert["timestamp"] = datetime.now().isoformat()
    
    
    alert_queue.put(alert)
    
    return {
        "status": "ok",
        "message": f"Алерт добавлен в очередь",
        "queue_size": alert_queue.qsize()
    }


@app.post("/api/alerts/bulk")
async def add_alerts_bulk(alerts: list):
 
    count = 0
    for alert in alerts:
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.now().isoformat()
        alert_queue.put(alert)
        count += 1
    
    return {
        "status": "ok",
        "message": f"Добавлено {count} алертов в очередь",
        "queue_size": alert_queue.qsize()
    }