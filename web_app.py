import json
import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import uvicorn

#----- НАСТРОЙКА -----

ALERTS_FILE = "alerts.json"
RULES_FILE = "rules.json"

#----- ПРИЛОЖЕНИЕ -----

app = FastAPI(title="Система обнаружения вторжений (IDS)")
templates = Jinja2Templates(directory="templates")

#----- ФУНКЦИИ -----

def read_json_file(filename: str):

    if not os.path.exists(filename):

        if "alerts" in filename:
            return []
        else:
            return {}
    
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)  
    except (json.JSONDecodeError, FileNotFoundError):
       
        if "alerts" in filename:
            return []
        else:
            return {}
    
    if data is None:
        if "alerts" in filename:
            return []
        else:
            return {}
    
    return data

# ----- ЭНДПОИНТЫ -----

@app.get("/")
async def home_page():
    html = """
    <html>
        <head>
            <title>IDS — Панель управления</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>СИСТЕМА ОБНАРУЖЕНИЯ ВТОРЖЕНИЙ</h1>
            <p>Добро пожаловать в панель управления IDS.</p>
            <ul>
                <li><a href="/alerts">Таблица алертов</a></li>
                <li><a href="/rules">Список правил</a></li>
                <li><a href="/api/alerts">API: JSON с алертами</a></li>
                <li><a href="/api/rules">API: JSON с правилами</a></li>
            </ul>
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
    rules = read_json_file(RULES_FILE)
    return rules


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
            <h1>Обнаруженные алерты (заглушка)</h1>
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
            <h1>Загруженные правила (заглушка)</h1>
            <div class="rules-box">
                <pre>{rules_json}</pre>
            </div>
            <p><a href="/">← На главную</a></p>
        </body>
    </html>
    """
    return HTMLResponse(content=html)

