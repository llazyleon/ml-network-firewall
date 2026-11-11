#!/usr/bin/env python3
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
import json
import asyncio
from datetime import datetime
from typing import Dict, List

app = FastAPI(title="ML Firewall Dashboard", version="1.0")

dashboard_data = {
    'total_flows': 0,
    'benign_flows': 0,
    'attack_flows': 0,
    'blocked_ips': [],
    'enforcement_actions': 0,
    'alerts': [],
}

active_connections: List[WebSocket] = []

async def broadcast_update():
    if not active_connections:
        return
    payload = {**dashboard_data, 'timestamp': datetime.now().isoformat()}
    dead = []
    for ws in active_connections:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        active_connections.remove(ws)


@app.get("/")
async def root():
    return FileResponse("src/dashboard.html", media_type="text/html")


@app.get("/api/health")
async def health():
    return {'status': 'healthy'}


@app.get("/api/stats")
async def get_stats():
    return {**dashboard_data, 'timestamp': datetime.now().isoformat()}


@app.post("/api/alert")
async def record_alert(alert: dict):
    alert['timestamp'] = datetime.now().isoformat()

    dashboard_data['total_flows'] += 1
    dashboard_data['attack_flows'] += 1

    if alert.get('source_ip') not in dashboard_data['blocked_ips']:
        dashboard_data['blocked_ips'].append(alert['source_ip'])

    dashboard_data['enforcement_actions'] += 1

    dashboard_data['alerts'].insert(0, alert)
    dashboard_data['alerts'] = dashboard_data['alerts'][:100]

    await broadcast_update()

    return {'status': 'recorded'}


@app.post("/api/benign")
async def record_benign():
    dashboard_data['total_flows'] += 1
    dashboard_data['benign_flows'] += 1
    await broadcast_update()
    return {'status': 'recorded'}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        await websocket.send_json({**dashboard_data, 'timestamp': datetime.now().isoformat()})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)


if __name__ == '__main__':
    import uvicorn
    print("\n" + "=" * 70)
    print("PHASE 5: WEB DASHBOARD")
    print("=" * 70)
    print("\nStarting dashboard backend...")
    print("  • URL: http://localhost:8000")
    print("\nPress Ctrl+C to stop\n")
    print("=" * 70 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=8000)
