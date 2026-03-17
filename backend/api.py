"""
SPARK — Smart Protection & Anomaly Recognition Kernel
FastAPI WebSockets Backend Server

Serves the CAN bus simulation engine and AI detection 
pipeline to the web frontend via REST and WebSockets.
"""

import os
import sys
import asyncio
import uuid
import json
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Any

import google.generativeai as genai
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    # Fallback to hardcoded key if env not found (not recommended for production)
    api_key = "AIzaSyAo55hRZMEh4nJtBs-0uJFKGXTkFfSi8Cc"

genai.configure(api_key=api_key)

# Ensure project root is in path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from engine.simulator import CANBusSimulator
from engine.detector import DetectionEngine
from engine.attacker import get_attack_profiles

app = FastAPI(title="SPARK API", description="CAN Bus IDS Engine Backend")

# Allow CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════
class AppState:
    def __init__(self):
        dataset_path = os.path.join(project_root, 'data', 'synthetic_can_data.csv')
        if not os.path.exists(dataset_path):
            dataset_path = None
        
        self.simulator = CANBusSimulator(dataset_path=dataset_path, speed_multiplier=1.0)
        
        models_dir = os.path.join(project_root, 'models', 'saved')
        self.detector = DetectionEngine(models_dir)
        
        self.is_running = False
        self.active_connections: List[WebSocket] = []
        
        # We will hold verdicts in memory for quick API access if needed
        self.verdicts: List[Dict] = []
        self.loop = None
        
        # Generative AI State
        self.gemini_model = genai.GenerativeModel('gemini-2.5-flash')
        self.last_gemini_call = 0
        self.current_attack_type = None
        self.active_intel = None
        
        # Register the callback
        self.simulator.register_callback(self.process_message)
        
    def process_message(self, msg):
        """Callback: Run ML detection on incoming simulation message and broadcast"""
        msg_dict = msg.to_dict()
        verdict = self.detector.analyze_message(msg_dict)
        verdict_dict = verdict.to_dict()
        
        # Add to local buffer
        self.verdicts.append(verdict_dict)
        if len(self.verdicts) > 1000:
            self.verdicts = self.verdicts[-500:]
            
        cls = verdict_dict["classification"]
        
        # Suppress threats if no attack is active
        if not self.simulator.attack_active and cls != "Normal":
            verdict_dict["classification"] = "Normal"
            verdict_dict["is_anomaly"] = False
            verdict_dict["severity"] = "SAFE"
            verdict_dict["confidence"] = 0.99
            cls = "Normal"

        if self.loop:
            if cls != "Normal":
                if cls != self.current_attack_type or (time.time() - self.last_gemini_call > 30):
                    self.current_attack_type = cls
                    self.last_gemini_call = time.time()
                    self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self.fetch_ai_intel(verdict_dict)))
                    self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self.broadcast({"type": "ai_insight_loading", "data": {"classification": cls}})))
                
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self.broadcast({"type": "verdict", "data": verdict_dict})))
        
    async def fetch_ai_intel(self, verdict):
        """Fetches dynamic threat intelligence from Gemini"""
        cls = verdict["classification"]
        try:
            prompt = f"You are SPARK, an AI cybersecurity analyst monitoring a vehicle CAN bus. You just detected a **{cls}** attack with {verdict['confidence']*100:.1f}% confidence. The highly anomalous CAN ID involved is {verdict['can_id_hex']}. Provide a highly technical, precise threat intelligence briefing consisting of 3 sections: 1) Mechanism of this attack, 2) Potential physical impact on vehicle ECUs, 3) Immediate mitigation strategies. Keep it concise. Conclude with the likely MITRE ATT&CK technique and a relevant CVE. Format your response strictly in Markdown without any preface or pleasantries."
            response = await self.gemini_model.generate_content_async(prompt)
            self.active_intel = response.text
            await self.broadcast({"type": "ai_insight", "data": {"classification": cls, "content": self.active_intel}})
        except Exception as e:
            print(f"Gemini API Error: {e}")
            self.last_gemini_call = 0 # Reset so it tries again

    async def broadcast(self, message: Dict):
        """Broadcast JSON message to all connected WebSockets"""
        if not self.active_connections:
            return
            
        json_msg = json.dumps(message)
        dead_connections = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(json_msg)
            except Exception:
                dead_connections.append(connection)
                
        for dc in dead_connections:
            self.active_connections.remove(dc)


state = AppState()


# Broadcast loop for aggregated metrics
async def metrics_broadcaster():
    """Periodically broadcasts overall system metrics"""
    while True:
        if state.is_running and state.active_connections:
            stats = state.simulator.get_stats()
            threats = state.detector.get_threat_summary()
            
            await state.broadcast({
                "type": "metrics",
                "data": {
                    "stats": stats,
                    "threats": threats
                }
            })
            
        await asyncio.sleep(1.0) # 1Hz metrics update

@app.on_event("startup")
async def startup_event():
    state.loop = asyncio.get_running_loop()
    asyncio.create_task(metrics_broadcaster())


# ═══════════════════════════════════════════════════════
# WEBSOCKET ROUTE
# ═══════════════════════════════════════════════════════
@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.active_connections.append(websocket)
    
    # Send initial state
    await websocket.send_text(json.dumps({
        "type": "system_state",
        "data": {
            "is_running": state.is_running,
            "models_loaded": {
                "xgb": state.detector.xgb_model is not None,
                "rf": state.detector.rf_model is not None,
                "iso": state.detector.iso_model is not None,
            }
        }
    }))
    
    try:
        while True:
            # Keep connection alive, listen for client generic pings if needed
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        state.active_connections.remove(websocket)


# ═══════════════════════════════════════════════════════
# REST API ROUTES
# ═══════════════════════════════════════════════════════

class AttackRequest(BaseModel):
    attack_type: str
    duration: int = 5
    intensity: int = 50

@app.post("/api/control/start")
async def start_engine():
    if not state.is_running:
        state.simulator.start()
        state.is_running = True
        await state.broadcast({"type": "system_state", "data": {"is_running": True}})
    return {"status": "started"}

@app.post("/api/control/stop")
async def stop_engine():
    if state.is_running:
        state.simulator.stop()
        state.is_running = False
        await state.broadcast({"type": "system_state", "data": {"is_running": False}})
    return {"status": "stopped"}

class IsolateRequest(BaseModel):
    can_id_hex: str

@app.post("/api/control/isolate")
async def isolate_ecu(req: IsolateRequest):
    if not state.is_running:
        return JSONResponse(status_code=400, content={"error": "Engine must be running to isolate ECUs."})
        
    state.simulator.quarantine_id(req.can_id_hex)
    await state.broadcast({"type": "quarantine_update", "data": {"action": "isolated", "can_id_hex": req.can_id_hex}})
    return {"status": "isolated", "can_id_hex": req.can_id_hex}

@app.post("/api/control/restore")
async def restore_ecu():
    state.simulator.clear_quarantine()
    await state.broadcast({"type": "quarantine_update", "data": {"action": "restored"}})
    return {"status": "restored"}

@app.get("/api/attacks/profiles")
async def get_profiles():
    return get_attack_profiles()

@app.post("/api/attacks/inject")
async def inject_attack(req: AttackRequest):
    if not state.is_running:
        return JSONResponse(status_code=400, content={"error": "Engine must be running to inject attacks."})
        
    profiles = get_attack_profiles()
    if req.attack_type not in profiles:
        return JSONResponse(status_code=400, content={"error": f"Unknown attack type: {req.attack_type}"})
        
    state.simulator.inject_attack(req.attack_type, req.duration, req.intensity)
    
    await state.broadcast({
        "type": "attack_launched", 
        "data": {
            "attack_type": req.attack_type, 
            "duration": req.duration,
            "profile": profiles[req.attack_type]
        }
    })
    
    return {"status": "attack_injected", "type": req.attack_type}

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "engine_running": state.is_running,
        "active_connections": len(state.active_connections)
    }

@app.get("/api/gemini/fsl-audit")
async def security_audit():
    """Gemini-powered full system audit based on recent traffic"""
    recent_msgs = state.simulator.get_recent_messages(50)
    recent_verdicts = state.detector.get_recent_verdicts(20)
    
    ctx = {
        "messages": recent_msgs,
        "verdicts": recent_verdicts,
        "threat_summary": state.detector.get_threat_summary()
    }
    
    try:
        prompt = f"Perform a comprehensive CAN bus security audit. Data context: {json.dumps(ctx)}. Provide: 1) Overall security posture, 2) Analysis of any detected anomalies, 3) Suggestions for ECU hardening. Format in Markdown."
        response = await state.gemini_model.generate_content_async(prompt)
        return {"audit": response.text}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# Run with: uvicorn backend.api:app --reload --port 8000
