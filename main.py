from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn, os, time

app = FastAPI(
    title="YUKI OSINT API",
    description="25+ Legal Intelligence & Data Lookup Tools — Vehicle, PAN, GST, Voter, UPI, IP, Email & more",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import routers
from routers.vehicle import router as vehicle_router
from routers.identity import router as identity_router
from routers.finance import router as finance_router
from routers.osint import router as osint_router
from routers.india import router as india_router
from routers.utils import router as utils_router

app.include_router(vehicle_router, prefix="/api", tags=["🚗 Vehicle"])
app.include_router(identity_router, prefix="/api", tags=["🆔 Identity"])
app.include_router(finance_router, prefix="/api", tags=["💳 Finance"])
app.include_router(osint_router, prefix="/api", tags=["🌐 OSINT"])
app.include_router(india_router, prefix="/api", tags=["🇮🇳 India"])
app.include_router(utils_router, prefix="/api", tags=["🔧 Utilities"])

@app.get("/", response_class=HTMLResponse)
async def home():
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>YUKI OSINT API</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#e0e0e0;font-family:'Segoe UI',sans-serif;min-height:100vh}
.header{background:linear-gradient(135deg,#0d1117,#1a2332);border-bottom:1px solid #2d3a4a;padding:30px;text-align:center}
.header h1{font-size:2em;background:linear-gradient(135deg,#4a88d4,#8ab4f8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}
.header p{color:#8b9bb5;font-size:1em}
.stats{display:flex;justify-content:center;gap:40px;padding:20px;flex-wrap:wrap}
.stat{text-align:center}
.stat span{font-size:2.5em;font-weight:700;color:#4a88d4;display:block}
.stat label{color:#8b9bb5;font-size:.85em;text-transform:uppercase}
.container{max-width:1200px;margin:0 auto;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}
.card{background:#111822;border:1px solid #1e2a3a;border-radius:12px;padding:18px;transition:.2s}
.card:hover{border-color:#4a88d4;transform:translateY(-2px);box-shadow:0 8px 25px rgba(74,136,212,.15)}
.card .icon{font-size:1.8em;margin-bottom:6px}
.card h3{color:#e0e7ef;font-size:1em;margin-bottom:4px}
.card p{color:#8b9bb5;font-size:.82em;margin-bottom:8px}
.card .badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.7em;font-weight:600}
.badge.legal{background:#1a3a2a;color:#4ade80}
.badge.grey{background:#3a2a1a;color:#fbbf24}
.badge.own{background:#1a2a3a;color:#60a5fa}
.endpoint{font-family:monospace;font-size:.78em;color:#4a88d4;background:#0a0f1a;padding:4px 8px;border-radius:6px;display:inline-block;margin-top:6px}
.footer{text-align:center;padding:30px;color:#4a5568;font-size:.85em}
.alert{background:#1a2a1a;border:1px solid #2a4a2a;border-radius:10px;padding:14px 18px;margin:20px auto;max-width:700px;text-align:center;color:#9bca9b;font-size:.85em}
</style>
</head>
<body>
<div class=header>
<h1>⚡ YUKI OSINT API</h1>
<p>25+ Legal Intelligence &amp; Data Lookup Tools</p>
</div>
<div class=stats>
<div class=stat><span>25+</span><label>Endpoints</label></div>
<div class=stat><span>🔒</span><label>100% Legal</label></div>
<div class=stat><span>⚡</span><label>Free</label></div>
</div>
<div class=container>
<div class=alert>✅ All endpoints use PUBLIC / LEGAL sources only. No leaked databases. No illegal data.</div>
<div class=grid>
<div class=card><div class=icon>🚗</div><h3>Vehicle RC</h3><p>Registration number se full RC details</p></div>
<div class=card><div class=icon>🚦</div><h3>Challan Info</h3><p>e-Challan details + payment status</p></div>
<div class=card><div class=icon>🆔</div><h3>PAN Info</h3><p>PAN se name, status, DOB</p></div>
<div class=card><div class=icon>🏦</div><h3>GSTIN</h3><p>GSTIN se business/trade details</p></div>
<div class=card><div class=icon>🗳</div><h3>Voter ID</h3><p>Epic number se voter details</p></div>
<div class=card><div class=icon>🏧</div><h3>IFSC Code</h3><p>IFSC se bank + branch info</p></div>
<div class=card><div class=icon>💳</div><h3>UPI Lookup</h3><p>UPI ID se registered name (if public)</p></div>
<div class=card><div class=icon>🌐</div><h3>IP Info</h3><p>IP address full geolocation</p></div>
<div class=card><div class=icon>📧</div><h3>Email OSINT</h3><p>Email breach check + validation</p></div>
<div class=card><div class=icon>📞</div><h3>Phone OSINT</h3><p>Mobile carrier + location</p></div>
<div class=card><div class=icon>🆘</div><h3>Breach Check</h3><p>Email/phone breach lookup</p></div>
<div class=card><div class=icon>🍲</div><h3>Ration Card</h3><p>Ration number se family info</p></div>
<div class=card><div class=icon>👨‍👩‍👧‍👦</div><h3>Samagra MP</h3><p>MP Samagra family details</p></div>
<div class=card><div class=icon>🔗</div><h3>Aadhaar→Ration</h3><p>Aadhaar-link ration check</p></div>
<div class=card><div class=icon>📖</div><h3>School Info</h3><p>UDISE+ school directory</p></div>
<div class=card><div class=icon>📸</div><h3>Instagram</h3><p>Public profile info</p></div>
<div class=card><div class=icon>📍</div><h3>GPS Reverse</h3><p>Lat/lon se address</p></div>
<div class=card><div class=icon>🌡</div><h3>Weather</h3><p>City current weather</p></div>
<div class=card><div class=icon>🌐</div><h3>DNS Lookup</h3><p>Domain DNS records</p></div>
<div class=card><div class=icon>🔍</div><h3>WHOIS</h3><p>Domain WHOIS info</p></div>
<div class=card><div class=icon>🧠</div><h3>AI Chat</h3><p>DeepSeek + Gemini + GPT</p></div>
<div class=card><div class=icon>📮</div><h3>PIN Code</h3><p>PIN se city/district info</p></div>
<div class=card><div class=icon>🆔</div><h3>Aadhaar Verify</h3><p>Virtual ID format check</p></div>
<div class=card><div class=icon>🔧</div><h3>URL Shorten</h3><p>Shorten long URLs</p></div>
<div class=card><div class=icon>📸</div><h3>Screenshot</h3><p>Website screenshot</p></div>
</div>
<p style=text-align:center;margin-top:30px>
<a href=/docs style='color:#4a88d4;font-size:1.1em'>📘 API Documentation →</a>
</p>
</div>
<div class=footer>⚡ Powered by @hostillbot • YUKI OSINT API v2.0</div>
</body>
</html>"""

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "endpoints": 25}

if __name__ == "__main__":
    import sys, os
    port = 8000
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
    port = int(os.getenv("PORT", port))
    print(f"Starting on PORT={port} (from env={os.getenv('PORT', 'not set')})", flush=True)
    uvicorn.run("main:app", host="0.0.0.0", port=port)
