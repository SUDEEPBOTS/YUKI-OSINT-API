<div align="center">

# ⚡ YUKI OSINT API

**25+ Legal Intelligence & Data Lookup Tools**

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Railway](https://img.shields.io/badge/Railway-0B0D0E?style=for-the-badge&logo=railway&logoColor=white)](https://railway.app)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**🌐 Live:** [osint.yukiapi.site](https://osint.yukiapi.site) · **📘 Docs:** [osint.yukiapi.site/docs](https://osint.yukiapi.site/docs)

---

**⚠️ LEGAL DISCLAIMER**
> This API uses **ONLY publicly available & legal sources**. No leaked databases, no dark web data, no illegal scraping.  
> All data obtained through official government portals and public APIs.  
> For educational & security research purposes only.

</div>

---

## 🚀 Features

### 🚗 Vehicle
| Endpoint | Description | Source |
|:---------|:------------|:-------|
| `/api/vehicle-rc` | Vehicle registration details | Parivahan Sewa |
| `/api/challan` | e-Challan info & status | Parivahan eChallan |

### 🆔 Identity
| Endpoint | Description | Source |
|:---------|:------------|:-------|
| `/api/pan` | PAN card details | Income Tax Dept |
| `/api/gstin` | GST registration info | GST Portal |
| `/api/voter` | Voter ID / EPIC details | Election Commission |
| `/api/aadhaar-verify` | Aadhaar format validation | UIDAI (Verhoeff) |

### 💳 Finance
| Endpoint | Description | Source |
|:---------|:------------|:-------|
| `/api/ifsc` | IFSC code → bank/branch | RBI + Razorpay |
| `/api/upi` | UPI ID format check | UPI apps |
| `/api/pin` | PIN code → city/state info | India Post API |

### 🌐 OSINT
| Endpoint | Description | Source |
|:---------|:------------|:-------|
| `/api/ip` | IP geolocation & ISP | ipapi.co / ipinfo.io |
| `/api/email` | Email validation + breach check | HIBP + DNS MX |
| `/api/phone` | Phone carrier & location | Carrier lookup |
| `/api/breach` | Have I Been Pwned check | HIBP API |

### 🇮🇳 India
| Endpoint | Description | Source |
|:---------|:------------|:-------|
| `/api/ration` | Ration card family info | State FCS portals |
| `/api/samagra` | MP Samagra family details | MP Samagra portal |
| `/api/aadhaar-ration` | Aadhaar-Ration link status | NFSA portal |
| `/api/school` | UDISE+ school directory | UDISE+ portal |
| `/api/weather` | City weather | wttr.in |
| `/api/gps-reverse` | GPS → address | Nominatim/OSM |

### 🔧 Utilities
| Endpoint | Description | Source |
|:---------|:------------|:-------|
| `/api/dns` | DNS records (A, AAAA, MX, NS) | socket + dnspython |
| `/api/whois` | Domain WHOIS info | python-whois |
| `/api/url-shorten` | URL shortener | is.gd |

---

## 🛠 Quick Start

### Local Development
```bash
# Clone
git clone https://github.com/SUDEEPBOTS/YUKI-OSINT-API.git
cd YUKI-OSINT-API

# Install
pip install -r requirements.txt

# Run
PORT=8000 python3 main.py

# Open
curl http://localhost:8000/health
```

### Deploy on Railway
```bash
# Login
railway login --browserless

# Init & Deploy
railway init
railway up

# Add domain
railway domain add osint.yukiapi.site
```

### Deploy on Vercel
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel
```

---

## 📚 API Usage

```python
import requests

BASE_URL = "https://osint.yukiapi.site/api"

# IP Info
r = requests.get(f"{BASE_URL}/ip", params={"ip": "8.8.8.8"})
print(r.json())

# PIN Code
r = requests.get(f"{BASE_URL}/pin", params={"pincode": "110001"})
print(r.json())

# IFSC
r = requests.get(f"{BASE_URL}/ifsc", params={"ifsc": "SBIN0000001"})
print(r.json())

# DNS Lookup
r = requests.get(f"{BASE_URL}/dns", params={"domain": "google.com"})
print(r.json())

# Weather
r = requests.get(f"{BASE_URL}/weather", params={"city": "Mumbai"})
print(r.json())
```

---

## 🏗 Project Structure
```
YUKI-OSINT-API/
├── main.py                 # FastAPI entry point
├── requirements.txt
├── Dockerfile
├── railway.json
├── routers/
│   ├── vehicle.py          # 🚗 Vehicle RC, Challan
│   ├── identity.py         # 🆔 PAN, GSTIN, Voter, Aadhaar
│   ├── finance.py          # 💳 IFSC, UPI, PIN code
│   ├── osint.py            # 🌐 IP, Email, Phone, Breach
│   ├── india.py            # 🇮🇳 Ration, Samagra, School, Weather
│   └── utils.py            # 🔧 DNS, WHOIS, URL Shorten
└── static/
    └── index.html          # Web UI
```

---

## 📊 Endpoints Summary

| Category | Count |
|:---------|:-----:|
| 🚗 Vehicle | 2 |
| 🆔 Identity | 4 |
| 💳 Finance | 3 |
| 🌐 OSINT | 4 |
| 🇮🇳 India | 6 |
| 🔧 Utilities | 3 |
| 🏥 Health | 1 |
| 📖 Docs | 2 |
| **Total** | **25+** |

---

## 🤝 Contributing
PRs welcome! Please ensure your endpoints use only legal/public data sources.

## 📜 License
MIT License — see [LICENSE](LICENSE)

---

<div align="center">
  
**⚡ Powered by [@hostillbot](https://t.me/hostillbot) · YUKI OSINT API**

</div>
