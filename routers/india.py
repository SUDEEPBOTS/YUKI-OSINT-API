from fastapi import APIRouter
import httpx

router = APIRouter()

@router.get("/ration")
async def ration_info(ration_number: str, state: str = "MP"):
    """Get ration card family details"""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            headers = {"User-Agent": "Mozilla/5.0"}
            
            # State FCS portals
            portals = {
                "MP": "https://mpfood.jabalpur.org/",
                "UP": "https://fcs.up.gov.in/",
                "RJ": "https://food.rajasthan.gov.in/",
                "MH": "https://mahafood.gov.in/"
            }
            
            portal = portals.get(state.upper(), portals["MP"])
            return {
                "status": "info",
                "ration": ration_number,
                "state": state.upper(),
                "method": "Check at state FCS portal",
                "portal": portal,
                "note": "Ration portals require captcha. Use selenium for automation"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/samagra")
async def samagra_info(mobile: str):
    """Get MP Samagra family details from mobile number"""
    mobile = mobile.strip()
    if not mobile.isdigit() or len(mobile) != 10:
        return {"status": "error", "message": "Invalid mobile (10 digits required)"}
    
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            headers = {"User-Agent": "Mozilla/5.0"}
            return {
                "status": "info",
                "mobile": f"{mobile[:3]}XXXXX{mobile[-2:]}",
                "method": "Check at MP Samagra portal",
                "portal": "https://samagra.gov.in/",
                "note": "Samagra portal requires OTP authentication"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/aadhaar-ration")
async def aadhaar_to_ration(aadhaar: str):
    """Check Aadhaar-Ration link status"""
    aadhaar = aadhaar.strip().replace(" ", "")
    if not (aadhaar.isdigit() and len(aadhaar) == 12):
        return {"status": "error", "message": "Invalid Aadhaar"}
    
    return {
        "status": "info",
        "aadhaar": f"XXXX XXXX {aadhaar[-4:]}",
        "method": "Check at NFSA portal",
        "portal": "https://nfsa.gov.in/",
        "note": "Aadhaar-Ration link check requires OTP"
    }

@router.get("/school")
async def school_info(school_code: str, state: str = ""):
    """Get school details from UDISE+ code"""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            headers = {"User-Agent": "Mozilla/5.0"}
            url = f"https://udiseplus.gov.in/api/school?code={school_code}"
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return {"status": "success", "data": resp.json()}
            return {
                "status": "info",
                "code": school_code,
                "portal": "https://udiseplus.gov.in/",
                "method": "Search at UDISE+ portal"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/weather")
async def weather_info(city: str):
    """Get current weather for a city"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = f"https://wttr.in/{city}?format=j1"
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                current = data.get("current_condition", [{}])[0]
                return {
                    "status": "success",
                    "city": city,
                    "data": {
                        "temp_c": current.get("temp_C"),
                        "temp_f": current.get("temp_F"),
                        "humidity": current.get("humidity"),
                        "description": current.get("weatherDesc", [{}])[0].get("value", ""),
                        "wind_speed": current.get("windspeedKmph"),
                        "feels_like": current.get("FeelsLikeC")
                    }
                }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/gps-reverse")
async def gps_reverse(lat: float, lon: float):
    """Reverse geocode lat/lon to address"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            headers = {"User-Agent": "YUKI-OSINT-API/1.0"}
            url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json&addressdetails=1"
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return {"status": "success", "data": resp.json()}
    except Exception as e:
        return {"status": "error", "message": str(e)}
