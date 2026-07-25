from fastapi import APIRouter, HTTPException
import httpx, re

router = APIRouter()

@router.get("/vehicle-rc")
async def vehicle_rc(registration: str):
    """Get vehicle RC details from registration number"""
    reg = registration.strip().upper()
    if not re.match(r'^[A-Z0-9\s-]{4,15}$', reg):
        return {"status": "error", "message": "Invalid registration number format"}
    
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            # Parivahan public API endpoint
            url = "https://parivahan.gov.in/rcdlstatus/vahan/rcStatus.xhtml"
            # Due to Parivahan's dynamic nature, provide instructional response
            return {
                "status": "info",
                "vehicle": reg,
                "message": "Parivahan portal requires OTP-based login. Use browser automation.",
                "portal": "https://vahan.parivahan.gov.in/nrservices/faces/user/citizen/SearchStatus.xhtml",
                "method": "Manual OTP verification required"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/challan")
async def challan_info(vehicle: str):
    """Get e-Challan details for a vehicle"""
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            return {
                "status": "info",
                "vehicle": vehicle,
                "method": "Visit eChallan portal with vehicle number",
                "portal": "https://echallan.parivahan.gov.in/",
                "note": "Requires captcha solving. Use selenium/playwright for automation"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}
