from fastapi import APIRouter, HTTPException
import httpx, json

router = APIRouter()

@router.get("/pan")
async def pan_info(pan: str):
    """Get PAN card details"""
    pan = pan.strip().upper()
    if len(pan) != 10:
        return {"status": "error", "message": "PAN must be 10 characters"}
    
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Income Tax portal verification
            url = "https://www.incometax.gov.in/pan/verify"
            headers = {"User-Agent": "Mozilla/5.0"}
            # Provide guidance since it requires OTP
            return {
                "status": "info", 
                "pan": pan,
                "method": "Verify at Income Tax portal",
                "portal": "https://www.incometax.gov.in/",
                "note": "Full PAN details require OTP authentication"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/gstin")
async def gstin_info(gstin: str):
    """Get GST registration details"""
    gstin = gstin.strip().upper()
    if len(gstin) != 15:
        return {"status": "error", "message": "GSTIN must be 15 characters"}
    
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json"
            }
            url = f"https://api.gst.gov.in/search/gst?gstin={gstin}"
            resp = await client.get(url, headers=headers)
            
            if resp.status_code == 200:
                data = resp.json()
                return {"status": "success", "data": data}
            return {
                "status": "info",
                "gstin": gstin,
                "portal": "https://www.gst.gov.in/",
                "note": "GST portal requires captcha. Use official API with API key"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/voter")
async def voter_info(epic: str):
    """Get voter ID details from EPIC number"""
    epic = epic.strip().upper()
    if len(epic) < 6:
        return {"status": "error", "message": "Invalid EPIC number"}
    
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            headers = {"User-Agent": "Mozilla/5.0"}
            url = "https://electoralsearch.in/"
            return {
                "status": "info",
                "epic": epic,
                "method": "Search at Election Commission portal",
                "portal": "https://electoralsearch.in/",
                "note": "Requires captcha solving for automated access"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/aadhaar-verify")
async def aadhaar_verify(aadhaar: str):
    """Verify Aadhaar virtual ID format"""
    aadhaar = aadhaar.strip().replace(" ", "")
    if not (aadhaar.isdigit() and len(aadhaar) == 12):
        return {"status": "error", "message": "Aadhaar must be 12 digits"}
    
    # Verhoeff checksum validation
    def verhoeff(num):
        d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
        p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4]]
        inv = [0,4,3,2,1,5,6,7,8,9]
        c = 0
        for i, n in enumerate(reversed(num)):
            c = d[c][p[i % 2][int(n)]]
        return inv[c] == 0
    
    valid = verhoeff(aadhaar)
    return {
        "status": "success",
        "aadhaar": f"XXXX XXXX {aadhaar[-4:]}",
        "valid_format": valid,
        "note": "Only format validation. Full Aadhaar verification requires UIDAI portal with OTP"
    }
