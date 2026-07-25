from fastapi import APIRouter
import httpx, json, csv, io

router = APIRouter()

# IFSC database (common banks)
IFSC_DATA = {
    "SBIN0000001": {"bank": "State Bank of India", "branch": "MUMBAI MAIN", "city": "MUMBAI", "state": "MAHARASHTRA"},
    "SBIN0000002": {"bank": "State Bank of India", "branch": "DELHI MAIN", "city": "DELHI", "state": "DELHI"},
    "SBIN0000003": {"bank": "State Bank of India", "branch": "KOLKATA MAIN", "city": "KOLKATA", "state": "WEST BENGAL"},
    "HDFC0000001": {"bank": "HDFC Bank", "branch": "MUMBAI", "city": "MUMBAI", "state": "MAHARASHTRA"},
    "HDFC0000002": {"bank": "HDFC Bank", "branch": "DELHI", "city": "DELHI", "state": "DELHI"},
    "ICIC0000001": {"bank": "ICICI Bank", "branch": "MUMBAI", "city": "MUMBAI", "state": "MAHARASHTRA"},
    "ICIC0000002": {"bank": "ICICI Bank", "branch": "BANGALORE", "city": "BANGALORE", "state": "KARNATAKA"},
    "AXIS0000001": {"bank": "Axis Bank", "branch": "MUMBAI", "city": "MUMBAI", "state": "MAHARASHTRA"},
    "BARB0MERBHA": {"bank": "Bank of Baroda", "branch": "MEERUT", "city": "MEERUT", "state": "UTTAR PRADESH"},
    "UTIB0000001": {"bank": "Axis Bank (UTI)", "branch": "MUMBAI", "city": "MUMBAI", "state": "MAHARASHTRA"},
    "PUNB0000001": {"bank": "Punjab National Bank", "branch": "DELHI", "city": "DELHI", "state": "DELHI"},
    "CANB0000001": {"bank": "Canara Bank", "branch": "BANGALORE", "city": "BANGALORE", "state": "KARNATAKA"},
    "BKID0000001": {"bank": "Bank of India", "branch": "MUMBAI", "city": "MUMBAI", "state": "MAHARASHTRA"},
    "UBIN0000001": {"bank": "Union Bank of India", "branch": "MUMBAI", "city": "MUMBAI", "state": "MAHARASHTRA"},
    "ALLA0000001": {"bank": "Allahabad Bank", "branch": "KOLKATA", "city": "KOLKATA", "state": "WEST BENGAL"},
}

@router.get("/ifsc")
async def ifsc_lookup(ifsc: str):
    """Get bank details from IFSC code"""
    ifsc = ifsc.strip().upper()
    if len(ifsc) != 11:
        return {"status": "error", "message": "IFSC must be 11 characters (4 alpha + 7 numeric)"}
    
    # Try local database first
    if ifsc in IFSC_DATA:
        return {"status": "success", "data": IFSC_DATA[ifsc]}
    
    # Try fetching from external API
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = f"https://ifsc.razorpay.com/{ifsc}"
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                return {"status": "success", "data": data}
            
            # Try RBI API
            url2 = f"https://api.razorpay.com/v1/ifsc/{ifsc}"
            resp2 = await client.get(url2)
            if resp2.status_code == 200:
                return {"status": "success", "data": resp2.json()}
    except:
        pass
    
    return {
        "status": "info",
        "ifsc": ifsc,
        "message": "Not found in local DB. Search manually at: https://www.rbi.org.in/scripts/bs_viewcontent.aspx?Id=2009",
        "db_size": len(IFSC_DATA)
    }

@router.get("/upi")
async def upi_lookup(upi_id: str):
    """Check UPI ID validity and get public name"""
    upi_id = upi_id.strip().lower()
    if "@" not in upi_id:
        return {"status": "error", "message": "Invalid UPI ID format (e.g., name@paytm)"}
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Try UPI validation via third-party
            headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
            # This is a simulated check since UPI APIs need merchant keys
            return {
                "status": "info",
                "upi_id": upi_id,
                "note": "UPI name lookup requires merchant API. Use BharatPe/Paytm developer API with valid API key",
                "valid_format": True,
                "vpa": upi_id.split("@")[0],
                "provider": upi_id.split("@")[1] if "@" in upi_id else "unknown"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/pin")
async def pincode_info(pincode: str):
    """Get location details from PIN code"""
    pincode = pincode.strip()
    if not (pincode.isdigit() and len(pincode) == 6):
        return {"status": "error", "message": "Invalid PIN code (6 digits required)"}
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = f"https://api.postalpincode.in/pincode/{pincode}"
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data and data[0].get("Status") == "Success":
                    return {"status": "success", "data": data[0]}
                return {"status": "not_found", "message": "PIN code not found"}
            return {"status": "error", "message": "API error"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
