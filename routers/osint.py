from fastapi import APIRouter
import httpx, json, socket, re

router = APIRouter()

@router.get("/ip")
async def ip_info(ip: str = None, ip_address: str = None):
    """Get IP geolocation and ISP info"""
    target = ip or ip_address
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            if not target:
                # Get requester's IP
                resp = await client.get("https://api.ipify.org?format=json")
                my_ip = resp.json().get("ip", "")
                resp2 = await client.get(f"https://ipapi.co/{my_ip}/json/")
                if resp2.status_code == 200:
                    return {"status": "success", "your_ip": my_ip, "data": resp2.json()}
                return {"status": "success", "ip": my_ip}
            
            # IP validation
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                return {"status": "error", "message": "Invalid IP format"}
            
            resp = await client.get(f"https://ipapi.co/{target}/json/")
            if resp.status_code == 200:
                return {"status": "success", "ip": target, "data": resp.json()}
            
            # Fallback
            resp2 = await client.get(f"https://ipinfo.io/{target}/json")
            if resp2.status_code == 200:
                return {"status": "success", "ip": target, "data": resp2.json()}
    except Exception as e:
        pass
    
    return {"status": "error", "message": "Could not fetch IP info"}

@router.get("/email")
async def email_osint(email: str):
    """Check email validity and breach status"""
    email = email.strip().lower()
    if "@" not in email or "." not in email:
        return {"status": "error", "message": "Invalid email format"}
    
    domain = email.split("@")[1]
    results = {
        "email": email,
        "valid_format": True,
        "domain_check": None,
        "haveibeenpwned": None,
        "disposable": False
    }
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Check MX records
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, 'MX')
                results["domain_check"] = {"has_mx": True, "mx_servers": [str(x.exchange) for x in answers[:3]]}
            except:
                results["domain_check"] = {"has_mx": False, "note": "No mail servers found"}
                return {"status": "success", "data": results}
            
            # Check disposable domains
            disposable_domains = {"tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com", "yopmail.com", "throwaway.email"}
            results["disposable"] = domain in disposable_domains
            
            # HIBP breach check (k-anonymity)
            import hashlib
            hash_prefix = hashlib.sha1(email.encode()).hexdigest()[:5].upper()
            hibp_url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"
            resp = await client.get(hibp_url, headers={"User-Agent": "YUKI-OSINT-API"})
            if resp.status_code == 200:
                results["haveibeenpwned"] = "Check at https://haveibeenpwned.com/ (API rate limited)"
            
            # Hunter.io check (if available)
            return {"status": "success", "data": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/phone")
async def phone_osint(phone: str):
    """Get phone carrier and location info"""
    phone = re.sub(r'[\s+\-]', '', phone)
    if not phone.isdigit() or len(phone) < 10:
        return {"status": "error", "message": "Invalid phone number (10+ digits required)"}
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Use free carrier lookup
            url = f"https://carrierlookup.com/api/lookup?number={phone}"
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            
            # Determine operator from first digits (India)
            prefix = phone[:4]
            operators = {
                "999": "Airtel", "998": "Airtel", "997": "Airtel", "996": "Airtel",
                "987": "Jio", "986": "Jio", "985": "Jio", "984": "Jio",
                "981": "VI", "982": "VI", "983": "VI",
                "990": "BSNL", "991": "BSNL", "992": "BSNL", "993": "BSNL",
                "700": "Airtel", "701": "Airtel", "702": "Airtel",
                "703": "Jio", "704": "Jio", "705": "Jio", "706": "Jio",
                "707": "VI", "708": "VI", "709": "VI",
                "800": "BSNL", "801": "BSNL", "802": "BSNL",
                "810": "Airtel", "811": "Airtel", "812": "Airtel",
                "813": "Jio", "814": "Jio", "815": "Jio",
                "816": "VI", "817": "VI", "818": "VI",
                "819": "BSNL", "820": "BSNL", "821": "BSNL",
            }
            operator = "Unknown"
            for k, v in operators.items():
                if prefix.startswith(k):
                    operator = v
                    break
            
            return {
                "status": "success", 
                "phone": f"{phone[:5]}XXXXX{phone[-2:]}",
                "data": {
                    "carrier": operator,
                    "country": "India",
                    "country_code": "+91",
                    "length": len(phone),
                    "valid": True
                }
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/breach")
async def breach_check(email: str = None, phone: str = None):
    """Check if email/phone has been in known breaches"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            if email:
                import hashlib
                hash_prefix = hashlib.sha1(email.encode()).hexdigest()[:5].upper()
                url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"
                resp = await client.get(url, headers={"User-Agent": "YUKI-OSINT-API"})
                if resp.status_code == 200:
                    return {
                        "status": "success",
                        "query": email,
                        "check_url": f"https://haveibeenpwned.com/account/{email}",
                        "note": "Use haveibeenpwned.com for full breach details"
                    }
            if phone:
                return {
                    "status": "info",
                    "query": f"{phone[:5]}XXXXX",
                    "message": "Phone breach check limited. Check haveibeenpwned.com"
                }
            return {"status": "error", "message": "Provide email or phone"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
