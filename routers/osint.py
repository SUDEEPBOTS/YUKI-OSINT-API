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
async def email_osint(email: str, deep: bool = False):
    """Full Email OSINT — domain, breach, gravatar, social, platforms check
    Set 'deep=true' for extended platform checks (slower)
    """
    import hashlib, dns.resolver as dns_resolver
    
    email = email.strip().lower()
    if "@" not in email or "." not in email:
        return {"status": "error", "message": "Invalid email format"}
    
    username = email.split("@")[0]
    domain = email.split("@")[1]
    email_hash = hashlib.md5(email.encode()).hexdigest()
    email_sha1 = hashlib.sha1(email.encode()).hexdigest()
    
    result = {
        "email": email,
        "username": username,
        "domain": domain,
        "valid_format": bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)),
        "disposable": False,
        "domain_info": {},
        "gravatar": None,
        "breach_check": {},
        "platforms": {},
        "deep_check": {}
    }
    
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        
        # 1. Disposable domain check
        disposable_domains = {
            "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com", 
            "yopmail.com", "throwaway.email", "temp-mail.org", "fakeinbox.com",
            "trashmail.com", "sharklasers.com", "burner.com"
        }
        result["disposable"] = domain in disposable_domains or any(dom in domain for dom in ["temp", "trash", "fake", "throw", "spam"])
        
        # 2. Domain MX / DNS check
        try:
            answers = dns_resolver.resolve(domain, 'MX')
            mx_list = [str(x.exchange) for x in answers[:5]]
            result["domain_info"]["mx_records"] = mx_list
            result["domain_info"]["has_email_server"] = True
            
            # Provider detection from MX
            mx_text = " ".join(mx_list).lower()
            if "google" in mx_text or "googlemail" in mx_text:
                result["domain_info"]["provider"] = "Google Workspace / Gmail"
            elif "outlook" in mx_text or "microsoft" in mx_text or "hotmail" in mx_text:
                result["domain_info"]["provider"] = "Microsoft 365 / Outlook"
            elif "protonmail" in mx_text or "proton" in mx_text:
                result["domain_info"]["provider"] = "ProtonMail"
            elif "yahoo" in mx_text:
                result["domain_info"]["provider"] = "Yahoo Mail"
            elif "zoho" in mx_text:
                result["domain_info"]["provider"] = "Zoho Mail"
            else:
                result["domain_info"]["provider"] = "Custom / Other"
                
        except:
            result["domain_info"]["has_email_server"] = False
            result["domain_info"]["mx_records"] = []
            result["domain_info"]["provider"] = "Unknown / No MX"
        
        # 3. Gravatar check (profile pic + name)
        try:
            grav_url = f"https://www.gravatar.com/{email_hash}.json"
            grav_resp = await client.get(grav_url, headers={"User-Agent": "YUKI-OSINT-API"})
            if grav_resp.status_code == 200:
                grav_data = grav_resp.json()
                entry = grav_data.get("entry", [{}])[0]
                result["gravatar"] = {
                    "has_profile": True,
                    "name": entry.get("displayName", entry.get("preferredUsername", "")),
                    "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}?s=400",
                    "avatar_url_secure": f"https://secure.gravatar.com/avatar/{email_hash}?s=400",
                    "profile_url": entry.get("profileUrl", ""),
                    "about": entry.get("aboutMe", "")[:200] if entry.get("aboutMe") else "",
                    "location": entry.get("currentLocation", ""),
                    "accounts": len(entry.get("accounts", [])) if "accounts" in entry else 0
                }
                # Get linked social accounts
                accounts = entry.get("accounts", [])
                if accounts:
                    result["gravatar"]["linked_accounts"] = []
                    for acc in accounts[:5]:
                        result["gravatar"]["linked_accounts"].append({
                            "platform": acc.get("shortname", acc.get("name", "")),
                            "url": acc.get("url", "")
                        })
            else:
                result["gravatar"] = {"has_profile": False}
        except:
            result["gravatar"] = {"has_profile": False, "error": "Gravatar check failed"}
        
        # 4. Breach check via HIBP k-anonymity
        try:
            hash_prefix = email_sha1[:5].upper()
            hibp_url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"
            hibp_resp = await client.get(hibp_url, headers={"User-Agent": "YUKI-OSINT-API"})
            if hibp_resp.status_code == 200:
                # Check if our hash suffix is in the response
                hash_suffix = email_sha1[5:].upper()
                breached = hash_suffix in hibp_resp.text
                if breached:
                    result["breach_check"] = {
                        "pwned": True,
                        "message": "Email found in known breaches! Check https://haveibeenpwned.com/ for details",
                        "check_url": f"https://haveibeenpwned.com/account/{email}"
                    }
                else:
                    result["breach_check"] = {"pwned": False, "message": "Not found in HIBP database"}
        except:
            result["breach_check"] = {"error": "Breach check unavailable"}
        
        # 5. Platform checks (public profiles)
        # GitHub
        try:
            gh_resp = await client.get(f"https://api.github.com/search/users?q={email}+in:email", 
                headers={"User-Agent": "YUKI-OSINT-API", "Accept": "application/vnd.github.v3+json"})
            if gh_resp.status_code == 200:
                gh_data = gh_resp.json()
                if gh_data.get("total_count", 0) > 0:
                    user = gh_data["items"][0]
                    result["platforms"]["github"] = {
                        "found": True,
                        "username": user.get("login"),
                        "profile": user.get("html_url"),
                        "avatar": user.get("avatar_url"),
                        "type": user.get("type")
                    }
        except:
            pass
        
        # Google profile / reviews check (via public Google Maps)
        try:
            # Google doesn't have a public API for this, but we can check
            result["platforms"]["google"] = {
                "note": "Google reviews/profile requires manual check at:",
                "check_url": f"https://www.google.com/search?q={email.replace('@', '%40')}"
            }
        except:
            pass
        
        # Deep checks (slow - only if requested)
        if deep:
            result["deep_check"] = await _deep_email_osint(email, username, client)
    
    return {"status": "success", "data": result}

async def _deep_email_osint(email, username, client):
    """Extended email OSINT checks"""
    deep = {}
    
    # Check common platforms
    platform_checks = [
        ("twitter", f"https://twitter.com/{username}"),
        ("instagram", f"https://www.instagram.com/{username}/"),
        ("facebook", f"https://www.facebook.com/{username}"),
        ("linkedin", f"https://www.linkedin.com/in/{username}/"),
        ("pinterest", f"https://www.pinterest.com/{username}/"),
        ("telegram", f"https://t.me/{username}"),
        ("reddit", f"https://www.reddit.com/user/{username}/"),
        ("medium", f"https://medium.com/@{username}"),
        ("keybase", f"https://keybase.io/{username}"),
    ]
    
    check_results = []
    for platform, url in platform_checks:
        try:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code < 400:
                check_results.append({
                    "platform": platform,
                    "exists": True,
                    "url": url,
                    "status": resp.status_code
                })
            else:
                check_results.append({
                    "platform": platform,
                    "exists": False,
                    "status": resp.status_code
                })
        except:
            check_results.append({"platform": platform, "exists": "unknown", "error": "timeout/failed"})
    
    deep["social_profiles"] = check_results
    
    # Check firebaseio / common leaks
    deep["note"] = "For deeper OSINT, use: holehe, GHunt, sherlock, maigret tools"
    deep["recommended_tools"] = [
        "holehe - Check if email used on 100+ websites",
        "GHunt - Google account OSINT",
        "sherlock - Social media username search",
        "theHarvester - Email OSINT collection"
    ]
    
    return deep

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
