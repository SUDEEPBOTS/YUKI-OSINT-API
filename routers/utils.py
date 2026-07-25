from fastapi import APIRouter
import httpx, json, socket, whois, asyncio

router = APIRouter()

@router.get("/dns")
async def dns_lookup(domain: str):
    """Get DNS records for a domain"""
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        return {"status": "error", "message": "Invalid domain"}
    
    results = {"domain": domain, "records": {}}
    
    try:
        # A record
        ip = socket.gethostbyname(domain)
        results["records"]["A"] = ip
    except:
        results["records"]["A"] = None
    
    try:
        # AAAA
        results["records"]["AAAA"] = socket.getaddrinfo(domain, 0, socket.AF_INET6)[0][4][0]
    except:
        results["records"]["AAAA"] = None
    
    try:
        # MX records
        import dns.resolver
        mx_records = []
        for mx in dns.resolver.resolve(domain, 'MX'):
            mx_records.append({"priority": mx.preference, "server": str(mx.exchange)})
        results["records"]["MX"] = mx_records
    except:
        results["records"]["MX"] = None
    
    try:
        # NS records
        ns_records = []
        for ns in dns.resolver.resolve(domain, 'NS'):
            ns_records.append(str(ns.target))
        results["records"]["NS"] = ns_records
    except:
        results["records"]["NS"] = None
    
    results["status"] = "success"
    return results

@router.get("/whois")
async def whois_lookup(domain: str):
    """Get WHOIS information for a domain"""
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        return {"status": "error", "message": "Invalid domain"}
    
    try:
        w = whois.whois(domain)
        data = {
            "domain": domain,
            "registrar": str(w.registrar or "N/A"),
            "creation_date": str(w.creation_date or "N/A"),
            "expiration_date": str(w.expiration_date or "N/A"),
            "name_servers": [str(ns) for ns in (w.name_servers or [])[:5]],
            "status": w.status,
            "org": str(w.org or "N/A")
        }
        return {"status": "success", "data": data}
    except Exception as e:
        return {"status": "error", "message": f"WHOIS lookup failed: {str(e)}"}

@router.get("/url-shorten")
async def url_shorten(url: str):
    """Shorten a long URL"""
    if not url.startswith("http"):
        return {"status": "error", "message": "URL must start with http:// or https://"}
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Using is.gd
            resp = await client.get(f"https://is.gd/create.php?format=json&url={url}")
            if resp.status_code == 200:
                data = resp.json()
                if "shorturl" in data:
                    return {"status": "success", "original": url, "short": data["shorturl"]}
            return {"status": "error", "message": "Could not shorten URL"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
