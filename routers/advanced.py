from fastapi import APIRouter, HTTPException
import httpx, json, hashlib, socket, re, uuid
from datetime import datetime

router = APIRouter()

import asyncio

# ─── DNS Subdomain Finder (with alive check) ───
COMMON_SUBDOMAINS = [
    "www", "mail", "api", "admin", "blog", "dev", "test", "static",
    "cdn", "app", "web", "staging", "vpn", "smtp", "pop", "imap",
    "ftp", "ssh", "git", "jenkins", "wiki", "docs", "status",
    "support", "help", "calendar", "mail2", "news", "portal",
    "remote", "server", "secure", "shop", "sso", "stage", "tracking",
    "beta", "demo", "forum", "community", "store", "partner",
    "media", "images", "img", "assets", "js", "css", "upload"
]

async def check_alive(domain: str, timeout: float = 3.0) -> dict:
    """Check if subdomain responds to HTTP/HTTPS"""
    result = {"alive": False, "http_status": None, "method": None, "response_time_ms": None, "real_service": False}
    
    import time
    start = time.time()
    
    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        for protocol in ["https", "http"]:
            try:
                resp = await client.get(f"{protocol}://{domain}", 
                    headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
                    follow_redirects=False)
                elapsed = round((time.time() - start) * 1000)
                result["alive"] = True
                result["http_status"] = resp.status_code
                result["method"] = protocol
                result["response_time_ms"] = elapsed
                result["server"] = resp.headers.get("server", resp.headers.get("via", ""))
                
                # Cloudflare 530 = proxied but NO backend service (fake alive)
                if resp.status_code == 530:
                    result["real_service"] = False
                    result["alive_label"] = "cloudflare_proxy"
                # 200-399 = real service
                elif 200 <= resp.status_code < 400:
                    result["real_service"] = True
                    result["alive_label"] = "alive"
                # 4xx/5xx but actual server responded (real but erroring)
                else:
                    result["real_service"] = True
                    result["alive_label"] = "error"
                break
            except:
                continue
    
    return result

@router.get("/subdomain")
async def subdomain_finder(domain: str, limit: int = 20, check_alive_endpoint: bool = True):
    """Find common subdomains with alive check. 
    Set 'check_alive_endpoint=false' to skip HTTP checking for faster results.
    """
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        return {"status": "error", "message": "Invalid domain"}
    
    # Limit max
    if limit > 50: limit = 50
    if limit < 1: limit = 10
    
    found = []
    checked = min(limit, len(COMMON_SUBDOMAINS))
    checked_list = COMMON_SUBDOMAINS[:checked]
    
    # Always check the bare/main domain first (@)
    try:
        ip_main = socket.gethostbyname(domain)
        entry = {"subdomain": "@", "domain": domain, "ip": ip_main, "alive": False, "http_status": None, "real_service": False}
        if check_alive_endpoint:
            try:
                alive_check = await check_alive(domain)
                entry["alive"] = alive_check["alive"]
                entry["http_status"] = alive_check["http_status"]
                entry["response_time_ms"] = alive_check["response_time_ms"]
                entry["real_service"] = alive_check["real_service"]
                entry["alive_label"] = alive_check.get("alive_label", "unknown")
            except:
                pass
        found.append(entry)
    except:
        pass
    
    for sub in checked_list:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            entry = {"subdomain": sub, "domain": full, "ip": ip, "alive": False, "http_status": None, "real_service": False}
            
            if check_alive_endpoint:
                try:
                    alive_check = await check_alive(full)
                    entry["alive"] = alive_check["alive"]
                    entry["http_status"] = alive_check["http_status"]
                    entry["response_time_ms"] = alive_check["response_time_ms"]
                    entry["real_service"] = alive_check["real_service"]
                    entry["alive_label"] = alive_check.get("alive_label", "unknown")
                except:
                    pass
            
            found.append(entry)
        except:
            pass
    
    # Summary with real_service detection (530 = cloudflare proxy, not real)
    alive_real = sum(1 for s in found if s.get("real_service"))
    cloudflare_proxy = sum(1 for s in found if s.get("alive_label") == "cloudflare_proxy")
    dead_count = sum(1 for s in found if not s.get("alive"))
    
    return {
        "status": "success",
        "domain": domain,
        "checked": checked + 1,  # +1 for the main domain (@)
        "found": len(found),
        "alive_real_services": alive_real,
        "cloudflare_proxied_only": cloudflare_proxy,
        "dead": dead_count,
        "subdomains": found
    }

# ─── SSL Certificate Check ───
@router.get("/ssl-check")
async def ssl_check(domain: str):
    """Check SSL certificate expiry date"""
    domain = domain.strip().lower()
    if not domain:
        return {"status": "error", "message": "Domain required"}
    
    try:
        import ssl
        import OpenSSL
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
        conn = OpenSSL.SSL.Connection(ctx, socket.socket())
        conn.connect((domain, 443))
        conn.setblocking(1)
        conn.do_handshake()
        cert = conn.get_peer_certificate()
        conn.close()
        
        not_before = datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
        not_after = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_left = (not_after - datetime.now()).days
        
        return {
            "status": "success",
            "domain": domain,
            "issued": not_before.isoformat(),
            "expires": not_after.isoformat(),
            "days_left": days_left,
            "expired": days_left < 0,
            "issuer": dict(cert.get_issuer().get_components()) if cert.get_issuer() else {},
            "subject": dict(cert.get_subject().get_components()) if cert.get_subject() else {}
        }
    except ImportError:
        # Fallback: use openssl binary
        try:
            import subprocess
            result = subprocess.run(
                ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain],
                input=b"Q\n", capture_output=True, timeout=15
            )
            output = result.stdout.decode()
            import re
            dates = re.findall(r'not(?:Before|After)=(.*?)(?:\n|$)', output)
            return {
                "status": "success",
                "domain": domain,
                "raw": "SSL info extracted",
                "note": "Install pyOpenSSL for detailed cert info"
            }
        except:
            return {"status": "error", "message": "SSL check failed"}
    except Exception as e:
        return {"status": "error", "message": f"SSL Error: {str(e)}"}

# ─── Hash Generator ───
@router.get("/hash")
async def hash_tool(text: str = None, hash_type: str = "md5", lookup: str = None):
    """Generate or lookup hashes"""
    results = {}
    
    if lookup:
        # Simple hash lookup (mock - real lookup needs external API)
        return {
            "status": "info",
            "hash": lookup,
            "note": "Hash lookup requires external database. Try https://hashes.com or https://crackstation.net",
            "databases": ["https://hashes.com", "https://crackstation.net", "https://hashkiller.io"]
        }
    
    if not text:
        return {"status": "error", "message": "Provide 'text' parameter to hash"}
    
    text_bytes = text.encode()
    
    # Always generate all common hashes
    results["md5"] = hashlib.md5(text_bytes).hexdigest()
    results["sha1"] = hashlib.sha1(text_bytes).hexdigest()
    results["sha256"] = hashlib.sha256(text_bytes).hexdigest()
    results["sha512"] = hashlib.sha512(text_bytes).hexdigest()
    
    try:
        results["sha3_256"] = hashlib.sha3_256(text_bytes).hexdigest()
        results["sha3_512"] = hashlib.sha3_512(text_bytes).hexdigest()
    except:
        pass
    
    return {
        "status": "success",
        "text": text,
        "length": len(text),
        "hashes": results
    }

# ─── Wayback Machine ───
@router.get("/wayback")
async def wayback_machine(domain: str, limit: int = 10):
    """Get historical URL snapshots from Wayback Machine"""
    domain = domain.strip().lower()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Get CDX data
            url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit={limit}&fl=timestamp,original"
            resp = await client.get(url, headers={"User-Agent": "YUKI-OSINT-API"})
            
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    snapshots = []
                    for entry in data[1:]:
                        ts, original = entry[0], entry[1]
                        year = ts[:4]
                        wayback_url = f"https://web.archive.org/web/{ts}/{original}"
                        snapshots.append({
                            "timestamp": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}",
                            "year": year,
                            "url": original,
                            "wayback_url": wayback_url
                        })
                    
                    # Group by year
                    by_year = {}
                    for s in snapshots:
                        y = s["year"]
                        if y not in by_year:
                            by_year[y] = []
                        by_year[y].append(s)
                    
                    return {
                        "status": "success",
                        "domain": domain,
                        "total_snapshots": len(data) - 1,
                        "shown": len(snapshots),
                        "by_year": {k: len(v) for k, v in sorted(by_year.items(), reverse=True)},
                        "recent": snapshots[:limit]
                    }
                return {"status": "not_found", "message": "No snapshots found", "domain": domain}
            return {"status": "error", "message": "Wayback API error"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ─── GitHub User Info ───
@router.get("/gh-user")
async def github_user(username: str):
    """Get public GitHub user info"""
    username = username.strip()
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = f"https://api.github.com/users/{username}"
            resp = await client.get(url, headers={"User-Agent": "YUKI-OSINT-API", "Accept": "application/vnd.github.v3+json"})
            
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "status": "success",
                    "data": {
                        "login": data.get("login"),
                        "name": data.get("name"),
                        "bio": data.get("bio"),
                        "company": data.get("company"),
                        "location": data.get("location"),
                        "email": data.get("email"),
                        "blog": data.get("blog"),
                        "twitter": data.get("twitter_username"),
                        "public_repos": data.get("public_repos"),
                        "followers": data.get("followers"),
                        "following": data.get("following"),
                        "created_at": data.get("created_at"),
                        "avatar": data.get("avatar_url"),
                        "profile": data.get("html_url")
                    }
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "message": f"User '{username}' not found"}
            return {"status": "error", "message": "GitHub API error"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ─── HTTP Headers ───
@router.get("/http-headers")
async def http_headers(url: str):
    """Get HTTP response headers from a URL"""
    if not url.startswith("http"):
        url = "https://" + url
    
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; YUKI-OSINT/1.0)"})
            
            headers = dict(resp.headers)
            # Clean up
            clean = {}
            important = {}
            security = {}
            
            for k, v in headers.items():
                clean[k] = v
                if k.lower() in ("server", "x-powered-by", "x-aspnet-version"):
                    important[k] = v
                if k.lower() in ("strict-transport-security", "x-frame-options", 
                                "x-content-type-options", "x-xss-protection",
                                "content-security-policy", "referrer-policy"):
                    security[k] = v
            
            return {
                "status": "success",
                "url": url,
                "status_code": resp.status_code,
                "headers": clean,
                "security_headers": security,
                "server_info": important
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ─── QR Code Generator ───
@router.get("/qr")
async def qr_generator(text: str, size: int = 200):
    """Generate QR code (returns URL to QR image)"""
    if not text:
        return {"status": "error", "message": "Text required"}
    
    from urllib.parse import quote
    encoded = quote(text)
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size={size}x{size}&data={encoded}"
    
    return {
        "status": "success",
        "text": text,
        "qr_url": qr_url,
        "note": "Use the QR URL directly in <img> tags"
    }

# ─── Text Translation ───
@router.get("/translate")
async def translate(text: str, to: str = "en", from_lang: str = "auto"):
    """Translate text using free API"""
    if not text:
        return {"status": "error", "message": "Text required"}
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # LibreTranslate or Lingva
            url = f"https://lingva.ml/api/v1/{from_lang}/{to}/{text}"
            resp = await client.get(url, headers={"User-Agent": "YUKI-OSINT-API"})
            
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "status": "success",
                    "original": text,
                    "translated": data.get("translation", ""),
                    "from": data.get("info", {}).get("detectedSource", from_lang) if not from_lang == "auto" else from_lang,
                    "to": to
                }
            
            # Fallback
            return {
                "status": "success",
                "original": text,
                "translated": text,
                "note": "Translation API unavailable. Try Google Translate directly",
                "google_url": f"https://translate.google.com/?sl={from_lang}&tl={to}&text={text}&op=translate"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ─── Currency Converter ───
@router.get("/currency")
async def currency_converter(amount: float = 1, from_c: str = "USD", to_c: str = "INR"):
    """Convert currency using free exchange rates"""
    from_c = from_c.upper()
    to_c = to_c.upper()
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = f"https://open.er-api.com/v6/latest/{from_c}"
            resp = await client.get(url)
            
            if resp.status_code == 200:
                data = resp.json()
                rates = data.get("rates", {})
                
                if to_c in rates:
                    rate = rates[to_c]
                    converted = round(amount * rate, 2)
                    
                    # Common currency names
                    names = {
                        "USD": "US Dollar", "EUR": "Euro", "GBP": "British Pound",
                        "INR": "Indian Rupee", "JPY": "Japanese Yen", "CNY": "Chinese Yuan",
                        "AUD": "Australian Dollar", "CAD": "Canadian Dollar", "CHF": "Swiss Franc",
                        "SGD": "Singapore Dollar", "AED": "Dirham", "SAR": "Saudi Riyal"
                    }
                    
                    return {
                        "status": "success",
                        "from": {"code": from_c, "name": names.get(from_c, from_c)},
                        "to": {"code": to_c, "name": names.get(to_c, to_c)},
                        "amount": amount,
                        "rate": rate,
                        "result": converted,
                        "updated": data.get("time_last_update_utc", "N/A")
                    }
                return {"status": "error", "message": f"Currency '{to_c}' not found"}
            return {"status": "error", "message": "API error"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ─── User Agent Parser ───
@router.get("/useragent")
async def useragent_parser(ua: str = None):
    """Parse User-Agent string or show current one"""
    if not ua:
        return {
            "status": "info",
            "message": "Provide a 'ua' parameter with User-Agent string",
            "example": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    
    result = {"raw": ua}
    
    # Browser detection
    if "Chrome" in ua and "Chromium" not in ua:
        result["browser"] = "Chrome"
    elif "Firefox" in ua:
        result["browser"] = "Firefox"
    elif "Safari" in ua and "Chrome" not in ua:
        result["browser"] = "Safari"
    elif "Edge" in ua or "Edg" in ua:
        result["browser"] = "Edge"
    elif "Opera" in ua or "OPR" in ua:
        result["browser"] = "Opera"
    else:
        result["browser"] = "Unknown"
    
    # OS detection
    if "Windows NT" in ua:
        ver = re.search(r"Windows NT (\d+\.\d+)", ua)
        versions = {"10.0": "Windows 10/11", "6.3": "Windows 8.1", "6.2": "Windows 8", "6.1": "Windows 7"}
        result["os"] = versions.get(ver.group(1) if ver else "", "Windows") if ver else "Windows"
    elif "Android" in ua:
        result["os"] = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        result["os"] = "iOS"
    elif "Linux" in ua:
        result["os"] = "Linux"
    elif "Mac OS X" in ua:
        result["os"] = "macOS"
    else:
        result["os"] = "Unknown"
    
    # Device detection
    if "Mobile" in ua:
        result["device"] = "Mobile"
    elif "Tablet" in ua or "iPad" in ua:
        result["device"] = "Tablet"
    else:
        result["device"] = "Desktop"
    
    return {"status": "success", "data": result}

# ─── Base64 Encode/Decode ───
import base64

@router.get("/base64")
async def base64_tool(text: str = None, mode: str = "encode", encoded: str = None):
    """Base64 encode or decode"""
    import base64
    
    if encoded:
        # Decode mode
        try:
            decoded = base64.b64decode(encoded).decode()
            return {
                "status": "success",
                "mode": "decode",
                "input": encoded[:100] + ("..." if len(encoded) > 100 else ""),
                "output": decoded
            }
        except:
            return {"status": "error", "message": "Invalid base64 input"}
    
    if not text:
        return {"status": "error", "message": "Provide 'text' to encode or 'encoded' to decode"}
    
    if mode == "encode":
        encoded_str = base64.b64encode(text.encode()).decode()
        return {
            "status": "success",
            "mode": "encode",
            "input": text[:100] + ("..." if len(text) > 100 else ""),
            "output": encoded_str,
            "url_safe": base64.urlsafe_b64encode(text.encode()).decode()
        }
    
    # Decode mode
    try:
        decoded = base64.b64decode(text).decode()
        return {"status": "success", "mode": "decode", "input": text[:100], "output": decoded}
    except:
        return {"status": "error", "message": "Invalid base64 input"}

# ─── Port Scanner ───
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

@router.get("/port-check")
async def port_scanner(host: str, ports: str = None):
    """Scan common ports on a host"""
    host = host.strip()
    if not host:
        return {"status": "error", "message": "Host required"}
    
    port_list = COMMON_PORTS
    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        except:
            pass
    
    # Limit scan to 10 ports max to avoid timeouts
    port_list = port_list[:10]
    open_ports = []
    
    for port in port_list:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((host, port))
            if result == 0:
                service = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
                    587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
                    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
                    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
                }
                open_ports.append({
                    "port": port,
                    "state": "open",
                    "service": service.get(port, "unknown")
                })
            s.close()
        except:
            pass
    
    return {
        "status": "success",
        "host": host,
        "scanned": len(port_list),
        "open_count": len(open_ports),
        "open_ports": open_ports
    }

# ─── Domain Age ───
@router.get("/domain-age")
async def domain_age(domain: str):
    """Get domain registration/creation date"""
    domain = domain.strip().lower()
    try:
        import whois
        w = whois.whois(domain)
        
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        
        if creation:
            age_days = (datetime.now() - creation).days
            age_years = age_days / 365.25
            
            return {
                "status": "success",
                "domain": domain,
                "creation_date": str(creation),
                "expiration_date": str(expiry) if expiry else "N/A",
                "days_old": age_days,
                "years_old": round(age_years, 1),
                "registrar": str(w.registrar or "N/A"),
                "name_servers": [str(ns) for ns in (w.name_servers or [])[:5]]
            }
        return {"status": "info", "domain": domain, "message": "Could not determine domain age"}
    except Exception as e:
        return {"status": "error", "message": f"WHOIS lookup failed: {str(e)}"}

# ─── Password Strength Checker ───
@router.get("/password-strength")
async def password_strength(password: str):
    """Check password strength"""
    if not password:
        return {"status": "error", "message": "Password required"}
    
    score = 0
    feedback = []
    
    # Length check
    if len(password) < 8:
        feedback.append("Too short (min 8 chars)")
    elif len(password) >= 12:
        score += 25
        feedback.append("✅ Good length")
    else:
        score += 15
        feedback.append("🟡 Moderate length")
    
    # Complexity checks
    if re.search(r'[a-z]', password):
        score += 10
    else:
        feedback.append("❌ Missing lowercase")
    
    if re.search(r'[A-Z]', password):
        score += 10
    else:
        feedback.append("❌ Missing uppercase")
    
    if re.search(r'\d', password):
        score += 10
    else:
        feedback.append("❌ Missing numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-=\[\]`~]', password):
        score += 15
    else:
        feedback.append("❌ Missing special chars")
    
    # Check common patterns
    common = ["password", "123456", "qwerty", "admin", "letmein", "welcome"]
    if password.lower() in common:
        score = 0
        feedback = ["🚫 Extremely common password!"]
    
    # Entropy check (simple)
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-=\[\]`~]', password): charset += 32
    entropy = len(password) * (charset.bit_length() - 1) if charset > 0 else 0
    
    # Rating
    if score >= 60:
        strength = "Very Strong 💪"
        level = 5
    elif score >= 45:
        strength = "Strong ✅"
        level = 4
    elif score >= 30:
        strength = "Medium 🟡"
        level = 3
    elif score >= 15:
        strength = "Weak ⚠️"
        level = 2
    else:
        strength = "Very Weak ❌"
        level = 1
    
    return {
        "status": "success",
        "password": password[:1] + "*" * (len(password) - 2) + password[-1:] if len(password) > 2 else "***",
        "length": len(password),
        "strength": strength,
        "score": min(score, 100),
        "level": f"{'🟩' * level}{'⬜' * (5-level)}",
        "entropy_bits": round(entropy, 1),
        "feedback": feedback
    }

# ─── IP Range Calculator (CIDR) ───
@router.get("/ip-range")
async def ip_range_calculator(cidr: str):
    """Calculate IP range details from CIDR notation"""
    import ipaddress
    
    cidr = cidr.strip()
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        return {
            "status": "success",
            "cidr": cidr,
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "wildcard_mask": str(network.hostmask),
            "num_hosts": network.num_addresses,
            "ip_version": f"IPv{network.version}",
            "is_private": network.is_private,
            "first_ip": str(list(network.hosts())[0]) if network.num_addresses > 2 else str(network.network_address),
            "last_ip": str(list(network.hosts())[-1]) if network.num_addresses > 2 else str(network.broadcast_address)
        }
    except ValueError as e:
        return {"status": "error", "message": f"Invalid CIDR: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ─── UUID Generator ───
@router.get("/uuid")
async def uuid_generator(count: int = 1):
    """Generate UUID(s)"""
    if count > 100: count = 100
    if count < 1: count = 1
    uuids = []
    for _ in range(count):
        uuids.append({"uuid4": str(uuid.uuid4()), "uuid4_hex": uuid.uuid4().hex})
    return {"status": "success", "count": count, "uuids": uuids}

# ─── Website Hosting Detector ───
PLATFORM_SIGNATURES = {
    "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-request-id"],
    "railway": ["up.railway.app", "railway.app"],
    "vercel": ["vercel.app", "x-vercel-id", "vercel"],
    "netlify": ["netlify.com", "netlify.app", "x-nf-request-id"],
    "heroku": ["herokuapp.com", "heroku-router"],
    "aws": ["cloudfront.net", "aws", "amazonaws.com", "x-amz-", "AWSALB"],
    "google_cloud": ["google", "gcp", "appspot.com", "googleapis.com"],
    "azure": ["azure.com", "azurewebsites.net", "x-azure-"],
    "digitalocean": ["digitalocean.com", "do-"],
    "github_pages": ["github.com", "github.io"],
    "nginx": ["nginx", "nginx-reuseport"],
    "apache": ["apache", "Apache"],
    "cloudflare_tunnel": ["cfargotunnel.com"],
    "ngrok": ["ngrok.io", "ngrok-free.app", "ngrok-agent"],
    "fly_io": ["fly.io", "fly.dev"],
    "render": ["render.com", "onrender.com"],
    "python_anywhere": ["pythonanywhere.com"],
}

@router.get("/detect")
async def detect_hosting(url: str = None, domain: str = None):
    """Detect website hosting platform. Provide 'url' (full URL) or 'domain'."""
    target = url or domain
    if not target:
        return {"status": "error", "message": "Provide 'url' or 'domain' parameter"}
    
    if not target.startswith("http"):
        target = "https://" + target
    
    try:
        import ssl, socket
        from urllib.parse import urlparse
        
        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        
        result = {
            "target": target,
            "domain": hostname,
            "ip": None,
            "asn_org": None,
            "cname": [],
            "platform": None,
            "confidence": 0,
            "evidence": [],
            "headers": {},
            "detected": []
        }
        
        async with httpx.AsyncClient(timeout=15, follow_redirects=False, verify=False) as client:
            try:
                resp = await client.get(target, headers={"User-Agent": "Mozilla/5.0 (compatible; YUKI-OSINT/1.0)"})
                result["status_code"] = resp.status_code
                result["headers"] = dict(resp.headers)
                
                # Check headers for platform signatures
                h_text = str(dict(resp.headers)).lower()
                for platform, sigs in PLATFORM_SIGNATURES.items():
                    matches = []
                    for sig in sigs:
                        if sig.lower() in h_text or sig.lower() in hostname:
                            matches.append(sig)
                    if matches:
                        result["detected"].append({"platform": platform, "signatures": matches})
                
            except Exception as e:
                result["header_error"] = str(e)
        
        # DNS CNAME check
        try:
            import dns.resolver
            for rtype in ['CNAME', 'A']:
                try:
                    answers = dns.resolver.resolve(hostname, rtype)
                    for ans in answers:
                        val = str(ans).lower()
                        result["cname"].append(val)
                        for platform, sigs in PLATFORM_SIGNATURES.items():
                            for sig in sigs:
                                if sig in val:
                                    result["detected"].append({"platform": platform, "signatures": [sig + " (DNS)"]})
                except:
                    pass
        except:
            pass
        
        # IP based detection
        try:
            import socket
            ip = socket.gethostbyname(hostname)
            result["ip"] = ip
            
            # ASN lookup
            async with httpx.AsyncClient(timeout=8) as client:
                ip_resp = await client.get(f"https://ipapi.co/{ip}/json/")
                if ip_resp.status_code == 200:
                    ip_data = ip_resp.json()
                    result["asn_org"] = ip_data.get("org")
                    result["ip_city"] = ip_data.get("city")
                    result["ip_country"] = ip_data.get("country_name")
                    
                    # Infer platform from ASN
                    org = (ip_data.get("org") or "").lower()
                    if "cloudflare" in org:
                        if not any(d["platform"] == "cloudflare" for d in result["detected"]):
                            result["detected"].append({"platform": "cloudflare", "signatures": [f"ASN: {org}"]})
                    if "google" in org or "gcp" in org:
                        if not any(d["platform"] in ("google_cloud", "railway") for d in result["detected"]):
                            result["detected"].append({"platform": "google_cloud", "signatures": [f"ASN: {org}"]})
                    if "amazon" in org or "aws" in org:
                        if not any(d["platform"] == "aws" for d in result["detected"]):
                            result["detected"].append({"platform": "aws", "signatures": [f"ASN: {org}"]})
                    if "digitalocean" in org:
                        if not any(d["platform"] == "digitalocean" for d in result["detected"]):
                            result["detected"].append({"platform": "digitalocean", "signatures": [f"ASN: {org}"]})
        except:
            pass
        
        # Determine best platform match
        if result["detected"]:
            # Remove duplicates
            seen = set()
            unique = []
            for d in result["detected"]:
                if d["platform"] not in seen:
                    seen.add(d["platform"])
                    unique.append(d)
            result["detected"] = unique
            
            # Pick highest confidence
            platform_priority = [
                "railway", "vercel", "cloudflare_tunnel", "cloudflare",
                "github_pages", "netlify", "heroku", "aws", "google_cloud",
                "azure", "digitalocean", "ngrok", "fly_io", "render"
            ]
            for p in platform_priority:
                if any(d["platform"] == p for d in unique):
                    result["platform"] = p
                    break
            if not result["platform"]:
                result["platform"] = unique[0]["platform"]
            
            result["confidence"] = len(result["detected"])
        
        return {"status": "success", "data": result}
    
    except Exception as e:
        return {"status": "error", "message": str(e)}
