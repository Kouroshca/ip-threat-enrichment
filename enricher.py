import requests
import config

def check_virus_total(ip):
    """Queries VirusTotal v3. Always returns same shape regardless of outcome."""
    if not config.VT_API_KEY:
        return {"status": "auth_error", "vt_malicious": 0, "vt_total": 0}

    headers = {"x-apikey": config.VT_API_KEY}
    try:
        response = requests.get(f"{config.VT_URL}{ip}", headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {
                "status": "ok",
                "vt_malicious": stats['malicious'],
                "vt_total": sum(stats.values())
            }
        elif response.status_code == 404:
            return {"status": "not_found", "vt_malicious": 0, "vt_total": 0}
        elif response.status_code == 429:
            return {"status": "rate_limited", "vt_malicious": 0, "vt_total": 0}
        elif response.status_code == 401:
            return {"status": "auth_error", "vt_malicious": 0, "vt_total": 0}
        else:
            return {"status": "error", "vt_malicious": 0, "vt_total": 0}
    except Exception as e:
        print(f"[-] VT request failed for {ip}: {e}")
        return {"status": "error", "vt_malicious": 0, "vt_total": 0}


def check_abuse_ipdb(ip):
    """Queries AbuseIPDB v2. Always returns same shape regardless of outcome."""
    if not config.ABUSEIPDB_API_KEY:
        return {"status": "auth_error", "abuse_score": 0, "isp": "Unknown"}

    headers = {'Accept': 'application/json', 'Key': config.ABUSEIPDB_API_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': 'true'}
    try:
        response = requests.get(config.ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            d = response.json()['data']
            return {
                "status": "ok",
                "abuse_score": d['abuseConfidenceScore'],
                "isp": d.get('isp', 'Unknown'),
                "total_reports": d.get('totalReports', 0),
                "last_reported": d.get('lastReportedAt', 'Never'),
                "country": d.get('countryCode', 'Unknown')
            }
        elif response.status_code == 429:
            return {"status": "rate_limited", "abuse_score": 0, "isp": "Unknown"}
        elif response.status_code == 401:
            return {"status": "auth_error", "abuse_score": 0, "isp": "Unknown"}
        else:
            return {"status": "error", "abuse_score": 0, "isp": "Unknown"}
    except Exception as e:
        print(f"[-] AbuseIPDB request failed for {ip}: {e}")
        return {"status": "error", "abuse_score": 0, "isp": "Unknown"}