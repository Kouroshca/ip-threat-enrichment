import config

def evaluate_verdict(vt_result, abuse_result):
    vt_status = vt_result.get("status")
    abuse_status = abuse_result.get("status")

# for Uknown 
    if vt_status != "ok" or abuse_status != "ok":
        reasons = []
        if vt_status != "ok":
            reasons.append(f"VT: {vt_status}")
        
        if abuse_status != "ok":
            reasons.append(f"AbuseIPDB: {abuse_status}")
        return (
            "Unknown",
            "Re-query manually. Do not assume clean.",
            f"Lookup failed ({', '.join(reasons)})"
        )
    
    vt_malicious = vt_result.get("vt_malicious", 0)
    vt_total = vt_result.get("vt_total", 0)
    abuse_score = abuse_result.get("abuse_score", 0)

#for malicious 
    if (vt_malicious >= config.VT_MALICIOUS_THRESHOLD or abuse_score>=config.ABUSE_MALICIOUS_THRESHOLD):
        return (
            "Malicious",
            "Isolate host immediately. Block IP at firewall. Escalate.",
            f"VT {vt_malicious}/{vt_total} engines | AbuseIPDB {abuse_score}%"
        )

#for suspicious: 
    if vt_malicious > 0 or abuse_score >= config.ABUSE_SUSPICIOUS_THRESHOLD:
        return ( "Suspicious",
            "Monitor closely. Review active connections from this IP.",
            f"VT {vt_malicious}/{vt_total} engines | AbuseIPDB {abuse_score}%"
        )
#clean:
    return (
    "Clean",
    "No action required. Log for baseline.",
    f"VT 0/{vt_total} engines | AbuseIPDB {abuse_score}%"
)

    