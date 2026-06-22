import sys
import time
import ipaddress
from parser_1 import parse_input
from enricher import check_virus_total, check_abuse_ipdb
from verdict import evaluate_verdict
from cache import init_cache, get_cached, save_to_cache
from reporter import generate_report

PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
)

def is_private(ip):
    #Returns True if IP is private, loopback, or reserved
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return True  # if it's not a valid IP, skip it

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <ip | file.csv | file.txt | file.log>")
        sys.exit(1)

    source = sys.argv[1]

    # parsing the input
    print("[*] Parsing input...")
    try:
        all_ips = parse_input(source)
    except (FileNotFoundError, ValueError) as e:
        print(f"[-] {e}")
        sys.exit(1)

    
    public_ips = [ip for ip in all_ips if not is_private(ip)]
    skipped = len(all_ips) - len(public_ips)

    print(f"[*] Loaded {len(all_ips)} unique IP(s) → "
          f"{len(public_ips)} public to enrich "
          f"(skipped {skipped} private/reserved)")

    if not public_ips:
        print("[-] No public IPs to enrich. Exiting.")
        sys.exit(0)

    
    init_cache()

    # enrichement
    results = []
    for idx, ip in enumerate(public_ips):
        print(f"\n[*] [{idx+1}/{len(public_ips)}] Enriching {ip}...")

        # Cache check
        cached = get_cached(ip)
        if cached:
            vt_result, abuse_result = cached
            print(f"[~] Cache hit for {ip} — skipping API calls")
        else:
            vt_result = check_virus_total(ip)
            abuse_result = check_abuse_ipdb(ip)
            save_to_cache(ip, vt_result, abuse_result)

            # Rate limit sleep — only on real API calls, never on cache hits
            if idx < len(public_ips) - 1:
                print("[*] Waiting 15s to respect API rate limits...")
                time.sleep(15)

        # Verdict
        verdict, action, confidence = evaluate_verdict(vt_result, abuse_result)

        results.append({
            "IP": ip,
            "Verdict": verdict,
            "Action": action,
            "Confidence": confidence,
            "Country": abuse_result.get("country", "Unknown"),
            "ISP": abuse_result.get("isp", "Unknown"),
            "Total_Reports": abuse_result.get("total_reports", "N/A"),
            "Last_Reported": abuse_result.get("last_reported", "N/A"),
        })

        print(f"[+] {ip} → {verdict} | {confidence}")

    # generating report with report script
    generate_report(results)
    print("\n[+] Done. Open triage_report.html to view results.")

if __name__ == "__main__":
    main()