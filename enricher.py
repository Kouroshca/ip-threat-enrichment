import os
import sys
import time
import requests
import pandas as pd
from jinja2 import Template
import config 

def check_virus_total(ip):
    """Queries VirusTotal v3 API for IP reputation."""
    if not config.VT_API_KEY:
        return {"vt_malicious": 0, "vt_total": 0}
    

    headers = {"x-apikey": config.VT_API_KEY}

    try: 
        response = requests.get(f"{config.VT_URL}{ip}", headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return{"vt_malicious": stats['malicious'], 
                   "vt_total": sum(stats.values())
                   }
        elif response.status_code == 429:
            print(f"[!] VT Rate limit hit for {ip}. Skipping...")

    except Exception as e: 
        print(f"[-] Error querying VirusTotal for {ip}: {e}")

    return {"vt_malicious": 0, "vt_total": 0}

# now the abuse IPDB
def check_abuse_ipdb(ip):
    """Queries AbuseIPDB v2 API for IP abuse confidence score."""
    if not config.ABUSEIPDB_API_KEY:
        return {"abuse_score": 0, "isp": "Unknown"}
    
    headers = {
        'Accept': 'application/json',
        'Key': config.ABUSEIPDB_API_KEY
    }
    params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': 'true'}
    try:
        response = requests.get(config.ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            res_data = response.json()['data']
            return {
                "abuse_score": res_data['abuseConfidenceScore'],
                "isp": res_data.get('isp', 'Unknown'),
                "usage_type": res_data.get('usageType', 'Unknown'),
                "total_reports": res_data.get('totalReports', 0),
                "last_reported": res_data.get('lastReportedAt', 'Never'),
                "domain": res_data.get('domain', 'Unknown')
            }
    except Exception as e:
        print(f"[-] Error querying AbuseIPDB for {ip}: {e}")
        
    return {"abuse_score": 0, "isp": "Unknown"}

def evaluate_verdict(vt_malicious, abuse_score):
    """Applies thresholds from config.py to classify the threat level."""
    if vt_malicious >= config.VT_MALICIOUS_THRESHOLD or abuse_score >= 50:
        return "Malicious", "Isolate host immediately & block IP on Firewall."
    elif vt_malicious > 0 or abuse_score >= config.ABUSE_SUSPICIOUS_THRESHOLD:
        return "Suspicious", "Monitor closely. Review active internal connections."
    return "Clean", "No action required. Baseline traffic."

def generate_html_report(results_df, output_path="triage_report.html"):
    """Compiles results into a sleek, dark-themed HTML report dashboard."""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>SOC Triage Intelligence Report</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background-color: #121212; color: #e0e0e0; margin: 30px; }
            h1 { color: #00ff66; border-bottom: 2px solid #333; padding-bottom: 10px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #1e1e1e; }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }
            th { background-color: #2d2d2d; color: #00ff66; text-transform: uppercase; font-size: 0.85em; }
            .badge { padding: 5px 10px; border-radius: 4px; font-weight: bold; font-size: 0.8em; }
            .Malicious { background-color: #ff3333; color: white; }
            .Suspicious { background-color: #ff9900; color: black; }
            .Clean { background-color: #00cc66; color: white; }
        </style>
    </head>
    <body>
        <h1>SOC Triage Intelligence Report</h1>
        <p>Generated on: {{ timestamp }} | Target Source: Automated IP Enrichment</p>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Verdict</th>
                    <th>VT Flags</th>
                    <th>Abuse Score</th>
                    <th>ISP</th>
                    <th>Recommended Action</th>
                </tr>
            </thead>
            <tbody>
                {% for row in data %}
                <tr>
                    <td><strong>{{ row['IP'] }}</strong></td>
                    <td><span class="badge {{ row['Verdict'] }}">{{ row['Verdict'] }}</span></td>
                    <td>{{ row['VT_Malicious'] }} / {{ row['VT_Total'] }}</td>
                    <td>{{ row['Abuse_Score'] }}%</td>
                    <td>{{ row['ISP'] }}</td>
                    <td><em>{{ row['Action'] }}</em></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </body>
    </html>
    """
    template = Template(html_template)
    rendered_html = template.render(
        data=results_df.to_dict(orient="records"),
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
    )
    with open(output_path, "w") as f:
        f.write(rendered_html)
    print(f"\n[+] Sleek HTML report successfully generated: {output_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python enricher.py <path_to_ip_file.txt>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"[-] File not found: {input_file}")
        sys.exit(1)

    print("[*] Parsing IP address list...")
    with open(input_file, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]
        
    results = []
    for idx, ip in enumerate(ips):
        print(f"[*] Processing [{idx+1}/{len(ips)}]: Enriching {ip}...")
        vt_data = check_virus_total(ip)
        abuse_data = check_abuse_ipdb(ip)
        verdict, action = evaluate_verdict(vt_data['vt_malicious'], abuse_data['abuse_score'])
        
        results.append({
            "IP": ip, "Verdict": verdict, "VT_Malicious": vt_data['vt_malicious'],
            "VT_Total": vt_data['vt_total'], "Abuse_Score": abuse_data['abuse_score'],
            "ISP": abuse_data['isp'], "Action": action
        })
        
        # 15-second delay to respect the free tier rate limits safely
        if idx < len(ips) - 1:
            print("[*] Waiting 15 seconds to respect API rate limits...")
            time.sleep(15) 

    df = pd.DataFrame(results)
    generate_html_report(df)

if __name__ == "__main__":
    main()




