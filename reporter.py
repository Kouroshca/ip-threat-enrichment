import time
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SOC Triage Intelligence Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #121212; color: #e0e0e0; margin: 30px; }
        h1 { color: #00ff66; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .summary { background: #1e1e1e; border-left: 4px solid #00ff66; padding: 12px 20px; margin: 20px 0; font-size: 0.95em; }
        .summary span { color: #00ff66; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #1e1e1e; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; font-size: 0.9em; }
        th { background-color: #2d2d2d; color: #00ff66; text-transform: uppercase; font-size: 0.8em; }
        .badge { padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.8em; }
        .Malicious { background-color: #ff3333; color: white; }
        .Suspicious { background-color: #ff9900; color: black; }
        .Clean { background-color: #00cc66; color: white; }
        .Unknown { background-color: #555555; color: #cccccc; }
        .confidence { font-size: 0.78em; color: #888; }
        .action { font-style: italic; font-size: 0.85em; }
    </style>
</head>
<body>
    <h1>🛡 SOC Triage Intelligence Report</h1>
    <p>Generated: {{ timestamp }}</p>

    <div class="summary">
        Enriched <span>{{ total }}</span> IPs —
        <span style="color:#ff3333">{{ malicious }}</span> Malicious /
        <span style="color:#ff9900">{{ suspicious }}</span> Suspicious /
        <span style="color:#00cc66">{{ clean }}</span> Clean /
        <span style="color:#888">{{ unknown }}</span> Unknown
    </div>

    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Verdict</th>
                <th>Confidence</th>
                <th>Country</th>
                <th>ISP</th>
                <th>Reports (90d)</th>
                <th>Last Reported</th>
                <th>Recommended Action</th>
            </tr>
        </thead>
        <tbody>
            {% for row in data %}
            <tr>
                <td><strong>{{ row.IP }}</strong></td>
                <td><span class="badge {{ row.Verdict }}">{{ row.Verdict }}</span></td>
                <td class="confidence">{{ row.Confidence }}</td>
                <td>{{ row.Country }}</td>
                <td>{{ row.ISP }}</td>
                <td>{{ row.Total_Reports }}</td>
                <td>{{ row.Last_Reported }}</td>
                <td class="action">{{ row.Action }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""

def generate_report(results, output_path = "triage_report.html"):
    # this part takes the list of result dicts from main.py and renders the HTML report.
    counts = {
        "Malicious": 0,
        "Suspicious": 0,
        "Clean": 0,
        "Unknown": 0
    }
    for row in results:
        verdict = row.get("Verdict", "Unknown")
        if verdict in counts:
            counts[verdict] += 1

    template = Template(HTML_TEMPLATE)
    rendered = template.render(
        data=results,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        total=len(results),
        malicious=counts["Malicious"],
        suspicious=counts["Suspicious"],
        clean=counts["Clean"],
        unknown=counts["Unknown"]
    )

    with open(output_path, "w") as f:
        f.write(rendered)

    print(f"[+] Report saved: {output_path}")