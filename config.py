# this is where Im going to do the settings manager.

import os

#keys of virus total and abuseIP 
VT_API_KEY = os.environ.get("VT_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSE_API_KEY") 

# TI endpoints
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# telling TIs how to classify the IP comparing to the points they get.
ABUSE_SUSPICIOUS_THRESHOLD = 20
VT_MALICIOUS_THRESHOLD = 3