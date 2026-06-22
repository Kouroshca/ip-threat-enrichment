import os
import re
import ipaddress
import pandas as pd

IP_CANDIDATE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def _extract_valid_ips(text):
    """Pull candidate IPs from raw text, keep only the ones that are real IPs."""
    found = set()
    for candidate in IP_CANDIDATE.findall(text):
        try:
            ip = ipaddress.ip_address(candidate)   # rejects 999.999.x.x etc.
            found.add(str(ip))
        except ValueError:
            continue
    return found

def parse_input(source):
    """
    Accepts a single IP string OR a file path (.csv / .txt / .log).
    Returns a deduped set of valid IP strings.
    """
    # Case 1 user typed a bare IP directly
    try:
        ipaddress.ip_address(source)
        return {source}
    except ValueError:
        pass  

    # Case 2: its a file
    if not os.path.exists(source):
        raise FileNotFoundError(f"Not a valid IP or an existing file: {source}")

    ext = os.path.splitext(source)[1].lower()
    if ext == ".csv":
        df = pd.read_csv(source, dtype=str)
        text = " ".join(df.fillna("").values.ravel())   
        return _extract_valid_ips(text)
    elif ext in (".txt", ".log"):
        with open(source, "r", errors="ignore") as f:
            return _extract_valid_ips(f.read())
    else:
        raise ValueError(f"Unsupported file type '{ext}'. Use .csv, .txt, or .log.")