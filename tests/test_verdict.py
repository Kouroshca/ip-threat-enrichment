import pytest
from verdict import evaluate_verdict

def ok_vt(malicious = 0, vt_total = 91):
    return {"status": "ok", "vt_malicious": malicious, "vt_total": vt_total }

def ok_abuse(score = 0):
    return {"status": "ok", "abuse_score": score, "ips" : "Test IPS", "total_report": 0, "last_reported": "Never", "country": "US"}

def failed_vt(reason = "rate_limited"):
    return {"status": reason, "vt_malicious": 0, "vt_total": 0}

def failed_abuse(reason = "rate_limited"):
    return {"status": reason, "abuse_score": 0, "isp": "Unknonw"}

# tests

def test_clean_requires_both_sources():
    # both should pass okay
    verdict, _, _ = evaluate_verdict(ok_vt(), ok_abuse())
    assert verdict == "Clean"

def test_vt_failure_is_unknown_not_clean():
    #this rate vt should never produce clean
    verdict, _, _ = evaluate_verdict(failed_vt("rate_limited"), ok_abuse())
    assert verdict == "Unknown"

def test_abuse_failure_is_unknown_not_clean():
    verdict, _, _ = evaluate_verdict(ok_vt(), failed_abuse("error"))
    assert verdict == "Unknown"

def test_both_failed_is_unknown():
    verdict, _, _ = evaluate_verdict(failed_vt(), failed_abuse())
    assert verdict == "Unknown"

def test_auth_error_is_unknown_not_clean():
    verdict, _, _ = evaluate_verdict(
        failed_vt("auth_error"),
        failed_abuse("auth_error")
    )
    assert verdict == "Unknown"

def test_high_abuse_score_is_malicious():
   #testing whether abuse is giving a correct review
    verdict, _, _ = evaluate_verdict(ok_vt(malicious=0), ok_abuse(score=85))
    assert verdict == "Malicious"
    
def test_high_vt_engines_is_malicious():
    verdict, _, _ = evaluate_verdict(ok_vt(malicious=0), ok_abuse(score=85))
    assert verdict == "Malicious"

def test_low_abuse_score_is_suspicious():
    verdict, _, _ = evaluate_verdict(ok_vt(malicious=0), ok_abuse(score=30))
    assert verdict == "Suspicious"

def test_single_vt_engine_is_suspicious():
    verdict, _, _ = evaluate_verdict(ok_vt(malicious=1), ok_abuse(score=0))
    assert verdict == "Suspicious"

def test_unknown_reason_string_contains_source():
    _, _, confidence = evaluate_verdict(failed_vt("rate_limited"), ok_abuse())
    assert "VT" in confidence

def test_malicious_returns_esclation():
    _, action, _ = evaluate_verdict(ok_vt(malicious=5), ok_abuse(score=85))
    assert "Escalate" in action

def test_clean_action_says_no_action():
    _, action, _ = evaluate_verdict(ok_vt(), ok_abuse())
    assert "No action" in action