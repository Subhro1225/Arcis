import re
import dns.resolver

def verify_email_dns(domain: str) -> dict:
    """Perform DNS checks to verify sender domain safety configuration."""
    results = {
        "has_mx": False,
        "has_spf": False,
        "has_dmarc": False
    }
    if not domain:
        return results

    # 1. Check MX Records
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        results["has_mx"] = len(mx_answers) > 0
    except Exception:
        pass

    # 2. Check SPF Record (TXT record starting with v=spf1)
    try:
        txt_answers = dns.resolver.resolve(domain, 'TXT')
        for txt in txt_answers:
            txt_str = txt.to_text().lower()
            if "v=spf1" in txt_str:
                results["has_spf"] = True
                break
    except Exception:
        pass

    # 3. Check DMARC Record (TXT record at _dmarc.<domain>)
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for txt in dmarc_answers:
            txt_str = txt.to_text().lower()
            if "v=dmarc1" in txt_str:
                results["has_dmarc"] = True
                break
    except Exception:
        pass

    return results

def predict_sender_email(email_address: str) -> dict:
    """
    Template for checking sender email legitimacy.
    
    TODO: Plug in your own Machine Learning model or classification rules here.
    
    Currently implements a heuristic-based baseline that checks:
    1. Email regex formatting validation.
    2. Free/public mail provider check (Gmail, Yahoo, Hotmail, etc.).
    3. Active domain DNS security configuration (MX, SPF, DMARC records).
    """
    email = str(email_address).strip()
    
    # 1. Basic formatting check
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return {
            "email": email,
            "is_phishing": True,
            "risk_score_pct": 100.0,
            "verdict": "Invalid email formatting",
            "dns_checks": {}
        }
        
    parts = email.split('@')
    local_part = parts[0]
    domain = parts[1].lower()

    # Free email provider list
    free_providers = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'mail.com', 'protonmail.com'}
    is_free_provider = domain in free_providers

    # 2. Run DNS verification metrics
    dns_status = verify_email_dns(domain)

    # 3. Baseline Heuristic Scoring (Placeholder logic)
    # Calculate a simple threat score
    score = 0
    reasons = []

    # Free provider checks
    if is_free_provider:
        # A free provider is not inherently spam, but checking for keywords inside local parts can raise suspicion
        suspicious_words = ['secure', 'support', 'service', 'verify', 'update', 'login', 'admin', 'billing', 'paypal', 'bank']
        flagged_words = [w for w in suspicious_words if w in local_part.lower()]
        if flagged_words:
            score += 65
            reasons.append(f"Free email local part contains suspicious keywords: {', '.join(brand.upper() for brand in flagged_words)}")
    else:
        # For private domain providers, lack of MX, SPF, or DMARC is highly suspicious
        if not dns_status["has_mx"]:
            score += 80
            reasons.append("Sender domain has no active MX mail server records.")
        if not dns_status["has_spf"]:
            score += 25
            reasons.append("Sender domain lacks SPF authentication record.")
        if not dns_status["has_dmarc"]:
            score += 25
            reasons.append("Sender domain lacks DMARC configuration policy.")

    # Bound risk score between 0 and 100
    risk_score = min(max(score, 0.0), 100.0)
    is_phishing = risk_score >= 50.0

    return {
        "email": email,
        "is_phishing": is_phishing,
        "risk_score_pct": float(risk_score),
        "details": {
            "is_free_provider": is_free_provider,
            "reasons": reasons if reasons else ["Email matches standard sender authentication patterns."]
        },
        "dns_checks": dns_status
    }

if __name__ == "__main__":
    test_emails = [
        "paypal-support@gmail.com",
        "billing@microsoft.com",
        "security-update@unverified-sender.xyz"
    ]
    print("="*60)
    print("TESTING EMAIL SENDER SECURITY CLASSIFIER")
    print("="*60)
    for te in test_emails:
        res = predict_sender_email(te)
        print(f"\nEmail: {te}")
        print("  Phishing:", res["is_phishing"], "| Risk:", res["risk_score_pct"], "%")
        print("  Reasons:", res["details"]["reasons"])
