# Beispielverwendung
detector = PhishingDetector()

# URL überprüfen
url_result = detector.check_url("https://example.com")
print(f"URL Risiko-Score: {url_result['risk_score']}")
print(f"Risikofaktoren: {url_result['risk_factors']}")

# E-Mail überprüfen
email_content = "Ihre Nachricht hier..."
email_result = detector.check_email(email_content)
print(f"E-Mail Risiko-Score: {email_result['risk_score']}")
print(f"Risikofaktoren: {email_result['risk_factors']}")