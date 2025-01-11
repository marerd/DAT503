import re
from urllib.parse import urlparse

def check_email(email):
    # Überprüfung der Absender-E-Mail-Adresse
    sender = email['From']
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', sender):
        return "Ungültige Absender-E-Mail-Adresse"

    # Analyse des E-Mail-Inhalts
    content = email['Body']
    if "dringend" in content.lower() or "sofort" in content.lower():
        return "Dringlichkeitsappell erkannt"

    # Überprüfung von Links
    links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
    for link in links:
        parsed_url = urlparse(link)
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', parsed_url.netloc):
            return "Verdächtiger Link erkannt"

    return "Keine Phishing-Merkmale erkannt"

# Beispiel-E-Mail
email = {
    'From': 'support@example.com',
    'Body': 'Bitte klicken Sie auf diesen Link, um Ihr Konto zu bestätigen: http://example.com/confirm'
}

print(check_email(email))
