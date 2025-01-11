import requests
from urllib.parse import urlparse

def check_website(url):
    # Überprüfung der URL
    parsed_url = urlparse(url)
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', parsed_url.netloc):
        return "Verdächtige URL"

    # Prüfung des SSL-Zertifikats
    try:
        response = requests.get(url)
        if not response.url.startswith('https'):
            return "Kein SSL-Zertifikat"
    except requests.exceptions.SSLError:
        return "Ungültiges SSL-Zertifikat"

    # Analyse des Webseiten-Inhalts
    content = response.text
    if "dringend" in content.lower() or "sofort" in content.lower():
        return "Dringlichkeitsappell erkannt"

    return "Keine Phishing-Merkmale erkannt"

# Beispiel-URL
url = 'https://example.com'

print(check_website(url))
