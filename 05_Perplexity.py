# Erstellt von Markus Erdelyi mit Unterstützung von Perplexity am 09.01.25

import re
import requests
from bs4 import BeautifulSoup

def check_email(email_content):
    suspicious = False
    reasons = []

    # Überprüfe auf dringende Aufforderungen
    if re.search(r'sofort|dringend|jetzt handeln', email_content, re.IGNORECASE):
        suspicious = True
        reasons.append("Dringende Aufforderung gefunden")

    # Überprüfe auf verdächtige Links
    links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_content)
    for link in links:
        if not link.startswith("https://"):
            suspicious = True
            reasons.append(f"Unsicherer Link gefunden: {link}")

    # Überprüfe auf Aufforderung zur Eingabe sensibler Daten
    if re.search(r'passwort|benutzername|kreditkarte', email_content, re.IGNORECASE):
        suspicious = True
        reasons.append("Aufforderung zur Eingabe sensibler Daten")

    return suspicious, reasons

def check_website(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        suspicious = False
        reasons = []

        # Überprüfe auf verdächtige Formulare
        forms = soup.find_all('form')
        for form in forms:
            if form.find('input', {'type': 'password'}):
                suspicious = True
                reasons.append("Verdächtiges Anmeldeformular gefunden")

        # Überprüfe auf SSL-Zertifikat
        if not url.startswith("https://"):
            suspicious = True
            reasons.append("Keine sichere HTTPS-Verbindung")

        return suspicious, reasons
    except:
        return True, ["Fehler beim Zugriff auf die Webseite"]

# Beispielnutzung
# email_content = "Bitte geben Sie sofort Ihr Passwort ein: http://example.com"
email_content = "Die Lieferung bedarf Ihrer Bestätigung"
website_url = "https://onlinecampus.fernfh.ac.at/login/index.php"

email_suspicious, email_reasons = check_email(email_content)
website_suspicious, website_reasons = check_website(website_url)

print("E-Mail-Überprüfung:")
print("Verdächtig:", email_suspicious)
print("Gründe:", email_reasons)

print("\nWebseiten-Überprüfung:")
print("Verdächtig:", website_suspicious)
print("Gründe:", website_reasons)
