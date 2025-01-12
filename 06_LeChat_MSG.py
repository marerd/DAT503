# Erstellt von Markus Erdelyi mit Unterstützung von LeChat am 10.01.25

import re
import extract_msg
from urllib.parse import urlparse

def check_email_msg(msg_file_path):
    # Laden der MSG-Datei
    msg = extract_msg.Message(msg_file_path)

    # Überprüfung der Absender-E-Mail-Adresse
    sender = msg.sender
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', sender):
        return "Ungültige Absender-E-Mail-Adresse"

    # Analyse des E-Mail-Inhalts
    content = msg.body
    if "dringend" in content.lower() or "sofort" in content.lower():
        return "Dringlichkeitsappell erkannt"

    # Überprüfung von Links
    links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
    for link in links:
        parsed_url = urlparse(link)
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', parsed_url.netloc):
            return "Verdächtiger Link erkannt"

    return "Keine Phishing-Merkmale erkannt"

# Beispiel-Pfad zur MSG-Datei
msg_file_path = 'c:\\tmp\\1.msg'

print(check_email_msg(msg_file_path))
