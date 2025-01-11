import extract_msg
import re
from email_validator import validate_email, EmailNotValidError

def check_msg_email(msg_file_path):
    try:
        # MSG-Datei öffnen
        msg = extract_msg.Message(msg_file_path)
        
        # E-Mail-Inhalt extrahieren
        sender = msg.sender
        subject = msg.subject
        body = msg.body
        
        suspicious = False
        reasons = []
        
        # Absender-E-Mail-Adresse überprüfen
        try:
            validate_email(sender)
        except EmailNotValidError:
            suspicious = True
            reasons.append(f"Ungültige Absender-E-Mail: {sender}")
        
        # Überprüfe auf dringende Aufforderungen
        if re.search(r'sofort|dringend|jetzt handeln', body, re.IGNORECASE):
            suspicious = True
            reasons.append("Dringende Aufforderung gefunden")
        
        # Überprüfe auf verdächtige Links
        links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
        for link in links:
            if not link.startswith("https://"):
                suspicious = True
                reasons.append(f"Unsicherer Link gefunden: {link}")
        
        # Überprüfe auf Aufforderung zur Eingabe sensibler Daten
        if re.search(r'passwort|benutzername|kreditkarte', body, re.IGNORECASE):
            suspicious = True
            reasons.append("Aufforderung zur Eingabe sensibler Daten")
        
        return suspicious, reasons
    
    except Exception as e:
        return True, [f"Fehler beim Lesen der MSG-Datei: {str(e)}"]

# Beispielnutzung
msg_file_path = "C:\\tmp\\1.msg"
suspicious, reasons = check_msg_email(msg_file_path)

print("MSG-Datei-Überprüfung:")
print("Verdächtig:", suspicious)
print("Gründe:", reasons)
