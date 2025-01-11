# Beispielverwendung
import Claude_EMail_MSG as myModule
detector = myModule.PhishingDetector()

# MSG-Datei analysieren
msg_file_path = "C:\\tmp\\obb.msg"
result = detector.analyze_email_file(msg_file_path)

if result['analysis']:
    print(f"Risiko-Score: {result['analysis']['risk_score']}/100")
    print("\nGefundene Risikofaktoren:")
    for factor in result['analysis']['risk_factors']:
        print(f"- {factor}")
    
    print("\nE-Mail Details:")
    print(f"Betreff: {result['email_data']['subject']}")
    print(f"Absender: {result['email_data']['sender']}")
    print(f"Gefundene URLs: {len(result['email_data']['embedded_urls'])}")
    print(f"Anhänge: {len(result['email_data']['attachments'])}")
else:
    print(f"Fehler bei der Analyse: {result['error']}")
