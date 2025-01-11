import extract_msg
import email
from email import policy
from email.parser import BytesParser
import os
from typing import Dict, Any, Union
import re
import requests
from urllib.parse import urlparse
import whois
from datetime import datetime
from bs4 import BeautifulSoup

class EmailParser:
    """Klasse zum Parsen verschiedener E-Mail-Formate"""
    
    @staticmethod
    def parse_msg_file(msg_path: str) -> Dict[str, Any]:
        """
        Parst eine MSG-Datei und extrahiert relevante Informationen
        """
        msg = extract_msg.Message(msg_path)
        
        # Basis-Informationen extrahieren
        email_data = {
            'subject': msg.subject,
            'sender': msg.sender,
            'body': msg.body,
            'date': msg.date,
            'attachments': [],
            'headers': dict(msg.header),
            'embedded_urls': []
        }
        
        # Anhänge verarbeiten
        for attachment in msg.attachments:
            email_data['attachments'].append({
                'filename': attachment.longFilename,
                'extension': os.path.splitext(attachment.longFilename)[1] if attachment.longFilename else None,
                'size': len(attachment.data) if attachment.data else 0
            })
            
        # URLs aus Body extrahieren
        email_data['embedded_urls'] = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_data['body'])
        
        return email_data

    @staticmethod
    def parse_eml_file(eml_path: str) -> Dict[str, Any]:
        """
        Parst eine EML-Datei und extrahiert relevante Informationen
        """
        with open(eml_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        email_data = {
            'subject': msg['subject'],
            'sender': msg['from'],
            'body': '',
            'date': msg['date'],
            'attachments': [],
            'headers': dict(msg.items()),
            'embedded_urls': []
        }
        
        # Body extrahieren
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    email_data['body'] += part.get_payload(decode=True).decode()
                elif part.get_content_type() == "text/html":
                    soup = BeautifulSoup(part.get_payload(decode=True).decode(), 'html.parser')
                    email_data['body'] += soup.get_text()
        else:
            email_data['body'] = msg.get_payload(decode=True).decode()
            
        # URLs extrahieren
        email_data['embedded_urls'] = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_data['body'])
        
        return email_data

class PhishingDetector:
    def __init__(self):
        self.suspicious_words = [
            'verify', 'account', 'banking', 'secure', 'update', 'login',
            'confirmen', 'bestätigen', 'konto', 'sicherheit', 'anmelden',
            'password', 'credential', 'urgent', 'dringend', 'wichtig'
        ]
        
        self.trusted_domains = [
            'paypal.com', 'amazon.com', 'ebay.com', 'google.com',
            'sparkasse.de', 'deutsche-bank.de', 'commerzbank.de'
        ]
        
        self.email_parser = EmailParser()

    def analyze_email_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analysiert eine E-Mail-Datei (MSG oder EML) auf Phishing-Indikatoren
        """
        # Dateityp bestimmen
        file_extension = os.path.splitext(file_path)[1].lower()
        
        try:
            # E-Mail je nach Format parsen
            if file_extension == '.msg':
                email_data = self.email_parser.parse_msg_file(file_path)
            elif file_extension == '.eml':
                email_data = self.email_parser.parse_eml_file(file_path)
            else:
                raise ValueError(f"Nicht unterstütztes Dateiformat: {file_extension}")
            
            # Analyse durchführen
            analysis_result = self._analyze_email_data(email_data)
            
            return {
                'email_data': email_data,
                'analysis': analysis_result
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'email_data': None,
                'analysis': None
            }

    def _analyze_email_data(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Führt die eigentliche Phishing-Analyse durch
        """
        risk_factors = []
        risk_score = 0
        
        # Betreff analysieren
        if email_data['subject']:
            for word in self.suspicious_words:
                if word in email_data['subject'].lower():
                    risk_factors.append(f'Verdächtiges Wort im Betreff: {word}')
                    risk_score += 10

        # Absender analysieren
        if email_data['sender']:
            sender_domain = email_data['sender'].split('@')[-1].lower()
            if not any(trusted_domain in sender_domain for trusted_domain in self.trusted_domains):
                risk_factors.append('Absender-Domain nicht in vertrauenswürdiger Liste')
                risk_score += 15

        # URLs analysieren
        for url in email_data['embedded_urls']:
            url_check = self.check_url(url)
            if url_check['is_suspicious']:
                risk_factors.append(f'Verdächtige URL gefunden: {url}')
                risk_score += 20

        # Anhänge analysieren
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.js', '.vbs']
        for attachment in email_data['attachments']:
            if attachment['extension'] and attachment['extension'].lower() in suspicious_extensions:
                risk_factors.append(f'Verdächtiger Anhang: {attachment["filename"]}')
                risk_score += 25

        # Dringlichkeitsanalyse
        urgent_phrases = ['sofort', 'dringend', 'schnell', 'wichtig', 'immediately']
        for phrase in urgent_phrases:
            if phrase in email_data['body'].lower():
                risk_factors.append('Dringende Aufforderung gefunden')
                risk_score += 15
                break

        return {
            'risk_score': min(risk_score, 100),
            'risk_factors': risk_factors,
            'is_suspicious': risk_score > 60
        }

    def check_url(self, url: str) -> Dict[str, Any]:
        """Bereits existierende URL-Überprüfungsmethode"""
        risk_factors = []
        risk_score = 0
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not url.startswith('https://'):
            risk_factors.append('Keine HTTPS-Verschlüsselung')
            risk_score += 20

        for word in self.suspicious_words:
            if word in url.lower():
                risk_factors.append(f'Verdächtiges Wort gefunden: {word}')
                risk_score += 10

        for trusted_domain in self.trusted_domains:
            if self._calculate_similarity(domain, trusted_domain) > 0.8:
                risk_factors.append(f'Ähnlich zu vertrauenswürdiger Domain: {trusted_domain}')
                risk_score += 30

        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age = (datetime.now() - creation_date).days
                if age < 30:
                    risk_factors.append('Domain ist weniger als 30 Tage alt')
                    risk_score += 25
        except:
            risk_factors.append('Domain-Information nicht verfügbar')
            risk_score += 10

        return {
            'risk_score': min(risk_score, 100),
            'risk_factors': risk_factors,
            'is_suspicious': risk_score > 60
        }

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Bereits existierende Ähnlichkeitsberechnungsmethode"""
        if len(str1) < len(str2):
            return self._calculate_similarity(str2, str1)
        if len(str2) == 0:
            return 0
        previous_row = range(len(str2) + 1)
        for i, c1 in enumerate(str1):
            current_row = [i + 1]
            for j, c2 in enumerate(str2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return 1 - (previous_row[-1] / max(len(str1), len(str2)))