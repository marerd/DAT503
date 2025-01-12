# Erstellt von Markus Erdelyi mit Unterstützung von Claude am 08.01.25

import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import ssl
import socket
import whois
from datetime import datetime

class PhishingDetector:
    def __init__(self):
        # Bekannte Phishing-Schlüsselwörter
        self.suspicious_words = [
            'verify', 'account', 'banking', 'secure', 'update', 'login',
            'confirmen', 'bestätigen', 'konto', 'sicherheit', 'anmelden'
        ]
        
        # Vertrauenswürdige Domains
        self.trusted_domains = [
            'paypal.com', 'amazon.com', 'ebay.com', 'google.com',
            'sparkasse.de', 'deutsche-bank.de', 'commerzbank.de'
        ]

    def check_url(self, url):
        risk_factors = []
        risk_score = 0
        
        # URL-Struktur analysieren
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # HTTPS überprüfen
        if not url.startswith('https://'):
            risk_factors.append('Keine HTTPS-Verschlüsselung')
            risk_score += 20

        # Suspicious Wörter in URL
        for word in self.suspicious_words:
            if word in url.lower():
                risk_factors.append(f'Verdächtiges Wort gefunden: {word}')
                risk_score += 10

        # Ähnlichkeit zu vertrauenswürdigen Domains prüfen
        for trusted_domain in self.trusted_domains:
            if self._calculate_similarity(domain, trusted_domain) > 0.8:
                risk_factors.append(f'Ähnlich zu vertrauenswürdiger Domain: {trusted_domain}')
                risk_score += 30

        try:
            # Domain-Alter prüfen
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

    def check_email(self, email_content):
        risk_factors = []
        risk_score = 0

        # Dringende Aufforderungen
        urgent_phrases = ['sofort', 'dringend', 'schnell', 'wichtig', 'immediately']
        for phrase in urgent_phrases:
            if phrase in email_content.lower():
                risk_factors.append('Dringende Aufforderung gefunden')
                risk_score += 15

        # Links überprüfen
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_content)
        for url in urls:
            url_check = self.check_url(url)
            if url_check['is_suspicious']:
                risk_factors.append(f'Verdächtige URL gefunden: {url}')
                risk_score += 20

        # Grammatik- und Rechtschreibfehler (vereinfacht)
        common_german_words = ['die', 'der', 'das', 'und', 'ist', 'sind']
        words = email_content.lower().split()
        spelling_errors = 0
        for word in words:
            if len(word) > 3 and not any(common_word in word for common_word in common_german_words):
                if not self._basic_spell_check(word):
                    spelling_errors += 1
        
        if spelling_errors > 5:
            risk_factors.append('Mehrere mögliche Rechtschreibfehler gefunden')
            risk_score += 15

        return {
            'risk_score': min(risk_score, 100),
            'risk_factors': risk_factors,
            'is_suspicious': risk_score > 50
        }

    def _calculate_similarity(self, str1, str2):
        # Levenshtein-Distanz (vereinfacht)
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

    def _basic_spell_check(self, word):
        # Vereinfachte Rechtschreibprüfung
        # In der Praxis würde man hier eine richtige Rechtschreibbibliothek verwenden
        return len(word) > 2
