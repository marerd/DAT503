# Erstellt von Markus Erdelyi mit Unterstützung von Microsofts Copilot am 07.01.25

import re
import requests
from bs4 import BeautifulSoup
import extract_msg

def extract_links(email_content):
    links = re.findall(r'(https?://\S+)', email_content)
    return links

def check_https(url):
    return url.startswith("https://")

def check_suspicious_words(url):
    suspicious_words = ["login", "verify", "update", "secure"]
    return any(word in url for word in suspicious_words)

def check_domain_length(url):
    domain = re.findall(r'://([^/]+)/?', url)[0]
    return len(domain) < 20

def fetch_page_content(url):
    try:
        response = requests.get(url)
        return response.text
    except:
        return ""

def check_for_forms(content):
    soup = BeautifulSoup(content, 'html.parser')
    return bool(soup.find_all('form'))

def is_phishing(url):
    if not check_https(url):
        print("Warning: The URL does not use HTTPS.")
    if check_suspicious_words(url):
        print("Warning: The URL contains suspicious words.")
    if check_domain_length(url):
        print("Warning: The domain length is unusually short.")
    content = fetch_page_content(url)
    if check_for_forms(content):
        print("Warning: The webpage contains forms.")

def check_msg_email_for_phishing(msg_path):
    msg = extract_msg.Message(msg_path)
    email_content = msg.body
    links = extract_links(email_content)
    for link in links:
        is_phishing(link)

# Beispiel-Pfad zur MSG-Datei
msg_path = "C:\\tmp\\1.msg"
check_msg_email_for_phishing(msg_path)
