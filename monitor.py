import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import shodan
import smtplib
from email.mime.text import MIMEText
from pymongo import MongoClient

# Recupera i segreti dalle variabili d'ambiente
API_KEY = os.getenv('SHODAN_API_KEY')
print(API_KEY)
SMTP_PORT = int(os.getenv('SMTP_PORT_SECRET'))
print(SMTP_PORT)
SMTP_USER = os.getenv('SMTP_USER_SECRET')
print(SMTP_USER)
SMTP_PASS = os.getenv('SMTP_PASS_SECRET')
print(SMTP_PASS)
TO_EMAIL = os.getenv('TO_EMAIL_SECRET')
print(TO_EMAIL)
SMTP_SERVER = os.getenv('SMTP_SERVER_SECRET')
print(SMTP_SERVER)
DB_URI = os.getenv('DB_URI')
print(DB_URI)
DB_NAME = os.getenv('DB_NAME')
print(DB_NAME)
COLLECTION_NAME = os.getenv('COLLECTION_NAME')
print(COLLECTION_NAME)
api = shodan.Shodan(API_KEY)

def invia_notifica(oggetto, corpo):
    msg = MIMEText(corpo)
    msg['Subject'] = oggetto
    msg['From'] = SMTP_USER
    msg['To'] = TO_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
        print("Email inviata con successo.")
    except smtplib.SMTPException as e:
        print(f"Errore nell'invio dell'email: {e}")
# Funzione per salvare i dati nel database
def salva_dati(dispositivo):
    try:
        collection.insert_one(dispositivo)
        print(f"Dati salvati per il dispositivo: {dispositivo['ip']}")
    except Exception as e:
        print(f"Errore nel salvataggio dei dati: {e}")


def ricerca_dispositivi_vulnerabili(query):
    try:
        results = api.search(query)
        print(f"Risultati trovati: {results['total']}")
        return results['matches']
    except shodan.APIError as e:
        print(f"Errore durante la ricerca su Shodan: {e}")
        return []

def analizza_vulnerabilita(dispositivi):
    vulnerabili = []
    for dispositivo in dispositivi:
        ip = dispositivo['ip_str']
        port = dispositivo['port']
        data = dispositivo['data']
        if 'vulns' in dispositivo:
            vulnerabili.append({
                'ip': ip,
                'port': port,
                'vulnerabilita': dispositivo['vulns'],
                'dati': data
            })
    return vulnerabili

def monitoraggio(query):
    dispositivi = ricerca_dispositivi_vulnerabili(query)
    vulnerabili = analizza_vulnerabilita(dispositivi)
    for dispositivo in vulnerabili:
        corpo_notifica = f"IP: {dispositivo['ip']}\nPorta: {dispositivo['port']}\nVulnerabilità: {dispositivo['vulnerabilita']}\nDati: {dispositivo['dati']}"
        invia_notifica("Allerta Shodan: Dispositivo Vulnerabile Trovato", corpo_notifica)
        salva_dati(dispositivo)

# Esegui il monitoraggio per una query specifica
query = 'country:"IT" city:"Roma" product:"webcam"'
monitoraggio(query)
