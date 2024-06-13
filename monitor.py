import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import shodan
import smtplib
from email.mime.text import MIMEText

# Configurazione Key Vault
KEY_VAULT_NAME = os.getenv('KEY_VAULT_NAME')
SECRET_NAME = os.getenv('SECRET_NAME')
SMTP_SERVER_SECRET = os.getenv('SMTP_SERVER_SECRET')
SMTP_PORT_SECRET = os.getenv('SMTP_PORT_SECRET')
SMTP_USER_SECRET = os.getenv('SMTP_USER_SECRET')
SMTP_PASS_SECRET = os.getenv('SMTP_PASS_SECRET')
TO_EMAIL_SECRET = os.getenv('TO_EMAIL_SECRET')

# Recupera i segreti dal Key Vault
key_vault_url = f"https://{KEY_VAULT_NAME}.vault.azure.net/"
credential = DefaultAzureCredential()
client = SecretClient(vault_url=key_vault_url, credential=credential)
API_KEY = client.get_secret(SECRET_NAME).value
print(API_KEY)
SMTP_SERVER = client.get_secret(SMTP_SERVER_SECRET).value
print(SMTP_SERVER)
SMTP_PORT = int(client.get_secret(SMTP_PORT_SECRET).value)
print(SMTP_PORT)
SMTP_USER = client.get_secret(SMTP_USER_SECRET).value
print(SMTP_USER)
SMTP_PASS = client.get_secret(SMTP_PASS_SECRET).value
print(SMTP_PASS)
TO_EMAIL = client.get_secret(TO_EMAIL_SECRET).value
print(TO_EMAIL)

# Configurazione Shodan e SMTP
api = shodan.Shodan(API_KEY)

def invia_notifica(oggetto, corpo):
    msg = MIMEText(corpo)
    msg['Subject'] = oggetto
    msg['From'] = SMTP_USER
    msg['To'] = TO_EMAIL

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(msg['From'], [msg['To']], msg.as_string())

def ricerca_dispositivi_vulnerabili(query):
    try:
        results = api.search(query)
        print(f"Risultati trovati: {results['total']}")
        return results['matches']
    except shodan.APIError as e:
        print(f"Errore: {e}")
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

# Esegui il monitoraggio per una query specifica
query = 'country:"IT" city:"Roma" vuln:heartbleed'  # Modifica la query in base alla tua interpretazione di "near your target"
monitoraggio(query)
