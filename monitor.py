import os
import shodan
import smtplib
import azure.cosmos.cosmos_client as cosmos_client
import uuid
from email.mime.text import MIMEText

# Recupera i segreti dalle variabili d'ambiente
API_KEY = os.getenv('SHODAN_API_KEY')
SMTP_PORT = int(os.getenv('SMTP_PORT_SECRET'))
SMTP_USER = os.getenv('SMTP_USER_SECRET')
SMTP_PASS = os.getenv('SMTP_PASS_SECRET')
TO_EMAIL = os.getenv('TO_EMAIL_SECRET')
SMTP_SERVER = os.getenv('SMTP_SERVER_SECRET')
DB_URI = os.getenv('DB_URI')
DB_NAME = os.getenv('DB_NAME')
COLLECTION_NAME = os.getenv('COLLECTION_NAME')
PRIMARY_KEY_DB = os.getenv('PRIMARY_KEY_DB')

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

# Funzione per verificare se il dispositivo esiste già nel database
def dispositivo_esiste(container, dispositivo):
    query = f'SELECT * FROM c WHERE c.ip="{dispositivo["ip"]}" AND c.port={dispositivo["port"]} AND c.CVE="{dispositivo["CVE"]}"'
    items = list(container.query_items(query=query, enable_cross_partition_query=True))
    return len(items) > 0

# Funzione per salvare i dati nel database
def collegamento_db(dispositivo):
    client = cosmos_client.CosmosClient(DB_URI, {'masterKey': PRIMARY_KEY_DB})
    try:
        database = client.get_database_client(DB_NAME)
        container = database.get_container_client(COLLECTION_NAME)
        print(f"Connessione creata col DB")
        
        if not dispositivo_esiste(container, dispositivo):
            salva_dispositivo(container, dispositivo)
            return True
        else:
            print(f"Dispositivo già esistente nel DB: {dispositivo['ip']}:{dispositivo['port']} CVE: {dispositivo['CVE']}")
            return False

    except Exception as e:
        print(f"Errore nel tentativo di connessione: {e}")
        return False

def salva_dispositivo(container, dispositivo):
    try:
        container.create_item(body=dispositivo)
        print(f"Dispositivo salvato correttamente: {dispositivo}")
    except Exception as e:
        print(f"Errore nel salvataggio del dispositivo: {e}")

def ricerca_dispositivi_vulnerabili(query):
    try:
        results = api.search(query)
        print(f"Risultati trovati: {results['total']}")
        return results['matches']
    except shodan.APIError as e:
        print(f"Errore durante la ricerca su Shodan: {e}")
        return []

def normalizza_vulnerabilita(dispositivi):
    dispositivi_normalizzati = []
    for dispositivo in dispositivi:
        ip = dispositivo['ip_str']
        port = dispositivo['port']
        longitude = dispositivo['location']['longitude'] if 'location' in dispositivo and 'longitude' in dispositivo['location'] else None
        latitude = dispositivo['location']['latitude'] if 'location' in dispositivo and 'latitude' in dispositivo['location'] else None
        if 'vulns' in dispositivo:
            for cve, details in dispositivo['vulns'].items():
                dispositivi_normalizzati.append({
                    'id': str(uuid.uuid4()), #genera un id unico
                    'ip': ip,
                    'port': port,
                    'longitude': longitude,
                    'latitude': latitude,
                    'CVE': cve,
                    'verified': details.get('verified', False),
                    'ranking_epss': details.get('ranking_epss', 0),
                    'cvss_v2': details.get('cvss_v2', 0),
                    'summary': details.get('summary', ''),
                    'references': ', '.join(details.get('references', [])),
                    'epss': details.get('epss', 0),
                    'cvss': details.get('cvss', 0)
                })
    return dispositivi_normalizzati

def monitoraggio(query):
    dispositivi = ricerca_dispositivi_vulnerabili(query)
    dispositivi_normalizzati = normalizza_vulnerabilita(dispositivi)
    for dispositivo in dispositivi_normalizzati:
        if collegamento_db(dispositivo):
            corpo_notifica = (f"IP: {dispositivo['ip']}\n"
                              f"Porta: {dispositivo['port']}\n"
                              f"Longitude: {dispositivo['longitude']}\n"
                              f"Latitude: {dispositivo['latitude']}\n"
                              f"CVE: {dispositivo['CVE']}\n"
                              f"Verified: {dispositivo['verified']}\n"
                              f"Ranking EPSS: {dispositivo['ranking_epss']}\n"
                              f"CVSS v2: {dispositivo['cvss_v2']}\n"
                              f"Summary: {dispositivo['summary']}\n"
                              f"References: {dispositivo['references']}\n"
                              f"EPSS: {dispositivo['epss']}\n"
                              f"CVSS: {dispositivo['cvss']}")
            invia_notifica("Allerta Shodan: Dispositivo Vulnerabile Trovato", corpo_notifica)

if __name__ == "__main__":
    # Esegui il monitoraggio per una query specifica solo se il file è eseguito direttamente
    query = 'country:"IT" city:"Castelnuovo della Daunia"'
    monitoraggio(query)
