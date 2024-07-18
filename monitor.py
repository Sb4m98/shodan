import os
import shodan
import smtplib
import azure.cosmos.cosmos_client as cosmos_client
import uuid
import urllib.parse
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def dispositivo_esiste(container, dispositivo):
    query = f'SELECT * FROM c WHERE c.ip="{dispositivo["ip"]}" AND c.port={dispositivo["port"]} AND c.CVE="{dispositivo["CVE"]}"'
    items = list(container.query_items(query=query, enable_cross_partition_query=True))
    return len(items) > 0

def collegamento_db(dispositivi):
    client = cosmos_client.CosmosClient(DB_URI, {'masterKey': PRIMARY_KEY_DB})
    try:
        database = client.get_database_client(DB_NAME)
        container = database.get_container_client(COLLECTION_NAME)
        print("Connessione creata col DB")

        dispositivi_da_salvare = verifica_dispositivi(container, dispositivi)
        salva_dispositivi(container, dispositivi_da_salvare)
        return dispositivi_da_salvare

    except Exception as e:
        print(f"Errore nel tentativo di connessione: {e}")
        return []

def verifica_dispositivi(container, dispositivi):
    futures = []
    results = []

    with ThreadPoolExecutor() as executor:
        for dispositivo in dispositivi:
            futures.append(executor.submit(dispositivo_esiste, container, dispositivo))
    
    for future in as_completed(futures):
        try:
            results.append(future.result())
        except Exception as e:
            print(f"Errore durante la verifica del dispositivo: {e}")
    
    # Filtra i dispositivi già esistenti
    return [dispositivo for dispositivo, esistente in zip(dispositivi, results) if not esistente]

def salva_dispositivi(container, dispositivi):
    try:
        if dispositivi:  # Verifica se la lista dispositivi non è vuota
            for dispositivo in dispositivi:
                container.upsert_item(body=dispositivo)
            print("Dispositivi salvati correttamente.")
    except Exception as e:
        print(f"Errore nel salvataggio dei dispositivi: {e}")


def ricerca_dispositivi_vulnerabili(query):
    try:
        results = api.search(query)
        print(f"Risultati trovati da analizzare: {results['total']}")
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
                    'id': str(uuid.uuid4()),
                    'ip': ip,
                    'port': port,
                    'longitude': longitude,
                    'latitude': latitude,
                    'CVE': cve,
                    'ranking_epss': details.get('ranking_epss', 0),
                    'summary': details.get('summary', ''),
                    'device': details.get('device', ''),
                    'product': details.get('product', ''),
                    'epss': details.get('epss', 0),
                    'cvss': details.get('cvss', 0),
                    'references': ', '.join(details.get('references', []))
                })
    return dispositivi_normalizzati

def invia_notifiche_in_batch(dispositivi_inviati):
    if dispositivi_inviati:
        corpo_notifica = "Dispositivi vulnerabili trovati:\n\n"
        for dispositivo in dispositivi_inviati:
            corpo_notifica += (f"IP: {dispositivo['ip']}\n"
                               f"Porta: {dispositivo['port']}\n"
                               f"CVE: {dispositivo['CVE']}\n"
                               f"Device: {dispositivo['device']}\n"
                               f"Product: {dispositivo['product']}\n"
                               f"Longitude: {dispositivo['longitude']}\n"
                               f"Latitude: {dispositivo['latitude']}\n"
                               f"Ranking EPSS: {dispositivo['ranking_epss']}\n"
                               f"Summary: {dispositivo['summary']}\n"
                               f"References: {dispositivo['references']}\n"
                               f"EPSS: {dispositivo['epss']}\n"
                               f"CVSS: {dispositivo['cvss']}\n"
                               "-----------------------------\n")
        
        invia_notifica("Allerta Shodan: Dispositivi Vulnerabili Trovati", corpo_notifica)
        print(f"Totale dispositivi vulnerabili trovati: {len(dispositivi_inviati)}")

def monitoraggio(query):
    query = urllib.parse.unquote(query)
    dispositivi = ricerca_dispositivi_vulnerabili(query)
    dispositivi_normalizzati = normalizza_vulnerabilita(dispositivi)
    
    dispositivi_inviati = collegamento_db(dispositivi_normalizzati)
    invia_notifiche_in_batch(dispositivi_inviati)

if __name__ == "__main__":
    query = 'country:"IT" city:"Castelnuovo della Daunia"'
    monitoraggio(query)
