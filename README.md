# Shodan Vulnerability Monitor

A threat intelligence pipeline built on top of the Shodan API to continuously surface exposed and vulnerable assets across arbitrary network scopes. Results are persisted in Azure Cosmos DB, deduplicated at ingestion, and surfaced through a Power BI dashboard. Novel findings trigger batched SMTP alerts. The application is packaged as a Flask service and runs on Azure App Service with a fully automated CI/CD pipeline via GitHub Actions.

---

## Overview

The system addresses a common gap in passive reconnaissance workflows: the absence of a stateful, automated layer that correlates Shodan results against a persistent store and surfaces only net-new findings. Rather than flooding operators with repeated alerts on known assets, the pipeline checks each (IP, port, CVE) tuple against the database before persisting and notifying, keeping signal-to-noise ratio high.

CVE metadata enrichment is handled natively by the Shodan API, which returns CVSS and EPSS scoring alongside vulnerability summaries and reference links. These are normalized into a flat document schema suited for Cosmos DB and Power BI consumption.

---

## Architecture

```
                    +------------------+
                    |   Shodan API     |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  Flask Web App   |  <-- HTTP trigger (custom query)
                    +--------+---------+
                             |
             +---------------+---------------+
             |                               |
    +--------v---------+          +----------v--------+
    | Azure Cosmos DB  |          |   SMTP Notifier   |
    | (dedup + store)  |          | (batch email alert)|
    +------------------+          +-------------------+
             |
    +--------v---------+
    |  Power BI Report |
    +------------------+
```

Deployment is handled through a GitHub Actions workflow that builds, packages, and pushes to Azure App Service on every merge to `main`.

---

## Features

- Arbitrary Shodan query execution via HTTP endpoint
- CVE normalization with CVSS, EPSS, ranking, summary, and references
- Stateful deduplication: only unseen (IP, port, CVE) tuples are persisted and alerted
- Concurrent Cosmos DB lookups via `ThreadPoolExecutor`
- Batched email alerts with full vulnerability context per finding
- Power BI dashboard redirect post-scan
- Secrets managed entirely via environment variables — no credentials in code

---

## Requirements

- Python 3.9+
- Shodan account with a paid API key (vulnerability data requires Shodan Enterprise or Membership)
- Azure Cosmos DB instance (Core SQL API)
- SMTP relay (Office 365, SendGrid, or equivalent)

---

## Installation

```bash
git clone https://github.com/your-username/shodan-monitor.git
cd shodan-monitor
pip install -r requirements.txt
```

---

## Configuration

All runtime configuration is passed through environment variables. No configuration files or hardcoded values are used.

| Variable | Description |
|---|---|
| `SHODAN_API_KEY` | Shodan API key |
| `SMTP_SERVER` | SMTP server hostname |
| `SMTP_PORT_SECRET` | SMTP port (typically 587 for STARTTLS) |
| `SMTP_USER_SECRET` | SMTP authentication username |
| `SMTP_PASS_SECRET` | SMTP authentication password |
| `TO_EMAIL_SECRET` | Alert recipient address |
| `DB_URI` | Azure Cosmos DB account URI |
| `DB_NAME` | Cosmos DB database name |
| `COLLECTION_NAME` | Cosmos DB container name |
| `PRIMARY_KEY_DB` | Cosmos DB primary key |

When deploying to Azure App Service, configure these as Application Settings rather than embedding them in the workflow definition.

---

## Running Locally

```bash
python app.py
```

Binds to `0.0.0.0:5000` by default.

---

## API

### `GET /monitoraggio`

Executes a Shodan search against the provided query, normalizes and deduplicates results, persists new findings to Cosmos DB, dispatches email alerts if new vulnerabilities are found, and redirects to the Power BI report.

**Query parameter:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `query` | string | `country:"IT" city:"Castelnuovo della Daunia"` | Any valid Shodan search query |

**Example:**

```
GET /monitoraggio?query=country%3A%22IT%22%20port%3A445%20vuln%3ACVE-2017-0144
```

On success, the client is redirected to the Power BI dashboard. On failure, a JSON error payload is returned with HTTP 500.

---

## Data Model

Each finding stored in Cosmos DB has the following schema:

```json
{
  "id": "<uuid>",
  "ip": "93.x.x.x",
  "port": 445,
  "latitude": 41.x,
  "longitude": 15.x,
  "CVE": "CVE-2017-0144",
  "cvss": 9.3,
  "epss": 0.974,
  "ranking_epss": 0.99,
  "summary": "The SMBv1 server in Microsoft Windows...",
  "device": "",
  "product": "Windows 7",
  "references": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144, ..."
}
```

Deduplication is performed on the composite key `(ip, port, CVE)` prior to any write operation.

---

## Project Structure

```
.
├── app.py                            # Flask application and route definitions
├── monitor.py                        # Core pipeline: search, normalize, persist, notify
├── requirements.txt
├── templates/
│   └── template.html
├── static/
│   └── logo.png
└── .github/
    └── workflows/
        └── main_shodanwebapp.yml     # CI/CD pipeline (build + deploy to Azure)
```

---

## Deployment

The included GitHub Actions workflow handles the full build and deployment lifecycle to Azure App Service.

**Required GitHub repository secrets:**

| Secret | Description |
|---|---|
| `AZUREAPPSERVICE_CLIENTID_*` | Azure service principal client ID |
| `AZUREAPPSERVICE_TENANTID_*` | Azure tenant ID |
| `AZUREAPPSERVICE_SUBSCRIPTIONID_*` | Azure subscription ID |

The workflow triggers on push to `main` and on manual dispatch. It builds under Python 3.9, installs dependencies, packages the application, and deploys to the `Production` slot of the `ShodanWebApp` App Service.

---

## Security Considerations

- Shodan queries should be scoped as narrowly as operationally required to avoid unnecessary API credit consumption and unintended reconnaissance scope
- The Cosmos DB primary key and SMTP credentials must be rotated regularly and should ideally be sourced from Azure Key Vault rather than App Service environment variables in high-security deployments
- The `/monitoraggio` endpoint is unauthenticated in the current implementation — access should be restricted at the network or application gateway level before exposing to non-trusted networks
- EPSS and CVSS scores sourced from Shodan reflect the state at query time; scores are subject to change as the NVD and FIRST update their datasets

---

## Dependencies

```
shodan
azure-identity
azure-keyvault-secrets
azure-cosmos
Flask
```
