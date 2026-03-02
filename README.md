# ThreatWatch — Threat Intelligence Dashboard

A real-time threat intelligence dashboard that aggregates malicious IP data and threat indicators from industry-leading security APIs. Built as a portfolio project demonstrating **cloud security**, **DevOps automation**, and **full-stack development** skills.

---

## Features

- **Malicious IP Feed** — Pulls the AbuseIPDB blacklist and displays IPs with confidence scores, country of origin, and severity ratings
- **Threat Intelligence Pulses** — Fetches recent threat indicators from AlienVault OTX (APTs, ransomware campaigns, CVE exploits, etc.)
- **IP Reputation Lookup** — Check any IP address on demand
- **Severity Classification** — Critical / High / Medium / Low color-coded across all data
- **Auto-refresh** — Dashboard refreshes every 60 seconds
- **Mock Data Mode** — Runs without API keys using realistic sample data

---

## Architecture

```
+---------------------------------------------------------------+
|                     GitHub Actions CI/CD                      |
| push to main -> run tests -> build image -> push ECR -> deploy|
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                        AWS (ECS Fargate)                      |
|                                                               |
|  Internet -> ALB (port 80) -> ECS Task (port 8000)           |
|                               |                               |
|                               +-- FastAPI Backend             |
|                               |   +-- /api/ips/blacklist      |
|                               |   +-- /api/ips/check/{ip}     |
|                               |   +-- /api/threats/pulses     |
|                               +-- Static HTML/JS Dashboard    |
|                                                               |
|  External APIs: AbuseIPDB         AlienVault OTX             |
|  Logs: CloudWatch Logs                                        |
|  Images: Amazon ECR                                           |
+---------------------------------------------------------------+
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, httpx |
| Frontend | Vanilla HTML/CSS/JavaScript |
| Containerization | Docker |
| Cloud Provider | AWS |
| Compute | ECS Fargate (serverless containers) |
| Load Balancing | Application Load Balancer |
| Container Registry | Amazon ECR |
| Monitoring | CloudWatch Logs |
| Infrastructure as Code | Terraform |
| CI/CD | GitHub Actions |

---

## Quick Start (Local)

### Prerequisites
- Python 3.11+
- Docker (optional)
- API keys (optional — mock data works without them)

### 1. Clone & setup

```bash
git clone https://github.com/Sadiel0/ThreatWatch.git
cd ThreatWatch
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and add your API keys (or leave blank for mock data)
```

Get free API keys:
- **AbuseIPDB**: https://www.abuseipdb.com/register
- **AlienVault OTX**: https://otx.alienvault.com/

### 3. Run the server

```bash
uvicorn app.main:app --reload
```

Open http://localhost:8000 in your browser.

### 4. Run tests

```bash
pytest tests/ -v
```

---

## Docker

```bash
docker build -t threatwatch .
docker run -p 8000:8000 \
  -e ABUSEIPDB_API_KEY=your_key \
  -e OTX_API_KEY=your_key \
  threatwatch
```

---

## AWS Deployment with Terraform

### Prerequisites
- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- [AWS CLI](https://aws.amazon.com/cli/) configured with your credentials

### Deploy

```bash
cd terraform

terraform init

terraform plan \
  -var="abuseipdb_api_key=your_key" \
  -var="otx_api_key=your_key"

terraform apply \
  -var="abuseipdb_api_key=your_key" \
  -var="otx_api_key=your_key"
```

Terraform outputs the ALB URL when complete:

```
alb_dns_name = "http://threatwatch-alb-123456789.us-east-1.elb.amazonaws.com"
```

### Teardown (avoid charges)

```bash
terraform destroy
```

> **Cost estimate:** ECS Fargate (0.25 vCPU / 512 MB) ~$0.01/hr + ALB ~$0.008/hr. Tear down when not in use.

---

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci-cd.yml`) automates:

1. **On every PR** — runs pytest
2. **On push to `main`** — runs tests, then:
   - Builds Docker image
   - Pushes to Amazon ECR (tagged with commit SHA + `latest`)
   - Updates ECS task definition with new image
   - Deploys to ECS (waits for stability)

### Required GitHub Secrets

| Secret | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key |

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/api/ips/blacklist?limit=25` | Get malicious IP blacklist |
| `GET` | `/api/ips/check/{ip}` | Check reputation of a specific IP |
| `GET` | `/api/threats/pulses?limit=10` | Get recent OTX threat pulses |

Interactive docs available at http://localhost:8000/docs

---

## Security Considerations

- **Non-root Docker user** — Container runs as `appuser`, not root
- **ECR image scanning** — Images scanned for vulnerabilities on push
- **Security groups** — ECS tasks only accept traffic from the ALB
- **Environment variables** — API keys never hardcoded; injected at runtime
- **Sensitive Terraform vars** — API keys marked `sensitive = true`
- **Production recommendation** — Store API keys in AWS Secrets Manager instead of plain environment variables

---

## Project Structure

```
ThreatWatch/
+-- app/
|   +-- main.py               # FastAPI app entry point
|   +-- models/
|   |   +-- schemas.py        # Pydantic data models
|   +-- routers/
|   |   +-- ips.py            # IP reputation endpoints
|   |   +-- threats.py        # Threat pulse endpoints
|   +-- services/
|   |   +-- abuseipdb.py      # AbuseIPDB API client
|   |   +-- otx.py            # AlienVault OTX API client
|   +-- static/
|       +-- index.html        # Dashboard (HTML/CSS/JS)
+-- tests/
|   +-- test_main.py          # pytest test suite
+-- terraform/
|   +-- main.tf               # All AWS infrastructure
|   +-- variables.tf          # Input variables
|   +-- outputs.tf            # Output values
+-- .github/
|   +-- workflows/
|       +-- ci-cd.yml         # GitHub Actions CI/CD
+-- Dockerfile
+-- requirements.txt
+-- .env.example
+-- README.md
```

---

## Skills Demonstrated

| Skill | How |
|---|---|
| **Cloud Security** | Threat intelligence APIs, severity classification, IP reputation analysis |
| **AWS** | ECS Fargate, ECR, ALB, IAM, CloudWatch — production-grade deployment |
| **Infrastructure as Code** | Full Terraform configuration, remote state ready |
| **CI/CD** | GitHub Actions pipeline: test -> build -> push -> deploy |
| **Containerization** | Multi-layer Dockerfile, health checks, non-root user |
| **Python/FastAPI** | RESTful API, async HTTP clients, Pydantic validation |
| **Frontend** | Vanilla JS dashboard, real API integration, responsive design |
| **Security Best Practices** | Least-privilege security groups, image scanning, secrets management |

---

## License

MIT
