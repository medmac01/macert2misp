# maCERT to MISP Ingestor

Ingest maCERT (Morocco CERT) vulnerability bulletins and malware reports from PDF format into MISP events.

## Features

- **PDF Parsing**: Extracts key fields from maCERT security bulletins:
  - Title
  - Reference number
  - Publication date
  - Risk level (Critique, Important, Modéré, Faible)
  - Impact assessment
  - Affected systems
  - CVE identifiers
  - Description and solution
  - External references

- **IOC Extraction**: Automatically extracts Indicators of Compromise from malware reports:
  - IP addresses (IPv4)
  - Domain names
  - File hashes (MD5, SHA1, SHA256)
  - File paths (Windows paths)
  - Malicious URLs

- **MISP Integration**: Creates properly structured MISP events with:
  - Vulnerability objects for each CVE
  - IP-port objects for C2 IPs
  - Domain-IP objects for malicious domains
  - File objects for malware hashes
  - Security advisory details
  - Automatic tagging (TLP, severity, source, type)

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd macert2misp

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Set your MISP credentials either via environment variables or command line arguments:

```bash
# Option 1: Environment variables
export MISP_URL="https://your-misp-instance.example.com"
export MISP_KEY="your-api-key-here"

# Option 2: Create a .env file (copy from example)
cp .env.example .env
# Edit .env with your credentials
```

## Usage

### Basic Usage

```bash
# Parse PDFs and push to MISP
python ingest.py

# Dry run (parse only, don't push to MISP)
python ingest.py --dry-run

# Specify custom docs folder
python ingest.py --docs-folder /path/to/pdfs

# Auto-publish events after creation
python ingest.py --publish
```

### Full Options

```bash
python ingest.py --help

Options:
  -d, --docs-folder     Folder containing PDF bulletins (default: docs)
  -u, --misp-url        MISP instance URL (or set MISP_URL env var)
  -k, --misp-key        MISP API key (or set MISP_KEY env var)
  --no-verify-ssl       Disable SSL certificate verification
  -p, --publish         Automatically publish events after creation
  --dry-run             Parse PDFs but do not push to MISP
  -v, --verbose         Enable verbose output
```

### Example

```bash
# Place maCERT PDF bulletins in the docs folder
mkdir -p docs
# Copy your PDF files to docs/

# Test parsing without pushing to MISP
python ingest.py --dry-run -v

# Push to MISP
python ingest.py --misp-url https://misp.example.com --misp-key YOUR_API_KEY
```

## MISP Event Structure

Each bulletin creates a MISP event with:

| Component | Description |
|-----------|-------------|
| **Event Info** | `[maCERT] <Title> - <Reference>` |
| **Threat Level** | Mapped from risk level (Critique→High, Important→Medium, etc.) |
| **Tags** | `tlp:green`, `type:vulnerability|malware|ioc`, `source:maCERT`, `severity:<level>` |
| **Vulnerability Objects** | One per CVE with ID, summary, and references |
| **IP-Port Objects** | C2 IP addresses (for malware reports) |
| **Domain-IP Objects** | Malicious domains (for malware reports) |
| **File Objects** | Malware hashes with type (MD5/SHA1/SHA256) |
| **Attributes** | Affected systems, external links, file paths, reference number |

## Supported PDF Formats

### Vulnerability Bulletins

```
BULLETIN DE SECURITE
Titre               <Vulnerability Title>
Numéro de Référence <Reference ID>
Date de Publication <DD Month YYYY>
Risque              <Important|Critique|Modéré|Faible>
Impact              <Impact Level>

Systèmes affectés
• <System 1>
• <System 2>

Identificateurs externes
• CVE-YYYY-NNNNN

Bilan de la vulnérabilité
<Description>

Solution
<Remediation steps>

Risque
• <Risk 1>
• <Risk 2>

Références
<URLs>
```

### Malware Reports with IOCs

```
NOTE DE SECURITE
Titre               <Malware Name>
Numéro de Référence <Reference ID>
Date de Publication <DD Month YYYY>
Risque              <Critique|Important>
Impact              <Impact Level>

<Description of the malware>

Indicateurs de compromission (IOCs):

IP :
- 1.2.3.4
- 5.6.7.8

Domains :
- malicious-domain.com
- evil-site.net

File paths:
- %TEMP%\malware.exe
- %WinDir%\System32\backdoor.dll

Hashs :
- <SHA256 hashes>
- <MD5 hashes>
```

Références
<URLs>
```

## License

MIT