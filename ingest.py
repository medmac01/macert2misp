#!/usr/bin/env python3
"""
maCERT to MISP Ingestor
=======================
Parses French CVE vulnerability report PDFs from maCERT (Morocco CERT)
and pushes them to a MISP instance as events with proper objects.
"""

import os
import re
import glob
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

import pdfplumber
from pymisp import PyMISP, MISPEvent, MISPObject, MISPAttribute

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class IOCData:
    """Indicators of Compromise extracted from maCERT PDF."""
    ips: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    file_paths: list = field(default_factory=list)
    hashes: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    
    def has_iocs(self) -> bool:
        """Check if any IOCs were found."""
        return bool(self.ips or self.domains or self.file_paths or self.hashes or self.urls)
    
    def total_count(self) -> int:
        """Return total number of IOCs."""
        return len(self.ips) + len(self.domains) + len(self.file_paths) + len(self.hashes) + len(self.urls)


@dataclass
class VulnerabilityReport:
    """Parsed vulnerability report from maCERT PDF."""
    title: str = ""
    reference: str = ""
    publication_date: Optional[datetime] = None
    risk_level: str = ""
    impact: str = ""
    affected_systems: list = field(default_factory=list)
    cve_ids: list = field(default_factory=list)
    description: str = ""
    solution: str = ""
    risks: list = field(default_factory=list)
    external_references: list = field(default_factory=list)
    iocs: IOCData = field(default_factory=IOCData)
    raw_text: str = ""
    source_file: str = ""
    report_type: str = "vulnerability"  # vulnerability or malware


class MaCERTParser:
    """Parser for maCERT vulnerability bulletin PDFs."""
    
    # French month mapping
    FRENCH_MONTHS = {
        'janvier': 1, 'février': 2, 'mars': 3, 'avril': 4,
        'mai': 5, 'juin': 6, 'juillet': 7, 'août': 8,
        'septembre': 9, 'octobre': 10, 'novembre': 11, 'décembre': 12
    }
    
    def __init__(self, docs_folder: str = "docs"):
        self.docs_folder = docs_folder
    
    def parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse French date format like '24 Décembre 2025'."""
        try:
            # Pattern: DD Month YYYY
            match = re.search(r'(\d{1,2})\s+(\w+)\s+(\d{4})', date_str, re.IGNORECASE)
            if match:
                day = int(match.group(1))
                month_name = match.group(2).lower()
                year = int(match.group(3))
                
                month = self.FRENCH_MONTHS.get(month_name)
                if month:
                    return datetime(year, month, day)
        except Exception as e:
            logger.warning(f"Could not parse date '{date_str}': {e}")
        return None
    
    def extract_field(self, text: str, field_name: str, next_field: str = None) -> str:
        """Extract a field value from the text."""
        pattern = rf'{field_name}\s+(.*?)(?={next_field}|$)' if next_field else rf'{field_name}\s+(.*?)$'
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return ""
    
    def extract_cves(self, text: str) -> list:
        """Extract all CVE identifiers from text."""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return list(set(re.findall(cve_pattern, text, re.IGNORECASE)))
    
    def extract_urls(self, text: str) -> list:
        """Extract all URLs from text."""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return list(set(re.findall(url_pattern, text)))
    
    def extract_ips(self, text: str) -> list:
        """Extract IPv4 addresses from text."""
        # Match IPv4 addresses, excluding common false positives
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, text)
        # Filter out version numbers and other non-IP patterns
        valid_ips = [ip for ip in ips if not self._is_version_number(ip, text)]
        return list(set(valid_ips))
    
    def _is_version_number(self, ip: str, text: str) -> bool:
        """Check if an IP-like string is actually a version number."""
        # Look for context around the IP that suggests it's a version
        version_contexts = ['version', 'v' + ip, 'Version', ip + ' ;']
        for ctx in version_contexts:
            if ctx in text:
                idx = text.find(ip)
                if idx > 0:
                    before = text[max(0, idx-20):idx].lower()
                    if 'version' in before or before.rstrip().endswith('v'):
                        return True
        return False
    
    def extract_domains(self, text: str) -> list:
        """Extract domain names from text."""
        # Match domains (excluding common false positives)
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|biz|info|xyz|me|cc|top|live|online|site|club|shop|app|dev|io|co|uk|sg|mx|ua|to|zapto)\b'
        domains = re.findall(domain_pattern, text, re.IGNORECASE)
        # Filter out email domains and known safe domains
        safe_domains = {'macert.gov.ma', 'example.com'}
        return list(set(d.lower() for d in domains if d.lower() not in safe_domains))
    
    def extract_hashes(self, text: str) -> list:
        """Extract file hashes (MD5, SHA1, SHA256) from text."""
        hashes = []
        # SHA256 (64 hex chars)
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        hashes.extend([('sha256', h.lower()) for h in re.findall(sha256_pattern, text)])
        # SHA1 (40 hex chars)
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha1_matches = re.findall(sha1_pattern, text)
        # Filter out SHA256 substrings
        sha256_set = set(h[1] for h in hashes)
        for h in sha1_matches:
            if not any(h.lower() in s for s in sha256_set):
                hashes.append(('sha1', h.lower()))
        # MD5 (32 hex chars)
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        md5_matches = re.findall(md5_pattern, text)
        existing = set(h[1] for h in hashes)
        for h in md5_matches:
            if h.lower() not in existing and not any(h.lower() in s for s in existing):
                hashes.append(('md5', h.lower()))
        return list(set(hashes))
    
    def extract_file_paths(self, text: str) -> list:
        """Extract Windows file paths from text."""
        paths = []
        # Windows paths with environment variables
        win_path_pattern = r'%[A-Za-z]+%(?:\\[^\s\n,;]+)+'
        paths.extend(re.findall(win_path_pattern, text))
        # Standard Windows paths
        std_path_pattern = r'[A-Z]:\\(?:[^\s\n,;\\]+\\)*[^\s\n,;\\]+'
        paths.extend(re.findall(std_path_pattern, text))
        return list(set(paths))
    
    def extract_iocs_from_section(self, text: str) -> IOCData:
        """Extract IOCs from the IOC section of the document."""
        iocs = IOCData()
        
        # Find IOC section
        ioc_section_match = re.search(
            r'Indicateurs de compromission.*?(?:IOCs?)?\s*:?\s*(.*)$',
            text, re.IGNORECASE | re.DOTALL
        )
        
        if not ioc_section_match:
            # No IOC section, try extracting from full text
            return iocs
        
        ioc_text = ioc_section_match.group(1)
        
        # Extract IPs from IP section
        ip_section = re.search(r'IP\s*:\s*(.+?)(?=Domains?\s*:|File paths?\s*:|Hashs?\s*:|URLs?\s*:|$)', 
                               ioc_text, re.IGNORECASE | re.DOTALL)
        if ip_section:
            iocs.ips = self.extract_ips(ip_section.group(1))
        
        # Extract Domains from Domain section
        domain_section = re.search(r'Domains?\s*:\s*(.+?)(?=IP\s*:|File paths?\s*:|Hashs?\s*:|URLs?\s*:|$)', 
                                   ioc_text, re.IGNORECASE | re.DOTALL)
        if domain_section:
            # Extract domains line by line (they're listed with - prefix)
            domain_text = domain_section.group(1)
            domain_lines = re.findall(r'-\s*([^\s\n]+)', domain_text)
            iocs.domains = list(set(d.strip() for d in domain_lines if '.' in d))
        
        # Extract File paths
        filepath_section = re.search(r'File paths?\s*:\s*(.+?)(?=IP\s*:|Domains?\s*:|Hashs?\s*:|URLs?\s*:|$)', 
                                     ioc_text, re.IGNORECASE | re.DOTALL)
        if filepath_section:
            iocs.file_paths = self.extract_file_paths(filepath_section.group(1))
        
        # Extract Hashes
        hash_section = re.search(r'Hashs?\s*:\s*(.+?)(?=IP\s*:|Domains?\s*:|File paths?\s*:|URLs?\s*:|$)', 
                                 ioc_text, re.IGNORECASE | re.DOTALL)
        if hash_section:
            iocs.hashes = self.extract_hashes(hash_section.group(1))
        
        # Extract URLs from URL section (if present)
        url_section = re.search(r'URLs?\s*:\s*(.+?)(?=IP\s*:|Domains?\s*:|File paths?\s*:|Hashs?\s*:|$)', 
                                ioc_text, re.IGNORECASE | re.DOTALL)
        if url_section:
            iocs.urls = self.extract_urls(url_section.group(1))
        
        return iocs
    
    def extract_list_items(self, text: str, start_marker: str, end_marker: str = None) -> list:
        """Extract bullet point items from a section."""
        # Find the section
        if end_marker:
            pattern = rf'{start_marker}(.*?){end_marker}'
        else:
            pattern = rf'{start_marker}(.*?)(?=\n[A-Z]|\Z)'
        
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            section = match.group(1)
            # Extract items marked with bullets or semicolons
            items = re.findall(r'[•\-]\s*([^•\-\n;]+)', section)
            if not items:
                # Try splitting by semicolons or newlines
                items = [item.strip() for item in re.split(r'[;\n]', section) if item.strip()]
            return [item.strip().rstrip(';') for item in items if item.strip()]
        return []
    
    def parse_pdf(self, pdf_path: str) -> VulnerabilityReport:
        """Parse a single PDF file and extract vulnerability information."""
        report = VulnerabilityReport()
        report.source_file = os.path.basename(pdf_path)
        
        logger.info(f"Parsing: {pdf_path}")
        
        try:
            with pdfplumber.open(pdf_path) as pdf:
                full_text = ""
                for page in pdf.pages:
                    text = page.extract_text() or ""
                    full_text += text + "\n"
                
                report.raw_text = full_text
                
                # Extract Title (handle multi-line)
                title_match = re.search(r'Titre\s+(.+?)(?=Numéro de Référence)', full_text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    # Clean up title - remove newlines and extra spaces
                    title = title_match.group(1).strip()
                    title = re.sub(r'\s+', ' ', title)
                    report.title = title
                
                # Extract Reference Number
                ref_match = re.search(r'Numéro de Référence\s+(\S+)', full_text, re.IGNORECASE)
                if ref_match:
                    report.reference = ref_match.group(1).strip()
                
                # Extract Publication Date
                date_match = re.search(r'Date de Publication\s+(\d{1,2}\s+\w+\s+\d{4})', full_text, re.IGNORECASE)
                if date_match:
                    report.publication_date = self.parse_date(date_match.group(1).strip())
                
                # Extract Risk Level
                risk_match = re.search(r'^Risque\s+(\w+)', full_text, re.IGNORECASE | re.MULTILINE)
                if risk_match:
                    report.risk_level = risk_match.group(1).strip()
                
                # Extract Impact
                impact_match = re.search(r'^Impact\s+(\w+)', full_text, re.IGNORECASE | re.MULTILINE)
                if impact_match:
                    report.impact = impact_match.group(1).strip()
                
                # Extract Affected Systems
                systems_match = re.search(r'Systèmes affectés\s*(.*?)(?=Identificateurs|$)', full_text, re.IGNORECASE | re.DOTALL)
                if systems_match:
                    systems_text = systems_match.group(1)
                    # Split by bullet points or semicolons
                    systems = re.findall(r'[•]\s*([^•\n]+)', systems_text)
                    if not systems:
                        systems = [s.strip() for s in systems_text.split(';') if s.strip()]
                    report.affected_systems = [s.strip().rstrip(';') for s in systems if s.strip()]
                
                # Extract CVE identifiers
                report.cve_ids = self.extract_cves(full_text)
                
                # Extract Description (Bilan de la vulnérabilité)
                desc_match = re.search(r'Bilan de la vulnérabilité\s*(.*?)(?=Solution|$)', full_text, re.IGNORECASE | re.DOTALL)
                if desc_match:
                    report.description = desc_match.group(1).strip()
                
                # Extract Solution
                sol_match = re.search(r'Solution\s*(.*?)(?=Risque|$)', full_text, re.IGNORECASE | re.DOTALL)
                if sol_match:
                    report.solution = sol_match.group(1).strip()
                
                # Extract Risks list
                risks_match = re.search(r'Risque\s*\n(.*?)(?=Références|$)', full_text, re.IGNORECASE | re.DOTALL)
                if risks_match:
                    risks_text = risks_match.group(1)
                    risks = re.findall(r'[•]\s*([^•\n]+)', risks_text)
                    report.risks = [r.strip().rstrip(';') for r in risks if r.strip()]
                
                # Extract References (URLs) - only from references section, not IOCs
                refs_section = re.search(r'Références\s*(.+?)(?=Indicateurs|Direction Générale|$)', full_text, re.IGNORECASE | re.DOTALL)
                if refs_section:
                    report.external_references = self.extract_urls(refs_section.group(1))
                else:
                    report.external_references = self.extract_urls(full_text)
                
                # Determine report type based on content
                if 'malware' in full_text.lower() or 'IOC' in full_text or 'Indicateurs de compromission' in full_text:
                    report.report_type = 'malware'
                
                # Extract IOCs if present
                report.iocs = self.extract_iocs_from_section(full_text)
                
                # If no structured IOC section but looks like malware report, try general extraction
                if report.report_type == 'malware' and not report.iocs.has_iocs():
                    # Try extracting from full text
                    report.iocs.ips = self.extract_ips(full_text)
                    report.iocs.hashes = self.extract_hashes(full_text)
                    report.iocs.file_paths = self.extract_file_paths(full_text)
                
                # Also extract description for malware reports (different section name)
                if not report.description:
                    # For malware reports, description might be right after the header
                    desc_match = re.search(r'Impact\s+\w+\s+(.+?)(?=Le maCERT|Indicateurs|Direction Générale)', 
                                          full_text, re.IGNORECASE | re.DOTALL)
                    if desc_match:
                        report.description = desc_match.group(1).strip()
                
        except Exception as e:
            logger.error(f"Error parsing PDF {pdf_path}: {e}")
            raise
        
        return report
    
    def parse_all(self) -> list:
        """Parse all PDF files in the docs folder."""
        pdf_files = glob.glob(os.path.join(self.docs_folder, "*.pdf"))
        reports = []
        
        for pdf_file in pdf_files:
            try:
                report = self.parse_pdf(pdf_file)
                reports.append(report)
                ioc_count = report.iocs.total_count() if report.iocs else 0
                logger.info(f"Successfully parsed: {report.title} ({len(report.cve_ids)} CVEs, {ioc_count} IOCs)")
            except Exception as e:
                logger.error(f"Failed to parse {pdf_file}: {e}")
        
        return reports


class MISPPublisher:
    """Publishes vulnerability reports to MISP."""
    
    # Risk level to MISP threat level mapping
    THREAT_LEVEL_MAP = {
        'critique': 1,      # High
        'critical': 1,
        'important': 2,     # Medium
        'modéré': 3,        # Low
        'moderate': 3,
        'faible': 4,        # Undefined
        'low': 4,
    }
    
    def __init__(self, misp_url: str, misp_key: str, verify_ssl: bool = True):
        """Initialize MISP connection."""
        self.misp = PyMISP(misp_url, misp_key, verify_ssl)
        logger.info(f"Connected to MISP at {misp_url}")
    
    def risk_to_threat_level(self, risk: str) -> int:
        """Convert risk level to MISP threat level."""
        return self.THREAT_LEVEL_MAP.get(risk.lower(), 2)
    
    def create_event(self, report: VulnerabilityReport) -> MISPEvent:
        """Create a MISP event from a vulnerability report."""
        event = MISPEvent()
        
        # Basic event info
        event.info = f"[maCERT] {report.title} - {report.reference}"
        event.threat_level_id = self.risk_to_threat_level(report.risk_level)
        event.analysis = 2  # Completed
        event.distribution = 0  # Your organisation only (adjust as needed)
        
        if report.publication_date:
            event.date = report.publication_date.strftime('%Y-%m-%d')
        
        # Add tags
        event.add_tag('tlp:green')
        event.add_tag('source:maCERT')
        
        # Add type-specific tags
        if report.report_type == 'malware':
            event.add_tag('type:malware')
            if report.iocs.has_iocs():
                event.add_tag('type:ioc')
        else:
            event.add_tag('type:vulnerability')
        
        if report.risk_level:
            event.add_tag(f'severity:{report.risk_level.lower()}')
        
        # Add vulnerability objects for each CVE
        for cve_id in report.cve_ids:
            vuln_obj = MISPObject('vulnerability')
            vuln_obj.add_attribute('id', cve_id)
            vuln_obj.add_attribute('summary', report.description[:65535] if report.description else report.title)
            
            if report.external_references:
                for ref in report.external_references:
                    vuln_obj.add_attribute('references', ref)
            
            event.add_object(vuln_obj)
        
        # Add security advisory object
        advisory_obj = MISPObject('security-playbook')
        advisory_obj.add_attribute('description', f"""
maCERT Security Bulletin: {report.reference}

Title: {report.title}
Risk Level: {report.risk_level}
Impact: {report.impact}

Description:
{report.description}

Solution:
{report.solution}

Affected Systems:
{chr(10).join('- ' + s for s in report.affected_systems)}

Risks:
{chr(10).join('- ' + r for r in report.risks)}
        """.strip())
        event.add_object(advisory_obj)
        
        # Add affected systems as attributes
        for system in report.affected_systems:
            attr = MISPAttribute()
            attr.type = 'text'
            attr.category = 'Payload delivery'
            attr.value = system
            attr.comment = 'Affected system/version'
            event.add_attribute(**attr)
        
        # Add external references
        for url in report.external_references:
            attr = MISPAttribute()
            attr.type = 'link'
            attr.category = 'External analysis'
            attr.value = url
            attr.comment = 'Vendor security bulletin'
            event.add_attribute(**attr)
        
        # Add reference number as internal reference
        if report.reference:
            attr = MISPAttribute()
            attr.type = 'text'
            attr.category = 'Internal reference'
            attr.value = report.reference
            attr.comment = 'maCERT bulletin reference'
            event.add_attribute(**attr)
        
        # Add IOCs if present
        if report.iocs and report.iocs.has_iocs():
            self._add_iocs_to_event(event, report.iocs, report.title)
        
        return event
    
    def _add_iocs_to_event(self, event: MISPEvent, iocs: IOCData, title: str):
        """Add IOC objects and attributes to the MISP event."""
        
        # Add IP addresses
        for ip in iocs.ips:
            # Create network-connection object for each IP
            ip_obj = MISPObject('ip-port')
            ip_obj.add_attribute('ip', ip, to_ids=True, comment=f'C2 IP from {title}')
            event.add_object(ip_obj)
        
        # Add domains
        for domain in iocs.domains:
            domain_obj = MISPObject('domain-ip')
            domain_obj.add_attribute('domain', domain, to_ids=True, comment=f'Malicious domain from {title}')
            event.add_object(domain_obj)
        
        # Add file hashes
        if iocs.hashes:
            for hash_type, hash_value in iocs.hashes:
                file_obj = MISPObject('file')
                file_obj.add_attribute(hash_type, hash_value, to_ids=True, comment=f'Malware hash from {title}')
                event.add_object(file_obj)
        
        # Add file paths as attributes
        for filepath in iocs.file_paths:
            attr = MISPAttribute()
            attr.type = 'filename'
            attr.category = 'Artifacts dropped'
            attr.value = filepath
            attr.to_ids = True
            attr.comment = f'Malware file path from {title}'
            event.add_attribute(**attr)
        
        # Add malicious URLs
        for url in iocs.urls:
            url_obj = MISPObject('url')
            url_obj.add_attribute('url', url, to_ids=True, comment=f'Malicious URL from {title}')
            event.add_object(url_obj)
    
    def publish(self, report: VulnerabilityReport, publish: bool = False) -> dict:
        """Create and push a MISP event for a vulnerability report."""
        try:
            event = self.create_event(report)
            result = self.misp.add_event(event, pythonify=True)
            
            # Handle different response formats
            event_id = None
            
            if isinstance(result, MISPEvent):
                # PyMISP returns a MISPEvent object when pythonify=True
                event_id = result.id
            elif isinstance(result, dict):
                if 'errors' in result:
                    logger.error(f"MISP error: {result['errors']}")
                    return result
                if 'Event' in result:
                    event_id = result['Event'].get('id')
                elif 'id' in result:
                    event_id = result.get('id')
                # Check if we got the API description page (wrong URL/protocol)
                if 'url' in result and '/events/add' in result.get('url', ''):
                    logger.error("MISP returned API description. Check your URL (use https:// instead of http://)")
                    return {'errors': 'Wrong protocol or URL - MISP returned API description instead of event'}
            
            if event_id:
                logger.info(f"Created MISP event {event_id}: {report.title}")
            else:
                logger.warning(f"Event may have been created but could not determine ID for: {report.title}")
            
            # Optionally publish the event
            if publish and event_id:
                self.misp.publish(event_id)
                logger.info(f"Published MISP event {event_id}")
            
            return {'Event': {'id': event_id}, 'success': True}
            
        except Exception as e:
            logger.error(f"Failed to publish to MISP: {e}")
            raise


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Ingest maCERT vulnerability bulletins into MISP'
    )
    parser.add_argument(
        '--docs-folder', '-d',
        default='docs',
        help='Folder containing PDF bulletins (default: docs)'
    )
    parser.add_argument(
        '--misp-url', '-u',
        default=os.environ.get('MISP_URL'),
        help='MISP instance URL (or set MISP_URL env var)'
    )
    parser.add_argument(
        '--misp-key', '-k',
        default=os.environ.get('MISP_KEY'),
        help='MISP API key (or set MISP_KEY env var)'
    )
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification'
    )
    parser.add_argument(
        '--publish', '-p',
        action='store_true',
        help='Automatically publish events after creation'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Parse PDFs but do not push to MISP'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse all PDFs
    pdf_parser = MaCERTParser(args.docs_folder)
    reports = pdf_parser.parse_all()
    
    if not reports:
        logger.warning("No PDF reports found to process")
        return
    
    logger.info(f"Parsed {len(reports)} reports")
    
    # Display parsed data
    for report in reports:
        print(f"\n{'='*60}")
        print(f"Title:       {report.title}")
        print(f"Type:        {report.report_type.upper()}")
        print(f"Reference:   {report.reference}")
        print(f"Date:        {report.publication_date}")
        print(f"Risk:        {report.risk_level}")
        print(f"Impact:      {report.impact}")
        if report.cve_ids:
            print(f"CVEs:        {', '.join(report.cve_ids)}")
        if report.affected_systems:
            print(f"Systems:     {len(report.affected_systems)} affected")
        if report.external_references:
            print(f"References:  {len(report.external_references)} URLs")
        
        # Display IOC summary
        if report.iocs and report.iocs.has_iocs():
            print(f"\n  IOCs ({report.iocs.total_count()} total):")
            if report.iocs.ips:
                print(f"    IPs:         {len(report.iocs.ips)}")
            if report.iocs.domains:
                print(f"    Domains:     {len(report.iocs.domains)}")
            if report.iocs.hashes:
                print(f"    Hashes:      {len(report.iocs.hashes)}")
            if report.iocs.file_paths:
                print(f"    File Paths:  {len(report.iocs.file_paths)}")
            if report.iocs.urls:
                print(f"    URLs:        {len(report.iocs.urls)}")
        print(f"{'='*60}")
    
    if args.dry_run:
        logger.info("Dry run - skipping MISP upload")
        return
    
    # Validate MISP credentials
    if not args.misp_url or not args.misp_key:
        logger.error("MISP URL and API key are required. Use --misp-url and --misp-key or set MISP_URL and MISP_KEY environment variables.")
        return
    
    # Publish to MISP
    publisher = MISPPublisher(
        args.misp_url,
        args.misp_key,
        verify_ssl=not args.no_verify_ssl
    )
    
    for report in reports:
        try:
            result = publisher.publish(report, publish=args.publish)
            # Handle different response formats
            event_id = None
            if isinstance(result, dict) and 'Event' in result:
                event_id = result['Event'].get('id')
            elif hasattr(result, 'id'):
                event_id = result.id
            
            if event_id:
                print(f"✓ Created event {event_id}: {report.title}")
            elif 'errors' in result if isinstance(result, dict) else False:
                print(f"✗ Failed to create event for: {report.title} - {result.get('errors')}")
            else:
                print(f"? Event created but ID unknown: {report.title}")
        except Exception as e:
            print(f"✗ Error processing {report.title}: {e}")


if __name__ == "__main__":
    main()
