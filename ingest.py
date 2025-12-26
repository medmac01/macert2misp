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
    raw_text: str = ""
    source_file: str = ""


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
                
                # Extract References (URLs)
                report.external_references = self.extract_urls(full_text)
                
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
                logger.info(f"Successfully parsed: {report.title} ({len(report.cve_ids)} CVEs)")
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
        event.add_tag('type:vulnerability')
        event.add_tag('source:maCERT')
        
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
        
        return event
    
    def publish(self, report: VulnerabilityReport, publish: bool = False) -> dict:
        """Create and push a MISP event for a vulnerability report."""
        try:
            event = self.create_event(report)
            result = self.misp.add_event(event)
            
            if 'errors' in result:
                logger.error(f"MISP error: {result['errors']}")
                return result
            
            event_id = result['Event']['id']
            logger.info(f"Created MISP event {event_id}: {report.title}")
            
            # Optionally publish the event
            if publish:
                self.misp.publish(event_id)
                logger.info(f"Published MISP event {event_id}")
            
            return result
            
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
    
    logger.info(f"Parsed {len(reports)} vulnerability reports")
    
    # Display parsed data
    for report in reports:
        print(f"\n{'='*60}")
        print(f"Title:       {report.title}")
        print(f"Reference:   {report.reference}")
        print(f"Date:        {report.publication_date}")
        print(f"Risk:        {report.risk_level}")
        print(f"Impact:      {report.impact}")
        print(f"CVEs:        {', '.join(report.cve_ids)}")
        print(f"Systems:     {len(report.affected_systems)} affected")
        print(f"References:  {len(report.external_references)} URLs")
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
            if 'Event' in result:
                print(f"✓ Created event {result['Event']['id']}: {report.title}")
            else:
                print(f"✗ Failed to create event for: {report.title}")
        except Exception as e:
            print(f"✗ Error processing {report.title}: {e}")


if __name__ == "__main__":
    main()
