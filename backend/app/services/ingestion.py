import requests
import json
import csv
import io
from typing import List, Dict, Any
from datetime import datetime, timedelta
import re
from ..config import settings
from ..models.models import ThreatIOC, ThreatInput, BulkIngestionJob, AccountThreatMapping, ThreatLifecycle
from ..db.session import SessionLocal
from .ai_classification import AIClassificationService, ai_service
from .correlation import CorrelationService

class ThreatIngestionService:
    """Service for ingesting threat intelligence from various OSINT sources."""
    
    def __init__(self):
        self.sources = {
            "alienvault_otx": {
                "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
                "headers": {"X-OTX-API-KEY": settings.otx_api_key} if settings.otx_api_key else {}
            },
            "abuseipdb": {
                "url": "https://api.abuseipdb.com/api/v1/blacklist",
                "headers": {"Key": settings.abuseipdb_api_key} if settings.abuseipdb_api_key else {}
            }
        }
    
    def fetch_alienvault_pulses(self) -> List[Dict[str, Any]]:
        """Fetch pulses from AlienVault OTX."""
        if not settings.otx_api_key:
            return []
        
        try:
            response = requests.get(
                self.sources["alienvault_otx"]["url"],
                headers=self.sources["alienvault_otx"]["headers"],
                params={"limit": 50}
            )
            response.raise_for_status()
            data = response.json()
            
            iocs = []
            for pulse in data.get("results", []):
                for indicator in pulse.get("indicators", []):
                    ioc_data = {
                        "type": self._normalize_indicator_type(indicator.get("type")),
                        "value": indicator.get("indicator"),
                        "source": "AlienVault OTX",
                        "first_seen": pulse.get("created"),
                        "last_seen": pulse.get("modified")
                    }
                    if ioc_data["type"] and ioc_data["value"]:
                        iocs.append(ioc_data)
            
            return iocs
        except Exception as e:
            print(f"Error fetching from AlienVault OTX: {e}")
            return []
    
    def fetch_abuseipdb_blacklist(self) -> List[Dict[str, Any]]:
        """Fetch blacklist from AbuseIPDB."""
        if not settings.abuseipdb_api_key:
            return []
        
        try:
            response = requests.get(
                self.sources["abuseipdb"]["url"],
                headers=self.sources["abuseipdb"]["headers"],
                params={"limit": 100}
            )
            response.raise_for_status()
            data = response.json()
            
            iocs = []
            for item in data.get("data", []):
                ioc_data = {
                    "type": "ip",
                    "value": item.get("ipAddress"),
                    "source": "AbuseIPDB",
                    "last_seen": item.get("lastReportedAt")
                }
                iocs.append(ioc_data)
            
            return iocs
        except Exception as e:
            print(f"Error fetching from AbuseIPDB: {e}")
            return []
    
    def _normalize_indicator_type(self, indicator_type: str) -> str:
        """Normalize indicator types to our schema."""
        type_mapping = {
            "IPv4": "ip",
            "IPv6": "ip",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "URI": "url",
            "FileHash-MD5": "hash",
            "FileHash-SHA1": "hash",
            "FileHash-SHA256": "hash"
        }
        return type_mapping.get(indicator_type, indicator_type.lower())
    
    def ingest_all_sources(self) -> int:
        """Ingest IOCs from all configured sources."""
        all_iocs = []
        all_iocs.extend(self.fetch_alienvault_pulses())
        all_iocs.extend(self.fetch_abuseipdb_blacklist())
        
        ingested_count = 0
        db = SessionLocal()
        try:
            for ioc_data in all_iocs:
                # Check if IOC already exists
                existing = db.query(ThreatIOC).filter(
                    ThreatIOC.type == ioc_data["type"],
                    ThreatIOC.value == ioc_data["value"]
                ).first()
                
                if not existing:
                    # Create new IOC
                    db_ioc = ThreatIOC(
                        type=ioc_data["type"],
                        value=ioc_data["value"],
                        source=ioc_data["source"],
                        first_seen=self._parse_datetime(ioc_data.get("first_seen")),
                        last_seen=self._parse_datetime(ioc_data.get("last_seen"))
                    )
                    db.add(db_ioc)
                    ingested_count += 1
            
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error during ingestion: {e}")
        finally:
            db.close()
        
        return ingested_count
    
    def _parse_datetime(self, date_str: str) -> datetime:
        """Parse datetime string to datetime object."""
        if not date_str:
            return None
        try:
            # Try different formats
            for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"]:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
            return None
        except:
            return None

# Global service instance
ingestion_service = ThreatIngestionService()

def normalize_input(value: str, input_type: str = None) -> Dict[str, Any]:
    """Normalize and validate input value."""
    value = value.strip()

    # Auto-detect type if not provided
    if not input_type:
        input_type = detect_indicator_type(value)

    # Validate and normalize based on type
    if input_type == 'ip':
        if not is_valid_ip(value):
            raise ValueError("Invalid IP address")
        normalized = normalize_ip(value)
    elif input_type == 'domain':
        if not is_valid_domain(value):
            raise ValueError("Invalid domain")
        normalized = value.lower()
    elif input_type == 'url':
        if not is_valid_url(value):
            raise ValueError("Invalid URL")
        normalized = normalize_url(value)
    elif input_type == 'hash':
        if not is_valid_hash(value):
            raise ValueError("Invalid hash")
        normalized = value.lower()
    else:
        raise ValueError("Unsupported indicator type")

    return {
        "type": input_type,
        "value": normalized,
        "original": value
    }

def detect_indicator_type(value: str) -> str:
    """Auto-detect indicator type."""
    value = value.strip()

    # IP patterns
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    if ip_pattern.match(value):
        return 'ip'

    # URL patterns
    url_pattern = re.compile(r'^https?://')
    if url_pattern.match(value.lower()):
        return 'url'

    # Hash patterns (MD5, SHA1, SHA256)
    hash_pattern = re.compile(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', re.IGNORECASE)
    if hash_pattern.match(value):
        return 'hash'

    # Domain pattern (simple check)
    domain_pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    if domain_pattern.match(value):
        return 'domain'

    # Default to domain if not matched
    return 'domain'

def is_valid_ip(value: str) -> bool:
    """Validate IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def normalize_ip(value: str) -> str:
    """Normalize IP address."""
    import ipaddress
    ip = ipaddress.ip_address(value)
    return str(ip)

def is_valid_domain(value: str) -> bool:
    """Validate domain name."""
    if len(value) > 253:
        return False
    domain_pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return bool(domain_pattern.match(value))

def is_valid_url(value: str) -> bool:
    """Validate URL."""
    from urllib.parse import urlparse
    try:
        result = urlparse(value)
        return all([result.scheme, result.netloc])
    except:
        return False

def normalize_url(value: str) -> str:
    """Normalize URL."""
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(value)
    # Normalize scheme to lowercase, remove default ports, etc.
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if ':' in netloc:
        host, port = netloc.rsplit(':', 1)
        if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
            netloc = host
    path = parsed.path.rstrip('/')
    query = parsed.query
    fragment = parsed.fragment
    return urlunparse((scheme, netloc, path, parsed.params, query, fragment))

def is_valid_hash(value: str) -> bool:
    """Validate hash."""
    hash_pattern = re.compile(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', re.IGNORECASE)
    return bool(hash_pattern.match(value))

def process_single_input(threat_input_id: int, db_session):
    """Process a single threat input and return prediction result."""
    prediction_result = None

    try:
        threat_input = db_session.query(ThreatInput).filter(ThreatInput.id == threat_input_id).first()
        if not threat_input:
            return None

        # Normalize
        normalized = normalize_input(threat_input.value, threat_input.type)

        # Update threat_input
        threat_input.value = normalized['value']
        threat_input.status = 'processed'

        # Create or update IOC
        ioc = db_session.query(ThreatIOC).filter(
            ThreatIOC.type == normalized['type'],
            ThreatIOC.value == normalized['value']
        ).first()

        if not ioc:
            ioc = ThreatIOC(
                type=normalized['type'],
                value=normalized['value'],
                source='User Input',
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            db_session.add(ioc)
            db_session.flush()  # Get ID

        # Account mapping
        if threat_input.account_id:
            mapping = AccountThreatMapping(
                account_id=threat_input.account_id,
                ioc_id=ioc.id
            )
            db_session.add(mapping)

        # Lifecycle
        lifecycle = ThreatLifecycle(
            threat_input_id=threat_input.id,
            ioc_id=ioc.id,
            state='new'
        )
        db_session.add(lifecycle)

        # AI Classification
        prediction = ai_service.classify_threat(ioc.id, db_session)
        if prediction:
            db_session.add(prediction)
            db_session.flush()  # Get prediction ID
            prediction_result = {
                'prediction_id': prediction.id,
                'prediction': prediction.prediction,
                'confidence': prediction.confidence,
                'model_name': prediction.model_name,
                'explanation': prediction.explanation,
                'ioc_id': ioc.id,
                'ioc_type': ioc.type,
                'ioc_value': ioc.value
            }

        db_session.commit()
        return prediction_result

    except Exception as e:
        db_session.rollback()
        print(f"Error processing single input {threat_input_id}: {e}")
        return None

def process_bulk_file(job_id: int, db_session):
    """Process bulk ingestion job."""
    try:
        job = db_session.query(BulkIngestionJob).filter(BulkIngestionJob.id == job_id).first()
        if not job:
            return

        job.status = 'processing'
        db_session.commit()

        # Read file
        with open(job.file_path, 'r') as f:
            if job.file_type == 'csv':
                reader = csv.DictReader(f)
                items = list(reader)
            elif job.file_type == 'json':
                data = json.load(f)
                items = data if isinstance(data, list) else [data]

        total = len(items)
        processed = 0

        for item in items:
            try:
                # Assume columns: type, value
                input_type = item.get('type')
                value = item.get('value')
                if not value:
                    continue

                normalized = normalize_input(value, input_type)

                # Create threat input
                threat_input = ThreatInput(
                    type=normalized['type'],
                    value=normalized['value'],
                    user_id=job.user_id,
                    status='processed'
                )
                db_session.add(threat_input)
                db_session.flush()

                # Process like single
                process_single_input(threat_input.id, db_session)

                processed += 1
                job.processed_items = processed
                db_session.commit()

            except Exception as e:
                print(f"Error processing item: {e}")
                continue

        job.status = 'completed' if processed == total else 'completed'  # or partial
        job.total_items = total
        db_session.commit()

    except Exception as e:
        db_session.rollback()
        job.status = 'failed'
        job.error_message = str(e)
        db_session.commit()
        print(f"Error processing bulk job {job_id}: {e}")