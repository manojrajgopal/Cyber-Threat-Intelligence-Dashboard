import requests
import json
from typing import List, Dict, Any
from datetime import datetime, timedelta
from ..config import settings
from ..models.models import ThreatIOC
from ..db.session import SessionLocal

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