import requests
import socket
import json
from typing import Dict, Any, Optional
from ..config import settings
from ..models.models import ThreatIOC, IOCEnrichment
from ..db.session import SessionLocal

class IOCEnrichmentService:
    """Service for enriching IOCs with additional intelligence."""
    
    def __init__(self):
        self.services = {
            "virustotal": {
                "url": "https://www.virustotal.com/api/v3/",
                "headers": {"x-apikey": settings.virustotal_api_key} if settings.virustotal_api_key else {}
            }
        }
    
    def enrich_ioc(self, ioc_id: int, db_session = None):
        """Enrich a specific IOC."""
        db = db_session or SessionLocal()
        try:
            ioc = db.query(ThreatIOC).filter(ThreatIOC.id == ioc_id).first()
            if not ioc:
                return
            
            enrichment_data = {}
            
            if ioc.type == "ip":
                enrichment_data.update(self._enrich_ip(ioc.value))
            elif ioc.type == "domain":
                enrichment_data.update(self._enrich_domain(ioc.value))
            elif ioc.type == "hash":
                enrichment_data.update(self._enrich_hash(ioc.value))
            
            # Store enrichment data
            for enrichment_type, data in enrichment_data.items():
                if data:
                    db_enrichment = IOCEnrichment(
                        ioc_id=ioc_id,
                        enrichment_type=enrichment_type,
                        data=data
                    )
                    db.add(db_enrichment)
            
            # Calculate and update risk score
            risk_score = self.calculate_risk_score(ioc)
            ioc.risk_score = risk_score
            
            # Update IOC enrichment status
            ioc.enriched = True
            db.commit()
            
        except Exception as e:
            if db_session is None:
                db.rollback()
            print(f"Error enriching IOC {ioc_id}: {e}")
        finally:
            if db_session is None:
                db.close()
    
    def _enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP address with geolocation and reputation."""
        enrichment = {}
        
        # Basic geolocation using ip-api.com (free)
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                geo_data = response.json()
                if geo_data.get("status") == "success":
                    enrichment["geolocation"] = {
                        "country": geo_data.get("country"),
                        "country_code": geo_data.get("countryCode"),
                        "region": geo_data.get("regionName"),
                        "city": geo_data.get("city"),
                        "lat": geo_data.get("lat"),
                        "lon": geo_data.get("lon"),
                        "isp": geo_data.get("isp"),
                        "org": geo_data.get("org")
                    }
        except Exception as e:
            print(f"Error getting geolocation for {ip}: {e}")
        
        # VirusTotal reputation
        if settings.virustotal_api_key:
            try:
                vt_url = f"{self.services['virustotal']['url']}ip_addresses/{ip}"
                response = requests.get(vt_url, headers=self.services['virustotal']['headers'], timeout=10)
                if response.status_code == 200:
                    vt_data = response.json()
                    attributes = vt_data.get("data", {}).get("attributes", {})
                    enrichment["virustotal"] = {
                        "reputation": attributes.get("reputation", 0),
                        "total_votes": attributes.get("total_votes", {}),
                        "last_analysis_stats": attributes.get("last_analysis_stats", {})
                    }
            except Exception as e:
                print(f"Error getting VT data for {ip}: {e}")
        
        return enrichment
    
    def _enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with WHOIS and reputation."""
        enrichment = {}
        
        # Basic WHOIS-like info
        try:
            ip = socket.gethostbyname(domain)
            enrichment["resolved_ip"] = ip
            # Get geolocation for resolved IP
            enrichment.update(self._enrich_ip(ip))
        except socket.gaierror:
            enrichment["resolved_ip"] = None
        
        # VirusTotal domain report
        if settings.virustotal_api_key:
            try:
                vt_url = f"{self.services['virustotal']['url']}domains/{domain}"
                response = requests.get(vt_url, headers=self.services['virustotal']['headers'], timeout=10)
                if response.status_code == 200:
                    vt_data = response.json()
                    attributes = vt_data.get("data", {}).get("attributes", {})
                    enrichment["virustotal"] = {
                        "reputation": attributes.get("reputation", 0),
                        "total_votes": attributes.get("total_votes", {}),
                        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                        "categories": attributes.get("categories", {})
                    }
            except Exception as e:
                print(f"Error getting VT data for {domain}: {e}")
        
        return enrichment
    
    def _enrich_hash(self, hash_value: str) -> Dict[str, Any]:
        """Enrich file hash with reputation."""
        enrichment = {}
        
        # VirusTotal file report
        if settings.virustotal_api_key:
            try:
                vt_url = f"{self.services['virustotal']['url']}files/{hash_value}"
                response = requests.get(vt_url, headers=self.services['virustotal']['headers'], timeout=10)
                if response.status_code == 200:
                    vt_data = response.json()
                    attributes = vt_data.get("data", {}).get("attributes", {})
                    enrichment["virustotal"] = {
                        "reputation": attributes.get("reputation", 0),
                        "total_votes": attributes.get("total_votes", {}),
                        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                        "names": attributes.get("names", []),
                        "type_description": attributes.get("type_description")
                    }
            except Exception as e:
                print(f"Error getting VT data for {hash_value}: {e}")
        
        return enrichment
    
    def calculate_risk_score(self, ioc: ThreatIOC) -> float:
        """Calculate risk score based on enrichment data."""
        score = 0.0
        
        for enrichment in ioc.enrichments:
            if enrichment.enrichment_type == "virustotal":
                vt_data = enrichment.data
                if isinstance(vt_data, dict):
                    # Higher malicious detections increase score
                    malicious = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
                    total = sum(vt_data.get("last_analysis_stats", {}).values())
                    if total > 0:
                        score += (malicious / total) * 0.8
                    
                    # Reputation affects score
                    reputation = vt_data.get("reputation", 0)
                    if reputation < 0:
                        score += min(abs(reputation) / 100, 0.5)
            
            elif enrichment.enrichment_type == "geolocation":
                # Certain countries might increase risk
                geo_data = enrichment.data
                if isinstance(geo_data, dict):
                    high_risk_countries = ["RU", "CN", "IR", "KP"]  # Example
                    if geo_data.get("country_code") in high_risk_countries:
                        score += 0.2
        
        return min(score, 1.0)  # Cap at 1.0

def enrich_ioc(ioc_id: int, db_session=None):
    return enrichment_service.enrich_ioc(ioc_id, db_session)

# Global service instance
enrichment_service = IOCEnrichmentService()