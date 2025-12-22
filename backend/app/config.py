from pydantic_settings import BaseSettings
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # Environment
    backend_env: str = "development"
    api_base_path: str = "/api"
    
    # JWT
    secret_key: str = "your_secret_key_here"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    
    # MySQL Database
    mysql_host: str = "localhost"
    mysql_port: int = 3306
    mysql_user: str = "cti_user"
    mysql_password: str = "cti_password"
    mysql_database: str = "cti_dashboard"
    
    # Optional Caching
    redis_host: Optional[str] = "localhost"
    redis_port: Optional[int] = 6379
    
    # Optional Search
    elasticsearch_url: Optional[str] = "http://localhost:9200"
    
    # API Keys for Enrichment
    virustotal_api_key: Optional[str] = "your_virustotal_key"
    abuseipdb_api_key: Optional[str] = "your_abuseipdb_key"
    otx_api_key: Optional[str] = "your_alienvault_otx_key"

    # AI and ML Configuration
    default_lifecycle_state: str = "new"
    ai_inference_mode: str = "local"
    model_storage_path: str = "./models"
    ai_model_auto_load: bool = True
    huggingface_api_key: Optional[str] = None
    database_url: Optional[str] = None
    jwt_secret_key: str = "your_secret_key_here"

    kaggle_dataset_path: Optional[str] = "./datasets"
    dataset_base_path: Optional[str] = "./datasets"
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()