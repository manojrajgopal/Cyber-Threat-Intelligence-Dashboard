from fastapi import APIRouter
from .routes import auth, users, iocs, alerts, dashboard, reports, ingestion, ai, correlation_api, lifecycle, account, risk

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(iocs.router, prefix="/iocs", tags=["iocs"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(risk.router, prefix="/risk", tags=["risk"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(ingestion.router, prefix="/ingestion", tags=["ingestion"])
api_router.include_router(ai.router, prefix="/ai", tags=["ai"])
api_router.include_router(correlation_api.router, prefix="/correlation", tags=["correlation"])
api_router.include_router(lifecycle.router, prefix="/lifecycle", tags=["lifecycle"])
api_router.include_router(account.router, prefix="/account", tags=["account"])