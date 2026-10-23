"""
Prowler IASM Database Layer.
Provides MongoDB connection management, document models, compound indexes, and repository access.
"""

from .mongo import (
    connect_to_mongo,
    close_mongo_connection,
    get_async_db,
    get_sync_db,
    is_mongo_connected,
    mongo_manager,
)
from .indexes import ensure_indexes, ensure_indexes_sync
from .models import (
    CloudAccountModel,
    TenantModel,
    ScanKPIsModel,
    ScanModel,
    FindingModel,
    AssetModel,
    ComplianceSummaryModel,
    MuteRuleModel,
)
from .repository import (
    TenantRepository,
    ScanRepository,
    FindingRepository,
    AssetRepository,
    ComplianceRepository,
    MuteRuleRepository,
    FINDINGS_PROJECTION,
    ASSETS_PROJECTION,
)

__all__ = [
    "connect_to_mongo",
    "close_mongo_connection",
    "get_async_db",
    "get_sync_db",
    "is_mongo_connected",
    "mongo_manager",
    "ensure_indexes",
    "ensure_indexes_sync",
    "CloudAccountModel",
    "TenantModel",
    "ScanKPIsModel",
    "ScanModel",
    "FindingModel",
    "AssetModel",
    "ComplianceSummaryModel",
    "MuteRuleModel",
    "TenantRepository",
    "ScanRepository",
    "FindingRepository",
    "AssetRepository",
    "ComplianceRepository",
    "MuteRuleRepository",
    "FINDINGS_PROJECTION",
    "ASSETS_PROJECTION",
]
