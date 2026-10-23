"""
Automated MongoDB Index Management for Prowler IASM.
Configures compound B-tree indexes, 30-day TTL auto-purge retention indexes,
text search indexes, and unique constraints.
"""

import logging
import os
from typing import Any

logger = logging.getLogger("prowler_iasm_db")

# Retention policy in days. Default is 0 (permanent retention, no auto-wiping).
SCAN_RETENTION_DAYS = int(os.getenv("SCAN_RETENTION_DAYS", "0"))


async def ensure_indexes(db: Any):
    """
    Asynchronously creates all performance and retention indexes across collections.
    Designed for idempotent execution on application startup.
    """
    if db is None:
        return

    try:
        logger.info("[MongoDB-Indexes] Verifying database indexes...")

        # 1. Findings Collection Indexes
        f_coll = db["findings"]
        await f_coll.create_index(
            [("tenant_id", 1), ("scan_id", 1), ("status", 1), ("severity", 1), ("service", 1)],
            name="idx_findings_compound_query",
            background=True,
        )
        await f_coll.create_index(
            [("tenant_id", 1), ("scan_id", 1), ("resource_id", 1)],
            name="idx_findings_resource_lookup",
            background=True,
        )
        await f_coll.create_index(
            [("tenant_id", 1), ("check_id", 1), ("resource_id", 1)],
            name="idx_findings_mute_match",
            background=True,
        )

        # Retention index: If SCAN_RETENTION_DAYS > 0, set TTL; otherwise keep permanently
        if SCAN_RETENTION_DAYS > 0:
            ttl_seconds = SCAN_RETENTION_DAYS * 86400
            await f_coll.create_index(
                [("created_at", 1)],
                expireAfterSeconds=ttl_seconds,
                name="idx_findings_ttl",
                background=True,
            )
            logger.info(f"[MongoDB-Indexes] Findings TTL auto-purge active ({SCAN_RETENTION_DAYS} days).")
        else:
            # Permanent retention: create standard index for fast sorting, without auto-deletion
            await f_coll.create_index(
                [("created_at", 1)],
                name="idx_findings_created_at",
                background=True,
            )
            logger.info("[MongoDB-Indexes] Permanent retention enabled (no 30-day auto-purge).")
        # Full-text search index for search toolbar
        await f_coll.create_index(
            [("check_title", "text"), ("resource_name", "text"), ("description", "text")],
            name="idx_findings_text_search",
            background=True,
        )

        # 2. Scans Collection Indexes
        s_coll = db["scans"]
        await s_coll.create_index(
            [("scan_id", 1)],
            unique=True,
            name="idx_scans_unique_scan_id",
            background=True,
        )
        await s_coll.create_index(
            [("tenant_id", 1), ("created_at", -1)],
            name="idx_scans_tenant_timeline",
            background=True,
        )
        await s_coll.create_index(
            [("tenant_id", 1), ("account_id", 1), ("created_at", -1)],
            name="idx_scans_account_timeline",
            background=True,
        )

        # 3. Assets Collection Indexes
        a_coll = db["assets"]
        await a_coll.create_index(
            [("tenant_id", 1), ("scan_id", 1), ("status", 1)],
            name="idx_assets_status_filter",
            background=True,
        )
        await a_coll.create_index(
            [("tenant_id", 1), ("scan_id", 1), ("service", 1)],
            name="idx_assets_service_filter",
            background=True,
        )
        await a_coll.create_index(
            [("tenant_id", 1), ("scan_id", 1), ("resource_arn", 1)],
            unique=True,
            name="idx_assets_unique_resource",
            background=True,
        )

        # 4. Compliance Summaries Collection Indexes
        c_coll = db["compliance_summaries"]
        await c_coll.create_index(
            [("tenant_id", 1), ("scan_id", 1), ("framework", 1)],
            unique=True,
            name="idx_compliance_framework_lookup",
            background=True,
        )

        # 5. Mute Rules Collection Indexes
        m_coll = db["mute_rules"]
        await m_coll.create_index(
            [("tenant_id", 1), ("check_id", 1), ("resource_id", 1)],
            name="idx_mute_rules_active_match",
            background=True,
        )
        # Auto-expire mute rules on their configured expiration date
        await m_coll.create_index(
            [("expires_at", 1)],
            expireAfterSeconds=0,
            name="idx_mute_rules_auto_expire",
            background=True,
        )

        logger.info("[MongoDB-Indexes] All compound and retention indexes successfully established.")
    except Exception as e:
        logger.warning(f"[MongoDB-Indexes] Index verification encountered an issue: {e}")


def ensure_indexes_sync(db: Any):
    """
    Synchronous index creation for post-processor scripts and CLI runners.
    """
    if db is None:
        return

    try:
        f_coll = db["findings"]
        f_coll.create_index(
            [("tenant_id", 1), ("scan_id", 1), ("status", 1), ("severity", 1), ("service", 1)],
            name="idx_findings_compound_query",
            background=True,
        )
        if SCAN_RETENTION_DAYS > 0:
            ttl_seconds = SCAN_RETENTION_DAYS * 86400
            f_coll.create_index(
                [("created_at", 1)],
                expireAfterSeconds=ttl_seconds,
                name="idx_findings_ttl",
                background=True,
            )
        else:
            f_coll.create_index(
                [("created_at", 1)],
                name="idx_findings_created_at",
                background=True,
            )

        s_coll = db["scans"]
        s_coll.create_index([("scan_id", 1)], unique=True, name="idx_scans_unique_scan_id", background=True)
        s_coll.create_index([("tenant_id", 1), ("created_at", -1)], name="idx_scans_tenant_timeline", background=True)

        a_coll = db["assets"]
        a_coll.create_index([("tenant_id", 1), ("scan_id", 1), ("status", 1)], name="idx_assets_status_filter", background=True)
        a_coll.create_index([("tenant_id", 1), ("scan_id", 1), ("resource_arn", 1)], unique=True, name="idx_assets_unique_resource", background=True)

        c_coll = db["compliance_summaries"]
        c_coll.create_index([("tenant_id", 1), ("scan_id", 1), ("framework", 1)], unique=True, name="idx_compliance_framework_lookup", background=True)

        m_coll = db["mute_rules"]
        m_coll.create_index([("tenant_id", 1), ("check_id", 1), ("resource_id", 1)], name="idx_mute_rules_active_match", background=True)
        m_coll.create_index([("expires_at", 1)], expireAfterSeconds=0, name="idx_mute_rules_auto_expire", background=True)
    except Exception as e:
        logger.warning(f"[MongoDB-Indexes-Sync] Sync index creation issue: {e}")

