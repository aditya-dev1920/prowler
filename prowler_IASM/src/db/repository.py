"""
Repository Layer for Prowler IASM.
Enforces multi-tenant isolation, compound indexed queries, bulk write pipelines,
and exception mute rule evaluation.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

from .mongo import get_async_db, get_sync_db

logger = logging.getLogger("prowler_iasm_db")

# Standard projection fields for sub-10ms UI table rendering
FINDINGS_PROJECTION = {
    "_id": 0,
    "id": 1,
    "uid": 1,
    "finding_uid": 1,
    "check_id": 1,
    "check_title": 1,
    "service": 1,
    "service_name": 1,
    "severity": 1,
    "status": 1,
    "region": 1,
    "resource_id": 1,
    "resource_name": 1,
    "description": 1,
    "status_extended": 1,
    "risk": 1,
    "categories": 1,
    "compliance": 1,
    "remediation": 1,
    "remediation_url": 1,
    "remediation_cli": 1,
    "references": 1,
    "scan_id": 1,
    "timestamp": 1,
    "tags": 1,
    "is_muted": 1,
}

ASSETS_PROJECTION = {
    "_id": 0,
    "resource_arn": 1,
    "resource_name": 1,
    "service": 1,
    "service_name": 1,
    "region": 1,
    "status": 1,
    "critical_failures": 1,
    "high_failures": 1,
    "medium_failures": 1,
    "low_failures": 1,
    "total_checks_evaluated": 1,
    "failed_checks": 1,
    "passed_checks": 1,
    "tags": 1,
}


# ==============================================================================
# 1. Scans Repository
# ==============================================================================
class ScanRepository:
    @staticmethod
    async def get_scan(scan_id: str, tenant_id: str = "default") -> Optional[Dict[str, Any]]:
        db = get_async_db()
        if db is None:
            return None
        return await db["scans"].find_one({"tenant_id": tenant_id, "scan_id": scan_id}, {"_id": 0})

    @staticmethod
    async def list_scans(tenant_id: str = "default", limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        db = get_async_db()
        if db is None:
            return []
        cursor = (
            db["scans"]
            .find({"tenant_id": tenant_id}, {"_id": 0})
            .sort("created_at", -1)
            .skip(offset)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    @staticmethod
    async def upsert_scan(scan_data: Dict[str, Any], tenant_id: str = "default") -> bool:
        db = get_async_db()
        if db is None:
            return False
        scan_id = scan_data.get("scan_id")
        if not scan_id:
            return False
        scan_data["tenant_id"] = tenant_id
        if "created_at" not in scan_data:
            scan_data["created_at"] = datetime.now(timezone.utc)
        await db["scans"].update_one(
            {"tenant_id": tenant_id, "scan_id": scan_id},
            {"$set": scan_data},
            upsert=True,
        )
        return True

    @staticmethod
    def upsert_scan_sync(scan_data: Dict[str, Any], tenant_id: str = "default") -> bool:
        db = get_sync_db()
        if db is None:
            return False
        scan_id = scan_data.get("scan_id")
        if not scan_id:
            return False
        scan_data["tenant_id"] = tenant_id
        if "created_at" not in scan_data:
            scan_data["created_at"] = datetime.now(timezone.utc)
        db["scans"].update_one(
            {"tenant_id": tenant_id, "scan_id": scan_id},
            {"$set": scan_data},
            upsert=True,
        )
        return True

    @staticmethod
    async def delete_scan_artifacts(scan_id: str, tenant_id: str = "default") -> bool:
        """Purges scan document and all associated findings, assets, and compliance summaries from MongoDB."""
        db = get_async_db()
        if db is None:
            return False
        try:
            await db["scans"].delete_one({"tenant_id": tenant_id, "scan_id": scan_id})
            await db["findings"].delete_many({"tenant_id": tenant_id, "scan_id": scan_id})
            await db["assets"].delete_many({"tenant_id": tenant_id, "scan_id": scan_id})
            await db["compliance_summaries"].delete_many({"tenant_id": tenant_id, "scan_id": scan_id})
            return True
        except Exception as e:
            logger.error(f"Failed to delete scan artifacts in Mongo for {scan_id}: {e}")
            return False


# ==============================================================================
# 2. Findings Repository
# ==============================================================================
class FindingRepository:
    @staticmethod
    async def get_findings_page(
        tenant_id: str,
        scan_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        service: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        db = get_async_db()
        if db is None:
            return [], 0

        query: Dict[str, Any] = {"tenant_id": tenant_id, "scan_id": scan_id}
        if status and status.upper() != "ALL":
            query["status"] = status.upper()
        if severity and severity.lower() != "all":
            query["severity"] = severity.lower()
        if service and service.lower() != "all":
            query["service"] = service.lower()
        if search and search.strip():
            # Use regex for flexible substring search across resource or check
            sq = search.strip()
            query["$or"] = [
                {"check_title": {"$regex": sq, "$options": "i"}},
                {"resource_id": {"$regex": sq, "$options": "i"}},
                {"resource_name": {"$regex": sq, "$options": "i"}},
                {"description": {"$regex": sq, "$options": "i"}},
            ]

        total = await db["findings"].count_documents(query)
        cursor = (
            db["findings"]
            .find(query, FINDINGS_PROJECTION)
            .skip(offset)
            .limit(limit)
        )
        items = await cursor.to_list(length=limit)
        return items, total

    @staticmethod
    def bulk_insert_findings_sync(
        scan_id: str,
        findings: List[Dict[str, Any]],
        tenant_id: str = "default",
        account_id: str = "",
    ) -> int:
        db = get_sync_db()
        if db is None or not findings:
            return 0

        now = datetime.now(timezone.utc)
        docs = []
        for f in findings:
            doc = dict(f)
            doc["tenant_id"] = tenant_id
            doc["scan_id"] = scan_id
            doc["account_id"] = account_id or doc.get("account_id", "")
            if "created_at" not in doc:
                doc["created_at"] = now
            docs.append(doc)

        # Batch insert in chunks of 1000 with BulkWriteError resilience
        coll = db["findings"]
        inserted_total = 0
        chunk_size = 1000
        for i in range(0, len(docs), chunk_size):
            chunk = docs[i : i + chunk_size]
            try:
                res = coll.insert_many(chunk, ordered=False)
                inserted_total += len(res.inserted_ids)
            except Exception as e:
                from pymongo.errors import BulkWriteError
                if isinstance(e, BulkWriteError):
                    inserted_total += e.details.get("nInserted", 0)
                else:
                    logger.warning(f"Batch write issue in findings: {e}")

        return inserted_total


# ==============================================================================
# 3. Assets Repository
# ==============================================================================
class AssetRepository:
    @staticmethod
    async def get_assets_page(
        tenant_id: str,
        scan_id: str,
        service: Optional[str] = None,
        status: Optional[str] = None,
        region: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        db = get_async_db()
        if db is None:
            return [], 0

        query: Dict[str, Any] = {"tenant_id": tenant_id, "scan_id": scan_id}
        if service and service.lower() != "all":
            query["service"] = service.lower()
        if status and status.lower() != "all":
            query["status"] = status.lower()
        if region and region.lower() != "all":
            query["region"] = region.lower()

        total = await db["assets"].count_documents(query)
        cursor = db["assets"].find(query, ASSETS_PROJECTION).skip(offset).limit(limit)
        items = await cursor.to_list(length=limit)
        return items, total

    @staticmethod
    def bulk_insert_assets_sync(
        scan_id: str,
        assets: List[Dict[str, Any]],
        tenant_id: str = "default",
        account_id: str = "",
    ) -> int:
        db = get_sync_db()
        if db is None or not assets:
            return 0

        now = datetime.now(timezone.utc)
        docs = []
        for a in assets:
            doc = dict(a)
            doc["tenant_id"] = tenant_id
            doc["scan_id"] = scan_id
            doc["account_id"] = account_id or doc.get("account_id", "")
            if "created_at" not in doc:
                doc["created_at"] = now
            docs.append(doc)

        coll = db["assets"]
        inserted_total = 0
        chunk_size = 1000
        for i in range(0, len(docs), chunk_size):
            chunk = docs[i : i + chunk_size]
            try:
                res = coll.insert_many(chunk, ordered=False)
                inserted_total += len(res.inserted_ids)
            except Exception as e:
                from pymongo.errors import BulkWriteError
                if isinstance(e, BulkWriteError):
                    inserted_total += e.details.get("nInserted", 0)
                else:
                    logger.warning(f"Batch write issue in assets: {e}")

        return inserted_total


# ==============================================================================
# 4. Compliance Summaries Repository
# ==============================================================================
class ComplianceRepository:
    @staticmethod
    async def get_compliance_summaries(tenant_id: str, scan_id: str) -> List[Dict[str, Any]]:
        db = get_async_db()
        if db is None:
            return []
        cursor = db["compliance_summaries"].find(
            {"tenant_id": tenant_id, "scan_id": scan_id},
            {"_id": 0}
        )
        return await cursor.to_list(length=100)

    @staticmethod
    def bulk_insert_compliance_sync(
        scan_id: str,
        compliance_overview: Dict[str, Any],
        tenant_id: str = "default",
    ) -> int:
        db = get_sync_db()
        if db is None or not compliance_overview:
            return 0

        now = datetime.now(timezone.utc)
        docs = []
        for fw, stats in compliance_overview.items():
            tot = stats.get("total", 0)
            passed = stats.get("passed", 0)
            failed = stats.get("failed", 0)
            score = stats.get("score", round(passed / tot * 100, 1) if tot > 0 else 100.0)
            docs.append({
                "tenant_id": tenant_id,
                "scan_id": scan_id,
                "framework": fw,
                "framework_name": fw.replace("-", " ").replace("_", " "),
                "score": score,
                "passed_controls": passed,
                "failed_controls": failed,
                "total_controls": tot,
                "requirements_evaluated": stats.get("requirements_count", 0),
                "created_at": now,
            })

        if docs:
            coll = db["compliance_summaries"]
            res = coll.insert_many(docs, ordered=False)
            return len(res.inserted_ids)
        return 0


# ==============================================================================
# 5. Mute Rules Repository
# ==============================================================================
class MuteRuleRepository:
    @staticmethod
    async def get_active_mute_rules(tenant_id: str = "default") -> List[Dict[str, Any]]:
        db = get_async_db()
        if db is None:
            return []
        now = datetime.now(timezone.utc)
        query = {
            "tenant_id": tenant_id,
            "$or": [
                {"expires_at": None},
                {"expires_at": {"$gt": now}},
            ],
        }
        cursor = db["mute_rules"].find(query)
        return await cursor.to_list(length=500)

    @staticmethod
    def get_active_mute_rules_sync(tenant_id: str = "default") -> List[Dict[str, Any]]:
        db = get_sync_db()
        if db is None:
            return []
        now = datetime.now(timezone.utc)
        query = {
            "tenant_id": tenant_id,
            "$or": [
                {"expires_at": None},
                {"expires_at": {"$gt": now}},
            ],
        }
        return list(db["mute_rules"].find(query))

    @staticmethod
    def is_finding_muted(finding: Dict[str, Any], active_mute_rules: List[Dict[str, Any]]) -> bool:
        """
        Evaluates whether a finding matches any active mute rule.
        Matches if check_id aligns and resource_id is identical or wildcard '*'.
        """
        chk = finding.get("check_id")
        res_id = finding.get("resource_id") or finding.get("resource_arn")
        for rule in active_mute_rules:
            if rule.get("check_id") == chk:
                r_target = rule.get("resource_id", "*")
                if r_target in ("*", res_id):
                    return True
        return False

    @staticmethod
    async def create_mute_rule(
        check_id: str,
        reason: str,
        resource_id: str = "*",
        muted_by: str = "security_admin",
        expires_at: Optional[datetime] = None,
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Creates a new exception mute rule and immediately updates matching findings to MUTED status.
        """
        now = datetime.now(timezone.utc)
        doc: Dict[str, Any] = {
            "tenant_id": tenant_id,
            "check_id": check_id,
            "resource_id": resource_id or "*",
            "reason": reason,
            "muted_by": muted_by,
            "created_at": now,
            "expires_at": expires_at,
        }
        db = get_async_db()
        if db is not None:
            res = await db["mute_rules"].insert_one(doc)
            rule_id = str(res.inserted_id)
            doc["id"] = rule_id
            doc["_id"] = rule_id

            # Instantly update existing matching findings across scans for this tenant
            find_filter: Dict[str, Any] = {
                "tenant_id": tenant_id,
                "check_id": check_id,
            }
            if resource_id and resource_id != "*":
                find_filter["$or"] = [
                    {"resource_id": resource_id},
                    {"resource_name": resource_id},
                ]
            await db["findings"].update_many(
                find_filter,
                {"$set": {"status": "MUTED", "is_muted": True}}
            )
        else:
            import uuid
            doc["id"] = f"mute_{uuid.uuid4().hex[:12]}"
            doc["_id"] = doc["id"]

        return doc

    @staticmethod
    async def delete_mute_rule(rule_id: str, tenant_id: str = "default") -> bool:
        """
        Deletes a mute rule and reverts any findings that are no longer covered by other rules back to FAIL.
        """
        db = get_async_db()
        if db is None:
            return False
        from bson import ObjectId
        try:
            rule = None
            try:
                rule = await db["mute_rules"].find_one({"_id": ObjectId(rule_id), "tenant_id": tenant_id})
            except Exception:
                rule = await db["mute_rules"].find_one({"_id": rule_id, "tenant_id": tenant_id})

            if not rule:
                return False

            del_res = await db["mute_rules"].delete_one({"_id": rule["_id"]})
            if del_res.deleted_count > 0:
                remaining_rules = await MuteRuleRepository.get_active_mute_rules(tenant_id)
                chk = rule.get("check_id")
                r_target = rule.get("resource_id", "*")

                # If no other rule covers this check/resource, revert findings to FAIL
                still_covered = any(
                    r.get("check_id") == chk and r.get("resource_id") in ("*", r_target)
                    for r in remaining_rules
                )
                if not still_covered:
                    unmute_filter: Dict[str, Any] = {
                        "tenant_id": tenant_id,
                        "check_id": chk,
                        "status": "MUTED"
                    }
                    if r_target and r_target != "*":
                        unmute_filter["$or"] = [{"resource_id": r_target}, {"resource_name": r_target}]
                    await db["findings"].update_many(
                        unmute_filter,
                        {"$set": {"status": "FAIL", "is_muted": False}}
                    )
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete mute rule {rule_id}: {e}")
            return False

    @staticmethod
    async def list_all_mute_rules(tenant_id: str = "default") -> List[Dict[str, Any]]:
        """Lists all mute rules for tenant, including active and expired."""
        db = get_async_db()
        if db is None:
            return []
        cursor = db["mute_rules"].find({"tenant_id": tenant_id}).sort("created_at", -1)
        rules = await cursor.to_list(length=1000)
        for r in rules:
            r["id"] = str(r["_id"])
            del r["_id"]
        return rules


# ==============================================================================
# 6. Tenants Repository
# ==============================================================================
class TenantRepository:
    @staticmethod
    async def get_tenant(tenant_id: str = "default") -> Optional[Dict[str, Any]]:
        """Retrieves tenant profile and connected cloud accounts."""
        db = get_async_db()
        if db is None:
            return None
        return await db["tenants"].find_one({"_id": tenant_id})

    @staticmethod
    async def list_tenants(limit: int = 50) -> List[Dict[str, Any]]:
        """Lists all organizations for the tenant switcher."""
        db = get_async_db()
        if db is None:
            return []
        cursor = db["tenants"].find().limit(limit)
        return await cursor.to_list(length=limit)

    @staticmethod
    async def upsert_tenant(tenant_data: Dict[str, Any]) -> bool:
        """Creates or updates tenant organization profile."""
        db = get_async_db()
        if db is None:
            return False
        tenant_id = tenant_data.get("_id") or tenant_data.get("id") or "default"
        tenant_data["_id"] = tenant_id
        if "created_at" not in tenant_data:
            tenant_data["created_at"] = datetime.now(timezone.utc)
        await db["tenants"].update_one(
            {"_id": tenant_id},
            {"$set": tenant_data},
            upsert=True
        )
        return True

    @staticmethod
    async def ensure_default_tenant(tenant_id: str = "default", name: str = "Primary Organization") -> Dict[str, Any]:
        """Ensures the baseline tenant document exists in the database on startup."""
        db = get_async_db()
        if db is None:
            return {"_id": tenant_id, "name": name, "cloud_accounts": []}
        existing = await db["tenants"].find_one({"_id": tenant_id})
        if existing:
            return existing
        now = datetime.now(timezone.utc)
        doc = {
            "_id": tenant_id,
            "name": name,
            "created_at": now,
            "cloud_accounts": []
        }
        await db["tenants"].update_one({"_id": tenant_id}, {"$setOnInsert": doc}, upsert=True)
        return doc

    @staticmethod
    def record_cloud_account_scan_sync(
        account_id: str,
        provider_alias: Optional[str] = None,
        tenant_id: str = "default",
        default_regions: Optional[List[str]] = None
    ) -> bool:
        """Records or updates a cloud account's last scan time and alias inside the tenant document."""
        db = get_sync_db()
        if db is None or not account_id:
            return False
        now = datetime.now(timezone.utc)
        # Pull existing entry if present to update without duplicate
        db["tenants"].update_one(
            {"_id": tenant_id},
            {"$pull": {"cloud_accounts": {"account_id": account_id}}}
        )
        acc_entry = {
            "account_id": account_id,
            "account_alias": provider_alias or account_id,
            "default_regions": default_regions or ["us-east-1", "ap-south-1"],
            "last_scan_at": now
        }
        db["tenants"].update_one(
            {"_id": tenant_id},
            {
                "$setOnInsert": {"name": "Primary Organization", "created_at": now},
                "$push": {"cloud_accounts": acc_entry}
            },
            upsert=True
        )
        return True

