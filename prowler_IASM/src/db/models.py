"""
Pydantic Document Schemas for Prowler IASM MongoDB Collections.
Defines strict models for tenants, scans, findings, assets, compliance summaries, and mute rules.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ------------------------------------------------------------------------------
# 1. Tenants Collection Models
# ------------------------------------------------------------------------------
class CloudAccountModel(BaseModel):
    account_id: str = Field(..., description="12-digit numeric AWS Account ID")
    account_alias: Optional[str] = Field(None, description="Human-readable alias e.g. 'Production-AWS'")
    role_arn: Optional[str] = Field(None, description="IAM Role ARN for cross-account assume role")
    external_id: Optional[str] = Field(None, description="Optional external ID for IAM role trust policy")
    default_regions: List[str] = Field(default_factory=lambda: ["us-east-1", "ap-south-1"])
    last_scan_at: Optional[datetime] = None


class TenantModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(alias="_id", description="Unique tenant identifier e.g. 'tenant_enterprise_01' or 'default'")
    name: str = Field(..., description="Organization or customer name e.g. 'Acme Corp' or 'Nopal Cyber'")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cloud_accounts: List[CloudAccountModel] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# 2. Scans Collection Models
# ------------------------------------------------------------------------------
class ScanKPIsModel(BaseModel):
    total_findings: int = 0
    passed: int = 0
    failed: int = 0
    muted: int = 0
    manual: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(alias="_id", description="Unique scan ID e.g. 'scan_157f6a53ad4a'")
    tenant_id: str = Field(default="default", description="Tenant isolation key")
    account_id: str = Field(..., description="Target AWS account ID")
    provider_alias: Optional[str] = None
    status: str = Field(default="completed", description="'queued' | 'running' | 'completed' | 'failed'")
    security_score: float = Field(default=100.0, description="Overall compliance score (0.0 to 100.0)")
    duration_seconds: Optional[float] = None
    kpis: ScanKPIsModel = Field(default_factory=ScanKPIsModel)
    services_breakdown: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    compliance_overview: Dict[str, Any] = Field(default_factory=dict)
    total_assets_scanned: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


# ------------------------------------------------------------------------------
# 3. Findings Collection Models
# ------------------------------------------------------------------------------
class FindingModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[str] = Field(None, alias="_id")
    tenant_id: str = Field(default="default", description="Tenant isolation key")
    scan_id: str = Field(..., description="Parent scan execution ID")
    account_id: str = Field(..., description="Audited AWS account ID")
    finding_uid: str = Field(..., description="Globally unique finding UID")
    check_id: str = Field(..., description="Prowler check ID e.g. 'iam_user_mfa_enabled'")
    check_title: str = Field(..., description="Human-readable title of check")
    service: str = Field(..., description="AWS service identifier e.g. 'iam', 's3'")
    service_name: Optional[str] = None
    region: str = Field(default="global", description="AWS region where resource resides")
    severity: str = Field(default="low", description="'critical' | 'high' | 'medium' | 'low'")
    status: str = Field(default="PASS", description="'PASS' | 'FAIL' | 'MANUAL' | 'MUTED'")
    resource_id: str = Field(..., description="Resource ARN or identifier")
    resource_name: Optional[str] = None
    status_extended: Optional[str] = None
    description: Optional[str] = None
    risk: Optional[str] = None
    categories: List[str] = Field(default_factory=list)
    compliance: Dict[str, List[str]] = Field(default_factory=dict)
    remediation: Optional[str] = None
    remediation_url: Optional[str] = None
    remediation_cli: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    is_muted: bool = False
    timestamp: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ------------------------------------------------------------------------------
# 4. Assets Collection Models
# ------------------------------------------------------------------------------
class AssetModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[str] = Field(None, alias="_id")
    tenant_id: str = Field(default="default", description="Tenant isolation key")
    scan_id: str = Field(..., description="Parent scan execution ID")
    account_id: str = Field(..., description="Audited AWS account ID")
    resource_arn: str = Field(..., description="Target AWS resource ARN or unique ID")
    resource_name: Optional[str] = None
    service: str = Field(..., description="AWS service e.g. 'rds', 'ecs'")
    service_name: Optional[str] = None
    region: str = Field(default="global")
    status: str = Field(default="secure", description="'secure' | 'vulnerable'")
    critical_failures: int = 0
    high_failures: int = 0
    medium_failures: int = 0
    low_failures: int = 0
    total_checks_evaluated: int = 0
    failed_checks: List[Dict[str, Any]] = Field(default_factory=list)
    passed_checks: List[Dict[str, Any]] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ------------------------------------------------------------------------------
# 5. Compliance Summaries Collection Models
# ------------------------------------------------------------------------------
class ComplianceSummaryModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[str] = Field(None, alias="_id")
    tenant_id: str = Field(default="default", description="Tenant isolation key")
    scan_id: str = Field(..., description="Parent scan execution ID")
    framework: str = Field(..., description="Framework identifier e.g. 'cis_4.0.1_aws', 'iso27001_2022'")
    framework_name: str = Field(..., description="Display title e.g. 'CIS AWS Foundations Benchmark v4.0.1'")
    score: float = Field(default=100.0, description="Compliance pass percentage (0.0 - 100.0)")
    passed_controls: int = 0
    failed_controls: int = 0
    total_controls: int = 0
    requirements_evaluated: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ------------------------------------------------------------------------------
# 6. Mute Rules Collection Models
# ------------------------------------------------------------------------------
class MuteRuleModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[str] = Field(None, alias="_id")
    tenant_id: str = Field(default="default", description="Tenant isolation key")
    check_id: str = Field(..., description="Target check ID to suppress e.g. 's3_bucket_public_access'")
    resource_id: str = Field(default="*", description="Target resource ARN or '*' for account-wide suppression")
    reason: str = Field(..., description="Business rationale / approved exception reason")
    muted_by: str = Field(default="security_admin", description="User or role creating the exception")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = Field(None, description="Optional auto-expiration date (TTL indexed)")
