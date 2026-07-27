import logging
import asyncio
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.entities import (
    ScanJob, AuthorizedTarget, ScanStatus, Asset, Service, CryptoFinding, AssetType, utc_now
)
from app.scanners.base import ScannerRegistry, ScanContext
import app.scanners  # Ensure all scanner plugins are registered

from app.core.scope_guard import ScopeGuard, ScopeGuardError
from app.core.sanitizer import Sanitizer
from app.normalization.engine import NormalizationEngine

logger = logging.getLogger(__name__)

class DiscoveryOrchestrator:
    """
    Coordinates scan job execution:
    ScopeGuard authorization -> Scanner discovery -> Sanitizer -> NormalizationEngine -> Database Persistence
    """

    @classmethod
    async def run_scan_job(cls, db: Session, scan_job_id: str) -> ScanJob:
        scan_job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not scan_job:
            raise ValueError(f"ScanJob {scan_job_id} not found.")

        target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == scan_job.target_id).first()
        if not target:
            scan_job.status = ScanStatus.FAILED
            scan_job.error_message = "Target does not exist."
            db.commit()
            return scan_job

        # ScopeGuard authorization check
        try:
            ScopeGuard.validate_target(target)
        except ScopeGuardError as e:
            scan_job.status = ScanStatus.FAILED
            scan_job.error_message = str(e)
            scan_job.completed_at = utc_now()
            db.commit()
            return scan_job

        # Set job state to RUNNING
        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = utc_now()
        db.commit()

        # Determine scanners to run
        scanners_to_run = scan_job.requested_scanners
        if not scanners_to_run or "all" in [s.lower() for s in scanners_to_run]:
            scanners_to_run = list(ScannerRegistry.list_scanners().keys())

        context = ScanContext(scan_job_id=scan_job.id, target_id=target.id)

        assets_count = 0
        services_count = 0
        findings_count = 0

        asset_cache = {}
        service_cache = {}

        try:
            for scanner_id in scanners_to_run:
                scanner = ScannerRegistry.get(scanner_id)
                if not scanner:
                    logger.warning(f"Scanner '{scanner_id}' not registered, skipping.")
                    continue

                async for raw_finding in scanner.discover(target.target_value, target.target_type, context):
                    # 1. Sanitizer pipeline
                    clean_finding = Sanitizer.sanitize(raw_finding)

                    # 2. Normalization Engine
                    norm_algo = NormalizationEngine.normalize_and_get_or_create(db, clean_finding.raw_algorithm_name)

                    # 3. Asset creation/lookup
                    asset_key = f"{clean_finding.asset_hostname}:{clean_finding.asset_ip}"
                    if asset_key not in asset_cache:
                        existing_asset = db.query(Asset).filter(
                            Asset.target_id == target.id,
                            Asset.hostname == clean_finding.asset_hostname,
                            Asset.ip_address == clean_finding.asset_ip
                        ).first()

                        if not existing_asset:
                            existing_asset = Asset(
                                target_id=target.id,
                                hostname=clean_finding.asset_hostname,
                                ip_address=clean_finding.asset_ip,
                                asset_type=clean_finding.asset_type,
                                environment=clean_finding.environment,
                                operating_system=clean_finding.operating_system,
                                metadata_json={}
                            )
                            db.add(existing_asset)
                            db.flush()
                            assets_count += 1
                        asset_cache[asset_key] = existing_asset

                    asset = asset_cache[asset_key]

                    # 4. Service creation/lookup
                    service = None
                    if clean_finding.port is not None:
                        service_key = f"{asset.id}:{clean_finding.port}:{clean_finding.application_protocol}"
                        if service_key not in service_cache:
                            existing_service = db.query(Service).filter(
                                Service.asset_id == asset.id,
                                Service.port == clean_finding.port,
                                Service.application_protocol == clean_finding.application_protocol
                            ).first()

                            if not existing_service:
                                existing_service = Service(
                                    asset_id=asset.id,
                                    port=clean_finding.port,
                                    transport_protocol=clean_finding.transport_protocol,
                                    application_protocol=clean_finding.application_protocol,
                                    service_name=clean_finding.service_name,
                                    metadata_json=clean_finding.service_metadata
                                )
                                db.add(existing_service)
                                db.flush()
                                services_count += 1
                            service_cache[service_key] = existing_service
                        service = service_cache[service_key]

                    # 5. CryptoFinding creation
                    evidence_hash = clean_finding.metadata.get("_evidence_hash", "none")
                    crypto_finding = CryptoFinding(
                        scan_job_id=scan_job.id,
                        asset_id=asset.id,
                        service_id=service.id if service else None,
                        scanner_id=scanner.scanner_id,
                        scanner_version=scanner.version,
                        finding_type=clean_finding.finding_type,
                        raw_algorithm_name=clean_finding.raw_algorithm_name,
                        normalized_algorithm_id=norm_algo.canonical_id,
                        purpose=clean_finding.purpose,
                        location_identifier=clean_finding.location_identifier,
                        evidence_snippet=clean_finding.evidence_snippet,
                        evidence_hash=evidence_hash,
                        confidence=clean_finding.confidence,
                        metadata_json=clean_finding.metadata
                    )
                    db.add(crypto_finding)
                    findings_count += 1

            # Job finished successfully
            scan_job.status = ScanStatus.COMPLETED
            scan_job.completed_at = utc_now()
            scan_job.stats_json = {
                "assets_found": assets_count,
                "services_found": services_count,
                "findings_found": findings_count
            }
            db.commit()

        except Exception as e:
            logger.exception("Scan job execution failed.")
            scan_job.status = ScanStatus.FAILED
            scan_job.error_message = str(e)
            scan_job.completed_at = utc_now()
            db.commit()

        return scan_job
