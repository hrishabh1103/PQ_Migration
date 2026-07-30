import logging
import asyncio
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.models.entities import (
    ScanJob, AuthorizedTarget, ScanStatus, Asset, Service, CryptoFinding, CryptoObject, Relationship,
    DataAsset, DataFlow, DiscoveryRun, DiscoveryCoverage, utc_now
)
from app.scanners.base import ScannerRegistry, ScanContext
import app.scanners  # Ensure all scanner plugins are registered

from app.core.scope_guard import ScopeGuard, ScopeGuardError
from app.core.sanitizer import Sanitizer
from app.normalization.engine import NormalizationEngine
from app.risk.provenance import create_provenance_record

from app.collectors.linux_collector import LinuxCollector
from app.collectors.observations import (
    AssetObservation, ServiceObservation, ProcessObservation,
    CryptoObservation, CertificateObservation, RelationshipObservation, CapabilityObservation
)
from app.collectors.modules.base_module import ModuleResultStatus

logger = logging.getLogger(__name__)

def _clean_metadata_json(meta: Any) -> dict:
    if not isinstance(meta, dict):
        return {}
    cleaned = {}
    for k, v in meta.items():
        if isinstance(v, (str, int, float, bool, type(None))):
            cleaned[k] = v
        elif isinstance(v, (list, tuple)):
            cleaned[k] = [x if isinstance(x, (str, int, float, bool)) else str(x) for x in v]
        elif isinstance(v, dict):
            cleaned[k] = _clean_metadata_json(v)
        else:
            cleaned[k] = str(v)
    return cleaned

class DiscoveryOrchestrator:
    """
    Coordinates scan job execution & collection runs:
    ScopeGuard authorization -> DiscoveryRun creation -> Scanner/Collector execution -> 
    Sanitizer -> NormalizationEngine -> Provenance & Asset Resolution -> DiscoveryCoverage Lifecycle -> Database Persistence
    """

    @classmethod
    def resolve_or_create_asset(
        cls,
        db: Session,
        target_id: str,
        hostname: Optional[str],
        ip_address: Optional[str],
        asset_type: str,
        environment: str,
        operating_system: Optional[str] = None,
        provider_resource_id: Optional[str] = None,
        external_id: Optional[str] = None,
        identity_key: Optional[str] = None,
        asset_category: str = "INFRASTRUCTURE",
        provider: Optional[str] = None,
        region: Optional[str] = None
    ) -> Asset:
        """
        Deterministic Asset Identity Resolution.
        Precedence:
        1. provider_resource_id
        2. external_id
        3. identity_key
        4. (hostname, target_id)
        Note: Never merge two assets solely because they share an IP address.
        """
        asset = None

        # 1. provider_resource_id
        if provider_resource_id:
            asset = db.query(Asset).filter(Asset.provider_resource_id == provider_resource_id).first()

        # 2. external_id
        if not asset and external_id:
            asset = db.query(Asset).filter(Asset.external_id == external_id).first()

        # 3. identity_key
        if not asset and identity_key:
            asset = db.query(Asset).filter(Asset.identity_key == identity_key).first()

        # 4. (hostname, target_id)
        if not asset and hostname:
            asset = db.query(Asset).filter(
                Asset.target_id == target_id,
                Asset.hostname == hostname
            ).first()

        if not asset:
            computed_key = identity_key or (f"host:{hostname}" if hostname else f"ip:{ip_address}:{target_id}")
            asset = Asset(
                target_id=target_id,
                hostname=hostname,
                ip_address=ip_address,
                asset_type=asset_type if hasattr(asset_type, 'value') else str(asset_type),
                asset_category=asset_category,
                identity_key=computed_key,
                provider_resource_id=provider_resource_id,
                external_id=external_id,
                provider=provider.lower() if provider else None,
                region=region,
                environment=environment,
                operating_system=operating_system,
                status="ACTIVE",
                metadata_json={}
            )
            db.add(asset)
            db.flush()
        else:
            if provider and not asset.provider:
                asset.provider = provider.lower()
            if region and not asset.region:
                asset.region = region

        return asset

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

        # Create generic parent DiscoveryRun record
        discovery_run = DiscoveryRun(
            run_type="SCAN",
            plugin_id="orchestrator",
            plugin_version="1.0.0",
            status="RUNNING",
            started_at=utc_now(),
            stats_json={}
        )
        db.add(discovery_run)
        db.flush()

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

                scanner_findings_count = 0

                async for raw_finding in scanner.discover(target.target_value, target.target_type, context):
                    scanner_findings_count += 1
                    # 1. Sanitizer pipeline
                    clean_finding = Sanitizer.sanitize(raw_finding)

                    # 2. Normalization Engine
                    norm_algo = NormalizationEngine.normalize_and_get_or_create(db, clean_finding.raw_algorithm_name)

                    # 3. Deterministic Asset Resolution
                    asset_key = f"{clean_finding.asset_hostname}:{clean_finding.asset_ip}"
                    if asset_key not in asset_cache:
                        asset = cls.resolve_or_create_asset(
                            db=db,
                            target_id=target.id,
                            hostname=clean_finding.asset_hostname,
                            ip_address=clean_finding.asset_ip,
                            asset_type=clean_finding.asset_type,
                            environment=clean_finding.environment,
                            operating_system=clean_finding.operating_system
                        )
                        asset_cache[asset_key] = asset
                        assets_count += 1

                    asset = asset_cache[asset_key]

                    # Update DiscoveryCoverage state: NOT_SCANNED -> IN_PROGRESS -> SCANNED
                    coverage = db.query(DiscoveryCoverage).filter(
                        DiscoveryCoverage.asset_id == asset.id,
                        DiscoveryCoverage.capability == scanner_id
                    ).first()

                    if not coverage:
                        coverage = DiscoveryCoverage(
                            asset_id=asset.id,
                            capability=scanner_id,
                            plugin_id=scanner.scanner_id,
                            discovery_run_id=discovery_run.id,
                            status="IN_PROGRESS",
                            findings_count=0,
                            last_evaluated_at=utc_now(),
                            metadata_json={}
                        )
                        db.add(coverage)
                        db.flush()
                    else:
                        coverage.status = "IN_PROGRESS"
                        coverage.discovery_run_id = discovery_run.id
                        coverage.plugin_id = scanner.scanner_id

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

                    # 5. Create Provenance Record
                    evidence_hash = clean_finding.metadata.get("_evidence_hash", "none")
                    prov = create_provenance_record(
                        db=db,
                        plugin_id=scanner.scanner_id,
                        evidence_hash=evidence_hash,
                        plugin_version=scanner.version,
                        discovery_run_id=discovery_run.id,
                        target_id=target.id,
                        collection_method="ACTIVE",
                        evidence_type="OBSERVATION",
                        confidence=clean_finding.confidence.value if hasattr(clean_finding.confidence, 'value') else str(clean_finding.confidence),
                        metadata_json=clean_finding.metadata
                    )

                    # 6. CryptoFinding creation
                    crypto_finding = CryptoFinding(
                        scan_job_id=scan_job.id,
                        discovery_run_id=discovery_run.id,
                        provenance_id=prov.id,
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

                    # Complete coverage state: SCANNED
                    coverage.status = "SCANNED"
                    coverage.findings_count += 1
                    coverage.last_evaluated_at = utc_now()

            # Job & DiscoveryRun finished successfully
            discovery_run.status = "COMPLETED"
            discovery_run.completed_at = utc_now()
            discovery_run.stats_json = {
                "assets_found": assets_count,
                "services_found": services_count,
                "findings_found": findings_count
            }

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
            discovery_run.status = "FAILED"
            discovery_run.error_message = str(e)
            discovery_run.completed_at = utc_now()

            scan_job.status = ScanStatus.FAILED
            scan_job.error_message = str(e)
            scan_job.completed_at = utc_now()
            db.commit()

        return scan_job

    @classmethod
    async def run_collection_job(cls, db: Session, target_id: str, collector_plugin_id: str = "linux-host") -> DiscoveryRun:
        """
        Executes a Collector run (e.g. LinuxCollector), converts structured DiscoveryObservations into 
        Asset, Service, CryptoObject, Relationship, Provenance, and DiscoveryCoverage entities.
        """
        target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
        if not target:
            raise ValueError(f"Target {target_id} not found.")

        # Create DiscoveryRun(type=COLLECTION)
        discovery_run = DiscoveryRun(
            run_type="COLLECTION",
            plugin_id=collector_plugin_id,
            plugin_version="1.0.0",
            status="RUNNING",
            started_at=utc_now(),
            stats_json={}
        )
        db.add(discovery_run)
        db.flush()

        # Primary Host Asset
        host_asset = cls.resolve_or_create_asset(
            db=db,
            target_id=target.id,
            hostname=target.target_value,
            ip_address=None,
            asset_type="HOST",
            environment=target.environment,
            operating_system="Linux"
        )

        collector = LinuxCollector()
        module_results = await collector.run_collection()

        obj_map: Dict[str, str] = {"host": host_asset.id}
        obs_count = 0

        for res in module_results:
            # Map module status to coverage state
            cov_status = "SCANNED"
            if res.status == ModuleResultStatus.PARTIAL:
                cov_status = "PARTIALLY_SCANNED"
            elif res.status == ModuleResultStatus.FAILED:
                cov_status = "FAILED"
            elif res.status == ModuleResultStatus.NOT_APPLICABLE:
                cov_status = "NOT_APPLICABLE"

            coverage = db.query(DiscoveryCoverage).filter(
                DiscoveryCoverage.asset_id == host_asset.id,
                DiscoveryCoverage.capability == res.capability
            ).first()

            if not coverage:
                coverage = DiscoveryCoverage(
                    asset_id=host_asset.id,
                    capability=res.capability,
                    plugin_id=collector.plugin_id,
                    discovery_run_id=discovery_run.id,
                    status=cov_status,
                    findings_count=len(res.observations),
                    last_evaluated_at=utc_now(),
                    metadata_json={}
                )
                db.add(coverage)
                db.flush()
            else:
                coverage.status = cov_status
                coverage.discovery_run_id = discovery_run.id
                coverage.findings_count += len(res.observations)
                coverage.last_evaluated_at = utc_now()

            for obs in res.observations:
                obs_count += 1
                ev_hash = hashlib.sha256(f"{obs.observation_type}:{obs.module_id}:{obs.metadata}".encode()).hexdigest()
                prov = create_provenance_record(
                    db=db,
                    plugin_id=collector.plugin_id,
                    evidence_hash=ev_hash,
                    discovery_run_id=discovery_run.id,
                    target_id=target.id,
                    collection_method="AGENT" if obs.module_id == "host_info" else "ACTIVE",
                    metadata_json=obs.metadata
                )

                if isinstance(obs, AssetObservation):
                    ast = cls.resolve_or_create_asset(
                        db=db,
                        target_id=target.id,
                        hostname=obs.hostname,
                        ip_address=obs.ip_address,
                        asset_type=obs.asset_type,
                        environment=target.environment,
                        operating_system=obs.os_distribution,
                        identity_key=obs.identity_key,
                        asset_category=obs.asset_category
                    )
                    if obs.identity_key:
                        obj_map[obs.identity_key] = ast.id

                elif isinstance(obs, ProcessObservation):
                    proc_key = f"process:{obs.process_name}:{obs.pid}"
                    proc_ast = cls.resolve_or_create_asset(
                        db=db,
                        target_id=target.id,
                        hostname=None,
                        ip_address=None,
                        asset_type="process",
                        environment=target.environment,
                        identity_key=proc_key,
                        asset_category="runtime"
                    )
                    obj_map[proc_key] = proc_ast.id

                elif isinstance(obs, ServiceObservation):
                    svc = db.query(Service).filter(
                        Service.asset_id == host_asset.id,
                        Service.port == obs.port
                    ).first()
                    if not svc:
                        svc = Service(
                            asset_id=host_asset.id,
                            port=obs.port,
                            transport_protocol=obs.transport_protocol,
                            application_protocol=obs.application_protocol,
                            service_name=obs.service_name,
                            metadata_json=obs.metadata
                        )
                        db.add(svc)
                        db.flush()
                    obj_map[f"service:{obs.port}"] = svc.id

                elif isinstance(obs, CryptoObservation):
                    existing = db.query(CryptoObject).filter(CryptoObject.identity_key == obs.identity_key).first()
                    if not existing:
                        cobj = CryptoObject(
                            object_type=obs.object_type,
                            canonical_name=obs.canonical_name,
                            provider=obs.provider,
                            version=obs.version,
                            identity_key=obs.identity_key,
                            fingerprint=obs.fingerprint,
                            provenance_id=prov.id,
                            discovery_run_id=discovery_run.id,
                            metadata_json=obs.metadata
                        )
                        db.add(cobj)
                        db.flush()
                        obj_map[obs.identity_key] = cobj.id
                    else:
                        obj_map[obs.identity_key] = existing.id

                elif isinstance(obs, CertificateObservation):
                    cert_key = f"cert:sha256:{obs.fingerprint}"
                    existing = db.query(CryptoObject).filter(CryptoObject.identity_key == cert_key).first()
                    if not existing:
                        cobj = CryptoObject(
                            object_type="CERTIFICATE",
                            canonical_name=f"Certificate ({obs.subject[:30]})",
                            provider=obs.issuer[:30],
                            identity_key=cert_key,
                            fingerprint=obs.fingerprint,
                            provenance_id=prov.id,
                            discovery_run_id=discovery_run.id,
                            metadata_json={"subject": obs.subject, "issuer": obs.issuer, "valid_to": obs.valid_to}
                        )
                        db.add(cobj)
                        db.flush()
                        obj_map[cert_key] = cobj.id
                    else:
                        obj_map[cert_key] = existing.id

                elif isinstance(obs, RelationshipObservation):
                    src_id = obj_map.get(obs.source_id_hint, host_asset.id)
                    tgt_id = obj_map.get(obs.target_id_hint)
                    if src_id and tgt_id:
                        rel = Relationship(
                            source_entity_type=obs.source_type,
                            source_entity_id=src_id,
                            target_entity_type=obs.target_type,
                            target_entity_id=tgt_id,
                            relationship_type=obs.relationship_type,
                            scanner_or_connector_id=collector.plugin_id,
                            provenance_id=prov.id,
                            discovery_run_id=discovery_run.id,
                            confidence=obs.confidence,
                            metadata_json=obs.metadata
                        )
                        db.add(rel)

        discovery_run.status = "COMPLETED"
        discovery_run.completed_at = utc_now()
        discovery_run.stats_json = {"observations_processed": obs_count, "modules_executed": len(module_results)}
        db.commit()

        return discovery_run

    @classmethod
    async def run_connector_sync(
        cls,
        db: Session,
        target_id: str,
        connector_plugin_id: str = "aws",
        allowed_regions: Optional[List[str]] = None,
        profile_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        **kwargs
    ) -> DiscoveryRun:
        """
        Executes a Connector DiscoveryRun (type=SYNC) across authorized API targets.
        Processes structured observations, applies sanitization, resolves canonical assets & CryptoObjects,
        tracks per-region/service coverage, and persists relationships & provenance.
        """
        from app.scanners.plugins import PluginRegistry
        connector = PluginRegistry.get(connector_plugin_id)
        if not connector:
            raise ValueError(f"Connector plugin '{connector_plugin_id}' not found in PluginRegistry")

        target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
        if not target:
            raise ValueError(f"Target '{target_id}' not found")

        # 1. Authorize target scope
        try:
            ScopeGuard.validate_target(target)
        except ScopeGuardError as e:
            raise ScopeGuardError(f"Target '{target.target_value}' blocked by ScopeGuard: {e}")

        # 2. Create DiscoveryRun (type=SYNC)
        discovery_run = DiscoveryRun(
            plugin_id=connector_plugin_id,
            run_type="SYNC",
            status="RUNNING",
            started_at=utc_now(),
            stats_json={"requested_regions": allowed_regions or ["us-east-1"]}
        )
        db.add(discovery_run)
        db.commit()
        db.refresh(discovery_run)

        obs_count = 0
        obj_map: Dict[str, str] = {}

        context = ScanContext(scan_job_id=discovery_run.id, target_id=target.id, run_id=discovery_run.id)

        try:
            collect_iter = connector.collect(
                target_value=target.target_value,
                target_type=target.target_type,
                context=context,
                allowed_regions=allowed_regions,
                profile_name=profile_name,
                role_arn=role_arn,
                **kwargs
            )

            async for obs in collect_iter:
                obs_count += 1
                ev_hash = hashlib.sha256(f"{obs.__class__.__name__}:{getattr(obs, 'identity_key', getattr(obs, 'provider_resource_id', obs_count))}".encode()).hexdigest()

                prov = create_provenance_record(
                    db=db,
                    plugin_id=connector_plugin_id,
                    evidence_hash=ev_hash,
                    discovery_run_id=discovery_run.id,
                    target_id=target.id,
                    collection_method="API",
                    metadata_json=_clean_metadata_json(getattr(obs, "metadata", getattr(obs, "metadata_json", {})))
                )

                if isinstance(obs, AssetObservation):
                    ast = cls.resolve_or_create_asset(
                        db=db,
                        target_id=target.id,
                        hostname=obs.hostname,
                        ip_address=obs.ip_address,
                        asset_type=obs.asset_type,
                        environment=target.environment,
                        operating_system=getattr(obs, 'operating_system', getattr(obs, 'os_distribution', None)),
                        provider_resource_id=obs.provider_resource_id,
                        external_id=obs.external_id,
                        identity_key=obs.identity_key,
                        asset_category=obs.asset_category,
                        provider=getattr(obs, 'provider', connector_plugin_id),
                        region=getattr(obs, 'region', None)
                    )
                    if obs.provider_resource_id:
                        obj_map[obs.provider_resource_id] = ast.id
                    if obs.identity_key:
                        obj_map[obs.identity_key] = ast.id

                elif isinstance(obs, CryptoObservation):
                    raw_algo = obs.canonical_name if hasattr(obs, 'canonical_name') and obs.canonical_name else obs.raw_algorithm_name
                    norm_id = NormalizationEngine.normalize_and_get_or_create(db, raw_algo)
                    c_key = obs.identity_key if hasattr(obs, 'identity_key') and obs.identity_key else f"crypto:{obs.raw_algorithm_name}"
                    existing = db.query(CryptoObject).filter(CryptoObject.identity_key == c_key).first()
                    if not existing:
                        cobj = CryptoObject(
                            object_type=getattr(obs, 'object_type', 'ALGORITHM'),
                            canonical_name=obs.canonical_name if hasattr(obs, 'canonical_name') else (norm_id.canonical_id if norm_id else obs.raw_algorithm_name),
                            provider=getattr(obs, 'provider', connector_plugin_id.upper()),
                            identity_key=c_key,
                            provenance_id=prov.id,
                            discovery_run_id=discovery_run.id,
                            metadata_json=getattr(obs, 'metadata', getattr(obs, 'metadata_json', {}))
                        )
                        db.add(cobj)
                        db.flush()
                        obj_map[c_key] = cobj.id
                    else:
                        obj_map[c_key] = existing.id

                    # Create CryptoFinding for Risk & Findings Engines
                    assoc_asset = db.query(Asset).filter(Asset.target_id == target.id).first()
                    if assoc_asset:
                        cf = CryptoFinding(
                            discovery_run_id=discovery_run.id,
                            provenance_id=prov.id,
                            asset_id=assoc_asset.id,
                            scanner_id=connector_plugin_id,
                            scanner_version="1.0.0",
                            finding_type="ALGORITHM",
                            raw_algorithm_name=raw_algo,
                            normalized_algorithm_id=norm_id.canonical_id if norm_id else "UNKNOWN",
                            purpose=getattr(obs, 'object_type', 'GENERAL_ENCRYPTION'),
                            location_identifier=c_key,
                            evidence_snippet=f"Discovered via {connector_plugin_id.upper()} Connector: {raw_algo}",
                            evidence_hash=ev_hash,
                            confidence="HIGH",
                            metadata_json=getattr(obs, 'metadata', {})
                        )
                        db.add(cf)

                elif isinstance(obs, CertificateObservation):
                    fp = getattr(obs, 'fingerprint', getattr(obs, 'fingerprint_sha256', ''))
                    cert_key = f"cert:sha256:{fp.replace(':', '').upper()}"
                    existing = db.query(CryptoObject).filter(CryptoObject.identity_key == cert_key).first()
                    if not existing:
                        cobj = CryptoObject(
                            object_type="CERTIFICATE",
                            canonical_name=f"Certificate ({obs.subject})",
                            provider=obs.issuer,
                            identity_key=cert_key,
                            fingerprint=fp,
                            provenance_id=prov.id,
                            discovery_run_id=discovery_run.id,
                            metadata_json={
                                "subject": obs.subject,
                                "issuer": obs.issuer,
                                "serial_number": obs.serial_number,
                                "valid_to": getattr(obs, 'valid_to', getattr(obs, 'not_after', None))
                            }
                        )
                        db.add(cobj)
                        db.flush()
                        obj_map[cert_key] = cobj.id
                        if hasattr(obs, 'location_identifier') and obs.location_identifier:
                            obj_map[obs.location_identifier] = cobj.id
                    else:
                        obj_map[cert_key] = existing.id

                    assoc_asset = db.query(Asset).filter(Asset.target_id == target.id).first()
                    norm_cert_algo = NormalizationEngine.normalize_and_get_or_create(db, getattr(obs, 'signature_algorithm', 'RSA-2048'))
                    if assoc_asset:
                        cf = CryptoFinding(
                            discovery_run_id=discovery_run.id,
                            provenance_id=prov.id,
                            asset_id=assoc_asset.id,
                            scanner_id=connector_plugin_id,
                            scanner_version="1.0.0",
                            finding_type="CERTIFICATE",
                            raw_algorithm_name=getattr(obs, 'signature_algorithm', 'RSA-2048'),
                            normalized_algorithm_id=norm_cert_algo.canonical_id if norm_cert_algo else "UNKNOWN",
                            purpose="DIGITAL_SIGNATURE",
                            location_identifier=cert_key,
                            evidence_snippet=f"X.509 Certificate ({obs.subject}) via {connector_plugin_id.upper()}",
                            evidence_hash=ev_hash,
                            confidence="HIGH",
                            metadata_json={"subject": obs.subject, "issuer": obs.issuer}
                        )
                        db.add(cf)

                elif isinstance(obs, RelationshipObservation):
                    src_hint = getattr(obs, 'source_id_hint', getattr(obs, 'source_provider_resource_id', None))
                    tgt_hint = getattr(obs, 'target_id_hint', getattr(obs, 'target_provider_resource_id', None))
                    src_id = obj_map.get(src_hint)
                    tgt_id = obj_map.get(tgt_hint)

                    # If hints are DB entity UUIDs or directly resolved
                    if not src_id and src_hint in obj_map.values():
                        src_id = src_hint
                    if not tgt_id and tgt_hint in obj_map.values():
                        tgt_id = tgt_hint

                    if src_id and tgt_id:
                        target_ent_type = obs.target_type if (hasattr(obs, 'target_type') and obs.target_type) else ("CRYPTO_OBJECT" if (tgt_hint and (str(tgt_hint).startswith("crypto:") or str(tgt_hint).startswith("cert:"))) else "ASSET")
                        rel = db.query(Relationship).filter(
                            Relationship.source_entity_id == src_id,
                            Relationship.target_entity_id == tgt_id,
                            Relationship.relationship_type == obs.relationship_type
                        ).first()
                        if not rel:
                            rel = Relationship(
                                source_entity_type="ASSET",
                                source_entity_id=src_id,
                                target_entity_type=target_ent_type,
                                target_entity_id=tgt_id,
                                relationship_type=obs.relationship_type,
                                scanner_or_connector_id=connector_plugin_id,
                                provenance_id=prov.id,
                                discovery_run_id=discovery_run.id,
                                confidence=obs.confidence,
                                metadata_json=getattr(obs, 'metadata', {})
                            )
                            db.add(rel)
                        else:
                            rel.provenance_id = prov.id
                            rel.discovery_run_id = discovery_run.id
                            rel.metadata_json = getattr(obs, 'metadata', {})

            discovery_run.status = "COMPLETED"
            discovery_run.completed_at = utc_now()
            discovery_run.stats_json = {"observations_processed": obs_count, "status": "COMPLETED"}
            db.commit()

            # Execute PQC Readiness Evaluation across targets post-sync
            from app.readiness.evaluator import ReadinessEvaluator
            try:
                ReadinessEvaluator.execute_assessment_run(db=db, target_id=target.id)
            except Exception as eval_err:
                logger.warning(f"Post-sync readiness evaluation failed for target '{target_id}': {eval_err}")

        except Exception as e:
            logger.error(f"AWSConnector sync failed for target '{target_id}': {e}", exc_info=True)
            discovery_run.status = "FAILED"
            discovery_run.completed_at = utc_now()
            discovery_run.stats_json = {"error": str(e), "observations_processed": obs_count}
            db.commit()
            raise

        return discovery_run
