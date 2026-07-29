import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.entities import Asset, AuthorizedTarget, CryptoObject, Relationship, DiscoveryCoverage, ReadinessAssessment, AssessmentRun, utc_now
from app.readiness.taxonomy import CryptographicPurpose, PrimitiveQuantumStatus, AssetReadinessResult
from app.readiness.policy import ReadinessPolicy
from app.readiness.classifier import PqcClassifier
from app.readiness.priority import MigrationPriorityEngine

logger = logging.getLogger(__name__)

class ReadinessEvaluator:
    """
    Evaluates PQC Readiness for Assets & Targets based on versioned policy rules.
    Enforces coverage-aware readiness: Incomplete coverage prevents READY classification.
    Persists historical ReadinessAssessment records linked to an AssessmentRun without overwriting past runs.
    """

    @classmethod
    def execute_assessment_run(
        cls,
        db: Session,
        policy_id: str = ReadinessPolicy.policy_id,
        policy_version: str = ReadinessPolicy.policy_version,
        target_id: Optional[str] = None
    ) -> AssessmentRun:
        """
        Executes a first-class AssessmentRun, creating a new AssessmentRun DB record and evaluating all targets/assets.
        """
        run = AssessmentRun(
            policy_id=policy_id,
            policy_version=policy_version,
            status="RUNNING",
            started_at=utc_now(),
            evaluated_entity_count=0,
            failed_entity_count=0,
            metadata_json={"target_id": target_id} if target_id else {}
        )
        db.add(run)
        db.commit()
        db.refresh(run)

        query = db.query(Asset)
        if target_id:
            query = query.filter(Asset.target_id == target_id)
        assets = query.all()

        evaluated = 0
        failed = 0

        for a in assets:
            try:
                cls.evaluate_asset(
                    db=db,
                    asset_id=a.id,
                    policy_id=policy_id,
                    policy_version=policy_version,
                    assessment_run_id=run.id
                )
                evaluated += 1
            except Exception as e:
                logger.error(f"Readiness evaluation failed for asset '{a.id}': {e}")
                failed += 1

        run.status = "COMPLETED"
        run.completed_at = utc_now()
        run.evaluated_entity_count = evaluated
        run.failed_entity_count = failed
        db.commit()
        db.refresh(run)

        return run

    @classmethod
    def evaluate_asset(
        cls,
        db: Session,
        asset_id: str,
        policy_id: str = ReadinessPolicy.policy_id,
        policy_version: str = ReadinessPolicy.policy_version,
        assessment_run_id: Optional[str] = None
    ) -> ReadinessAssessment:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset '{asset_id}' not found")

        # Create or link AssessmentRun if not provided
        if not assessment_run_id:
            run = db.query(AssessmentRun).filter(
                AssessmentRun.policy_id == policy_id,
                AssessmentRun.policy_version == policy_version
            ).order_by(AssessmentRun.started_at.desc()).first()

            if not run:
                run = AssessmentRun(
                    policy_id=policy_id,
                    policy_version=policy_version,
                    status="COMPLETED",
                    started_at=utc_now(),
                    completed_at=utc_now()
                )
                db.add(run)
                db.commit()
                db.refresh(run)
            assessment_run_id = run.id

        # 1. Fetch Discovery Coverage
        coverage_records = db.query(DiscoveryCoverage).filter(DiscoveryCoverage.asset_id == asset_id).all()
        has_scanned_coverage = any(c.status == "SCANNED" for c in coverage_records)
        has_incomplete_coverage = any(c.status in ["NOT_SCANNED", "PARTIALLY_SCANNED", "FAILED"] for c in coverage_records) or len(coverage_records) == 0

        # 2. Query Cryptographic Objects linked to Asset
        relationships = db.query(Relationship).filter(
            (Relationship.source_entity_id == asset_id) | (Relationship.target_entity_id == asset_id)
        ).all()

        crypto_object_ids = set()
        for r in relationships:
            if r.source_entity_type in ["CRYPTO_OBJECT", "CERTIFICATE"]:
                crypto_object_ids.add(r.source_entity_id)
            if r.target_entity_type in ["CRYPTO_OBJECT", "CERTIFICATE"]:
                crypto_object_ids.add(r.target_entity_id)

        crypto_objects = db.query(CryptoObject).filter(CryptoObject.id.in_(crypto_object_ids)).all() if crypto_object_ids else []

        vulnerable_count = 0
        resistant_count = 0
        hybrid_count = 0
        highest_priority_score = 0
        top_priority_data: Dict[str, Any] = {}

        overall_quantum_exposure = PrimitiveQuantumStatus.NOT_APPLICABLE

        if not crypto_objects:
            if has_incomplete_coverage:
                readiness_result = AssetReadinessResult.INCOMPLETE_COVERAGE
                overall_quantum_exposure = PrimitiveQuantumStatus.UNKNOWN
            else:
                readiness_result = AssetReadinessResult.UNKNOWN  # NO_VULNERABILITY_FOUND != READY
                overall_quantum_exposure = PrimitiveQuantumStatus.NOT_APPLICABLE
        else:
            for cobj in crypto_objects:
                purpose = CryptographicPurpose.KEY_ESTABLISHMENT
                if "CERT" in cobj.object_type or "SIGN" in cobj.object_type:
                    purpose = CryptographicPurpose.DIGITAL_SIGNATURE

                status, rec, rat = PqcClassifier.classify_primitive(cobj.canonical_name, purpose)

                if status == PrimitiveQuantumStatus.QUANTUM_VULNERABLE:
                    vulnerable_count += 1
                elif status == PrimitiveQuantumStatus.HYBRID:
                    hybrid_count += 1
                elif status == PrimitiveQuantumStatus.QUANTUM_RESISTANT:
                    resistant_count += 1

                # Calculate priority for this primitive
                p_res = MigrationPriorityEngine.calculate_priority(
                    quantum_status=status,
                    purpose=purpose,
                    is_internet_exposed=False,
                    business_criticality="MEDIUM",
                    coverage_status="SCANNED" if has_scanned_coverage else "NOT_SCANNED"
                )

                if p_res["priority_score"] >= highest_priority_score:
                    highest_priority_score = p_res["priority_score"]
                    top_priority_data = p_res

            # Determine Aggregate Asset Quantum Exposure
            if vulnerable_count > 0:
                overall_quantum_exposure = PrimitiveQuantumStatus.QUANTUM_VULNERABLE
            elif hybrid_count > 0:
                overall_quantum_exposure = PrimitiveQuantumStatus.HYBRID
            elif resistant_count > 0:
                overall_quantum_exposure = PrimitiveQuantumStatus.QUANTUM_RESISTANT

            # Determine Asset Readiness Result (Coverage-Aware)
            if has_incomplete_coverage:
                readiness_result = AssetReadinessResult.INCOMPLETE_COVERAGE
            elif vulnerable_count > 0:
                readiness_result = AssetReadinessResult.NOT_READY
            elif hybrid_count > 0 or (resistant_count > 0 and (vulnerable_count > 0 or has_incomplete_coverage)):
                readiness_result = AssetReadinessResult.PARTIALLY_READY
            elif resistant_count > 0 and vulnerable_count == 0 and not has_incomplete_coverage:
                readiness_result = AssetReadinessResult.READY
            else:
                readiness_result = AssetReadinessResult.UNKNOWN

        if not top_priority_data:
            top_priority_data = MigrationPriorityEngine.calculate_priority(
                quantum_status=overall_quantum_exposure,
                purpose=CryptographicPurpose.UNKNOWN,
                coverage_status="NOT_SCANNED" if has_incomplete_coverage else "SCANNED"
            )

        # 3. Create & Persist ReadinessAssessment Historical Record
        assessment = ReadinessAssessment(
            assessment_run_id=assessment_run_id,
            asset_id=asset.id,
            target_id=asset.target_id,
            policy_id=policy_id,
            policy_version=policy_version,
            readiness_result=readiness_result.value if isinstance(readiness_result, AssetReadinessResult) else readiness_result,
            quantum_exposure=overall_quantum_exposure.value if isinstance(overall_quantum_exposure, PrimitiveQuantumStatus) else overall_quantum_exposure,
            migration_priority_score=top_priority_data.get("priority_score", 0),
            migration_category=top_priority_data.get("category", "LOW"),
            confidence=top_priority_data.get("confidence", "MEDIUM"),
            known_factors_json={"factors": top_priority_data.get("known_factors", [])},
            unknown_factors_json={"factors": top_priority_data.get("unknown_factors", [])},
            factor_breakdown_json=top_priority_data.get("factor_breakdown", {}),
            rationale=top_priority_data.get("rationale", "")
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        return assessment
