import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import Asset, CryptoObject, DiscoveryCoverage, ReadinessAssessment, Relationship
from app.readiness.taxonomy import CryptographicPurpose, PrimitiveQuantumStatus, AssetReadinessResult
from app.readiness.policy import ReadinessPolicy
from app.readiness.classifier import PqcClassifier
from app.readiness.evaluator import ReadinessEvaluator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/readiness", tags=["PQC Readiness Engine"])

@router.get("/summary")
def get_readiness_summary(db: Session = Depends(get_db)):
    """
    Returns enterprise-wide PQC Readiness metrics derived from real database assets & assessments.
    Exposes Quantum Exposure breakdown, Asset Readiness states, Discovery Coverage confidence, and Policy Version.
    """
    assets = db.query(Asset).all()
    assessments = db.query(ReadinessAssessment).order_by(ReadinessAssessment.created_at.desc()).all()

    # Get latest assessment per asset
    latest_assessments: Dict[str, ReadinessAssessment] = {}
    for a in assessments:
        if a.asset_id and a.asset_id not in latest_assessments:
            latest_assessments[a.asset_id] = a

    vulnerable_assets = sum(1 for a in latest_assessments.values() if a.quantum_exposure == PrimitiveQuantumStatus.QUANTUM_VULNERABLE)
    resistant_assets = sum(1 for a in latest_assessments.values() if a.quantum_exposure == PrimitiveQuantumStatus.QUANTUM_RESISTANT)
    hybrid_assets = sum(1 for a in latest_assessments.values() if a.quantum_exposure == PrimitiveQuantumStatus.HYBRID)
    incomplete_coverage_assets = sum(1 for a in latest_assessments.values() if a.readiness_result == AssetReadinessResult.INCOMPLETE_COVERAGE)
    unknown_readiness_assets = sum(1 for a in latest_assessments.values() if a.readiness_result == AssetReadinessResult.UNKNOWN)

    return {
        "policy": ReadinessPolicy.get_policy_metadata(),
        "total_assets_inventoried": len(assets),
        "total_assets_assessed": len(latest_assessments),
        "quantum_exposure_breakdown": {
            "QUANTUM_VULNERABLE": vulnerable_assets,
            "QUANTUM_RESISTANT": resistant_assets,
            "HYBRID": hybrid_assets,
            "UNKNOWN": unknown_readiness_assets
        },
        "asset_readiness_breakdown": {
            "READY": sum(1 for a in latest_assessments.values() if a.readiness_result == "READY"),
            "PARTIALLY_READY": sum(1 for a in latest_assessments.values() if a.readiness_result == "PARTIALLY_READY"),
            "NOT_READY": sum(1 for a in latest_assessments.values() if a.readiness_result == "NOT_READY"),
            "INCOMPLETE_COVERAGE": incomplete_coverage_assets,
            "UNKNOWN": unknown_readiness_assets
        },
        "critical_priority_items": sum(1 for a in latest_assessments.values() if a.migration_category in ["CRITICAL", "HIGH"])
    }

@router.get("/assets")
def list_readiness_assets(
    readiness: Optional[str] = Query(None, description="Filter by readiness state (READY, NOT_READY, INCOMPLETE_COVERAGE, etc.)"),
    exposure: Optional[str] = Query(None, description="Filter by quantum exposure"),
    db: Session = Depends(get_db)
):
    """
    List evaluated assets with PQC readiness results, quantum exposure, priority scores, and rationale.
    """
    assets = db.query(Asset).all()
    results = []

    for a in assets:
        # Check or generate assessment
        latest_assessment = db.query(ReadinessAssessment).filter(ReadinessAssessment.asset_id == a.id).order_by(ReadinessAssessment.created_at.desc()).first()
        if not latest_assessment:
            latest_assessment = ReadinessEvaluator.evaluate_asset(db, a.id)

        if readiness and latest_assessment.readiness_result != readiness.upper():
            continue
        if exposure and latest_assessment.quantum_exposure != exposure.upper():
            continue

        results.append({
            "asset_id": a.id,
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "asset_type": a.asset_type,
            "provider": a.provider,
            "readiness_result": latest_assessment.readiness_result,
            "quantum_exposure": latest_assessment.quantum_exposure,
            "migration_priority_score": latest_assessment.migration_priority_score,
            "migration_category": latest_assessment.migration_category,
            "confidence": latest_assessment.confidence,
            "known_factors": latest_assessment.known_factors_json.get("factors", []),
            "unknown_factors": latest_assessment.unknown_factors_json.get("factors", []),
            "policy_id": latest_assessment.policy_id,
            "policy_version": latest_assessment.policy_version,
            "rationale": latest_assessment.rationale,
            "assessed_at": latest_assessment.created_at.isoformat()
        })

    return results

@router.get("/assets/{asset_id}")
def get_asset_readiness_detail(asset_id: str, db: Session = Depends(get_db)):
    """
    Get detailed PQC readiness assessment for a specific asset.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    assessment = ReadinessEvaluator.evaluate_asset(db, asset_id)
    return {
        "asset": {
            "id": asset.id,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "asset_type": asset.asset_type,
            "provider": asset.provider,
            "provider_resource_id": asset.provider_resource_id,
            "region": asset.region
        },
        "assessment": {
            "id": assessment.id,
            "policy_id": assessment.policy_id,
            "policy_version": assessment.policy_version,
            "readiness_result": assessment.readiness_result,
            "quantum_exposure": assessment.quantum_exposure,
            "migration_priority_score": assessment.migration_priority_score,
            "migration_category": assessment.migration_category,
            "confidence": assessment.confidence,
            "known_factors": assessment.known_factors_json.get("factors", []),
            "unknown_factors": assessment.unknown_factors_json.get("factors", []),
            "rationale": assessment.rationale,
            "assessed_at": assessment.created_at.isoformat()
        }
    }

@router.get("/crypto/{crypto_object_id}")
def get_crypto_readiness_detail(crypto_object_id: str, db: Session = Depends(get_db)):
    """
    Get purpose-aware PQC classification and migration recommendation for a CryptoObject.
    """
    cobj = db.query(CryptoObject).filter(
        (CryptoObject.id == crypto_object_id) | (CryptoObject.identity_key == crypto_object_id)
    ).first()
    if not cobj:
        raise HTTPException(status_code=404, detail=f"CryptoObject '{crypto_object_id}' not found")

    purpose = CryptographicPurpose.KEY_ESTABLISHMENT
    if "CERT" in cobj.object_type or "SIGN" in cobj.object_type:
        purpose = CryptographicPurpose.DIGITAL_SIGNATURE

    status, rec, rationale = PqcClassifier.classify_primitive(cobj.canonical_name, purpose)

    return {
        "crypto_object_id": cobj.id,
        "canonical_name": cobj.canonical_name,
        "object_type": cobj.object_type,
        "provider": cobj.provider,
        "identity_key": cobj.identity_key,
        "purpose": purpose.value,
        "quantum_status": status.value,
        "recommendation": rec,
        "rationale": rationale
    }

@router.get("/migration-priorities")
def get_migration_priorities(db: Session = Depends(get_db)):
    """
    Returns prioritized list of migration items sorted by priority score descending.
    Exposes rationale, confidence, known factors, unknown factors, and dependency impact.
    """
    assessments = db.query(ReadinessAssessment).all()
    sorted_items = sorted(assessments, key=lambda a: a.migration_priority_score, reverse=True)

    items = []
    for a in sorted_items:
        asset = db.query(Asset).filter(Asset.id == a.asset_id).first()
        items.append({
            "assessment_id": a.id,
            "asset_id": a.asset_id,
            "asset_name": asset.hostname if asset else "Unknown Asset",
            "asset_type": asset.asset_type if asset else "UNKNOWN",
            "priority_score": a.migration_priority_score,
            "category": a.migration_category,
            "quantum_exposure": a.quantum_exposure,
            "readiness_result": a.readiness_result,
            "confidence": a.confidence,
            "known_factors": a.known_factors_json.get("factors", []),
            "unknown_factors": a.unknown_factors_json.get("factors", []),
            "rationale": a.rationale,
            "policy_version": a.policy_version,
            "assessed_at": a.created_at.isoformat()
        })

    return items
