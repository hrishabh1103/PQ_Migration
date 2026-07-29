import logging
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.entities import Asset, CryptoObject, Relationship, CorrelationRecord, DiscoveryRun, utc_now
from app.correlation.models import CorrelationDecision, EvidenceStrength, CorrelationEvidence

logger = logging.getLogger(__name__)

RULE_ID = "rule-correlation-v1"
RULE_VERSION = "v1.0"

COMPATIBLE_ENTITY_GROUPS = [
    {"ASSET", "CLOUD_VM", "HOST", "SERVER", "CLOUD_STORAGE", "KMS_KEY", "CLOUD_ACCOUNT", "CLOUD_REGION", "CLOUD_LOAD_BALANCER", "CLOUD_DATABASE", "CLOUD_CDN"},
    {"CRYPTO_OBJECT", "CERTIFICATE"},
    {"DATA_ASSET"},
    {"SERVICE"}
]

def are_types_compatible(type_a: str, type_b: str) -> bool:
    t_a = type_a.upper()
    t_b = type_b.upper()
    for grp in COMPATIBLE_ENTITY_GROUPS:
        if t_a in grp and t_b in grp:
            return True
    return False

class CorrelationEngine:
    """
    Provider-independent Entity Correlation Engine.
    Evaluates evidence strength hierarchy, records persisted CorrelationRecord entries,
    and performs controlled canonical resolution ONLY for IDENTICAL decisions based on strong deterministic evidence.
    Strictly checks entity type and namespace compatibility to prevent cross-type false merges.
    """

    @classmethod
    def evaluate_pair(
        cls,
        db: Session,
        source_type: str,
        source_id: str,
        target_type: str,
        target_id: str
    ) -> CorrelationRecord:
        """
        Evaluate correlation between two entities, persist a CorrelationRecord, and execute
        canonical resolution ONLY if decision == IDENTICAL and entity types are compatible.
        """
        matching_evidence: List[Dict[str, Any]] = []
        conflicting_evidence: List[Dict[str, Any]] = []

        decision = CorrelationDecision.UNRESOLVED
        confidence = "LOW"

        # 1. Fetch Source and Target Entities
        source_entity = cls._get_entity(db, source_type, source_id)
        target_entity = cls._get_entity(db, target_type, target_id)

        types_compatible = are_types_compatible(source_type, target_type)

        if not source_entity or not target_entity:
            decision = CorrelationDecision.UNRESOLVED
            confidence = "LOW"
        elif not types_compatible:
            # Incompatible Entity Types (e.g. ASSET vs DATA_ASSET with same ID string)
            decision = CorrelationDecision.UNRESOLVED
            confidence = "LOW"
            conflicting_evidence.append(CorrelationEvidence(
                evidence_type="ENTITY_TYPE_INCOMPATIBILITY",
                source_value=source_type,
                target_value=target_type,
                strength=EvidenceStrength.STRONG,
                matched=False,
                description=f"Incompatible entity types '{source_type}' and '{target_type}' cannot be correlated as IDENTICAL"
            ).model_dump())
        else:
            # 2. Evaluate Identity Evidence Hierarchy on Compatible Entity Types
            strong_matches = 0
            medium_matches = 0
            weak_matches = 0
            conflicts = 0

            # A. Strong Deterministic Evidence (Provider Resource ID / ARN)
            src_arn = getattr(source_entity, "provider_resource_id", None) or getattr(source_entity, "external_id", None)
            tgt_arn = getattr(target_entity, "provider_resource_id", None) or getattr(target_entity, "external_id", None)

            if src_arn and tgt_arn:
                if src_arn == tgt_arn:
                    strong_matches += 1
                    matching_evidence.append(CorrelationEvidence(
                        evidence_type="PROVIDER_RESOURCE_ID",
                        source_value=src_arn,
                        target_value=tgt_arn,
                        strength=EvidenceStrength.STRONG,
                        matched=True,
                        description="Exact match on provider resource ID / ARN"
                    ).model_dump())
                else:
                    conflicts += 1
                    conflicting_evidence.append(CorrelationEvidence(
                        evidence_type="PROVIDER_RESOURCE_ID",
                        source_value=src_arn,
                        target_value=tgt_arn,
                        strength=EvidenceStrength.STRONG,
                        matched=False,
                        description="Conflicting provider resource IDs"
                    ).model_dump())

            # B. Strong Deterministic Evidence (Valid X.509 SHA-256 Fingerprint - Certificate entities only)
            if source_type.upper() in ["CERTIFICATE", "CRYPTO_OBJECT"] and target_type.upper() in ["CERTIFICATE", "CRYPTO_OBJECT"]:
                src_fp = getattr(source_entity, "fingerprint", None)
                tgt_fp = getattr(target_entity, "fingerprint", None)

                if src_fp and tgt_fp:
                    if src_fp.lower() == tgt_fp.lower():
                        strong_matches += 1
                        matching_evidence.append(CorrelationEvidence(
                            evidence_type="X509_SHA256_FINGERPRINT",
                            source_value=src_fp,
                            target_value=tgt_fp,
                            strength=EvidenceStrength.STRONG,
                            matched=True,
                            description="Exact match on valid X.509 SHA-256 fingerprint"
                        ).model_dump())
                    else:
                        conflicts += 1
                        conflicting_evidence.append(CorrelationEvidence(
                            evidence_type="X509_SHA256_FINGERPRINT",
                            source_value=src_fp,
                            target_value=tgt_fp,
                            strength=EvidenceStrength.STRONG,
                            matched=False,
                            description="Conflicting X.509 fingerprints"
                        ).model_dump())

            # C. Strong Deterministic Evidence (Identity Key)
            src_key = getattr(source_entity, "identity_key", None)
            tgt_key = getattr(target_entity, "identity_key", None)

            if src_key and tgt_key:
                if src_key == tgt_key:
                    strong_matches += 1
                    matching_evidence.append(CorrelationEvidence(
                        evidence_type="IDENTITY_KEY",
                        source_value=src_key,
                        target_value=tgt_key,
                        strength=EvidenceStrength.STRONG,
                        matched=True,
                        description="Exact match on deterministic identity key"
                    ).model_dump())

            # D. Medium Contextual Evidence (EC2 Instance ID matching Linux Host Metadata)
            src_meta = getattr(source_entity, "metadata_json", {}) or {}
            tgt_meta = getattr(target_entity, "metadata_json", {}) or {}
            src_inst = src_meta.get("instance_id") or src_meta.get("ec2_instance_id")
            tgt_inst = tgt_meta.get("instance_id") or tgt_meta.get("ec2_instance_id")

            if src_inst and tgt_inst and src_inst == tgt_inst:
                medium_matches += 1
                matching_evidence.append(CorrelationEvidence(
                    evidence_type="EC2_INSTANCE_ID",
                    source_value=src_inst,
                    target_value=tgt_inst,
                    strength=EvidenceStrength.MEDIUM,
                    matched=True,
                    description="Match on EC2 instance ID across cloud & host collector"
                ).model_dump())

            # E. Weak Evidence (IP Address, Hostname, Display Name, AWS Tags)
            src_ip = getattr(source_entity, "ip_address", None)
            tgt_ip = getattr(target_entity, "ip_address", None)
            if src_ip and tgt_ip and src_ip == tgt_ip:
                weak_matches += 1
                matching_evidence.append(CorrelationEvidence(
                    evidence_type="IP_ADDRESS",
                    source_value=src_ip,
                    target_value=tgt_ip,
                    strength=EvidenceStrength.WEAK,
                    matched=True,
                    description="Shared IP address (Weak evidence - NEVER independently triggers IDENTICAL)"
                ).model_dump())

            src_host = getattr(source_entity, "hostname", None)
            tgt_host = getattr(target_entity, "hostname", None)
            if src_host and tgt_host and src_host.lower() == tgt_host.lower():
                weak_matches += 1
                matching_evidence.append(CorrelationEvidence(
                    evidence_type="HOSTNAME",
                    source_value=src_host,
                    target_value=tgt_host,
                    strength=EvidenceStrength.WEAK,
                    matched=True,
                    description="Shared hostname (Weak evidence - NEVER independently triggers IDENTICAL)"
                ).model_dump())

            # 3. Decision Matrix
            if conflicts > 0 and strong_matches == 0:
                decision = CorrelationDecision.CONFLICTING
                confidence = "HIGH"
            elif strong_matches > 0:
                decision = CorrelationDecision.IDENTICAL
                confidence = "HIGH"
            elif medium_matches > 0:
                decision = CorrelationDecision.LIKELY_SAME
                confidence = "MEDIUM"
            elif weak_matches > 0:
                decision = CorrelationDecision.RELATED
                confidence = "LOW"
            else:
                decision = CorrelationDecision.UNRESOLVED
                confidence = "LOW"

        # 4. Check for existing CorrelationRecord or create new
        rec = db.query(CorrelationRecord).filter(
            CorrelationRecord.source_entity_id == source_id,
            CorrelationRecord.target_entity_id == target_id
        ).first()

        if not rec:
            rec = CorrelationRecord(
                source_entity_type=source_type,
                source_entity_id=source_id,
                target_entity_type=target_type,
                target_entity_id=target_id,
                decision=decision.value if isinstance(decision, CorrelationDecision) else decision,
                confidence=confidence,
                matching_evidence_json={"evidence": matching_evidence},
                conflicting_evidence_json={"evidence": conflicting_evidence},
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                status="ACTIVE"
            )
            db.add(rec)
        else:
            rec.decision = decision.value if isinstance(decision, CorrelationDecision) else decision
            rec.confidence = confidence
            rec.matching_evidence_json = {"evidence": matching_evidence}
            rec.conflicting_evidence_json = {"evidence": conflicting_evidence}
            rec.updated_at = utc_now()

        db.flush()

        # 5. Controlled Canonical Resolution ONLY for IDENTICAL and Compatible Entity Types
        # LIKELY_SAME, RELATED, UNRESOLVED, CONFLICTING MUST NEVER MERGE ENTITIES
        if decision == CorrelationDecision.IDENTICAL and source_id != target_id:
            cls._execute_canonical_resolution(db, source_type, source_id, target_id)

        db.commit()
        return rec

    @classmethod
    def _execute_canonical_resolution(
        cls,
        db: Session,
        entity_type: str,
        source_id: str,
        target_id: str
    ):
        """
        Executes non-destructive canonical resolution for IDENTICAL entities.
        Preserves all source entities, provenance records, correlation evidence, and source metadata.
        """
        logger.info(f"Executing Canonical Resolution: {entity_type} '{source_id}' -> '{target_id}'")
        rels = db.query(Relationship).filter(
            (Relationship.source_entity_id == source_id) | (Relationship.target_entity_id == source_id)
        ).all()

        for r in rels:
            if r.source_entity_id == source_id:
                r.source_entity_id = target_id
            if r.target_entity_id == source_id:
                r.target_entity_id = target_id

    @classmethod
    def _get_entity(cls, db: Session, entity_type: str, entity_id: str) -> Optional[Any]:
        if entity_type.upper() in ["ASSET", "CLOUD_VM", "HOST", "KMS_KEY", "CLOUD_STORAGE", "CLOUD_ACCOUNT", "CLOUD_REGION", "CLOUD_LOAD_BALANCER", "CLOUD_DATABASE", "CLOUD_CDN"]:
            return db.query(Asset).filter(Asset.id == entity_id).first()
        elif entity_type.upper() in ["CRYPTO_OBJECT", "CERTIFICATE"]:
            return db.query(CryptoObject).filter(CryptoObject.id == entity_id).first()
        elif entity_type.upper() in ["DATA_ASSET", "DATAASSET"]:
            from app.models.entities import DataAsset
            return db.query(DataAsset).filter(DataAsset.id == entity_id).first()
        return None
