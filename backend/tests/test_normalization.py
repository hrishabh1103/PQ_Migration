from app.normalization.engine import NormalizationEngine
from app.models.entities import QuantumSafetyStatus, PrimitiveType

def test_normalization_rsa2048(db_session):
    algo = NormalizationEngine.normalize_and_get_or_create(db_session, "RSA-2048")
    assert algo.canonical_id == "RSA-2048"
    assert algo.canonical_family == "RSA"
    assert algo.observed_name == "RSA-2048"
    assert algo.quantum_safety_status == QuantumSafetyStatus.QUANTUM_VULNERABLE
    assert algo.primitive_type == PrimitiveType.ASYMMETRIC_ENCRYPTION

def test_normalization_kyber768_preserves_observed_and_implementation(db_session):
    algo = NormalizationEngine.normalize_and_get_or_create(db_session, "Kyber768")
    assert algo.observed_name == "Kyber768"
    assert algo.canonical_family == "ML-KEM"
    assert algo.canonical_variant == "ML-KEM-768"
    assert algo.implementation_variant == "Kyber768"
    assert algo.quantum_safety_status == QuantumSafetyStatus.PQC_CANDIDATE

def test_normalization_ml_kem_768_standardized(db_session):
    algo = NormalizationEngine.normalize_and_get_or_create(db_session, "ML-KEM-768")
    assert algo.canonical_family == "ML-KEM"
    assert algo.quantum_safety_status == QuantumSafetyStatus.PQC_STANDARDIZED
    assert algo.implementation_variant is None

def test_normalization_unknown_algo(db_session):
    algo = NormalizationEngine.normalize_and_get_or_create(db_session, "CustomAlgo99")
    assert algo.quantum_safety_status == QuantumSafetyStatus.UNKNOWN
    assert algo.canonical_id.startswith("UNKNOWN-")
