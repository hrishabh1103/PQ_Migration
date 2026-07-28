import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.models.entities import CryptoFinding, NormalizedAlgorithm, Asset, Service, CryptoObject, Relationship

def utc_now():
    return datetime.now(timezone.utc)

class CBOMComponent(BaseModel):
    bom_ref: str
    name: str
    component_type: str = "application"
    version: str = "1.0.0"
    properties: Dict[str, Any] = Field(default_factory=dict)

class CBOMCryptoAsset(BaseModel):
    bom_ref: str
    asset_type: str = "algorithm" # algorithm, key, certificate, protocol
    canonical_algorithm: str
    primitive: str
    execution_environment: str = "software-plain-text"
    purpose: str = "unknown"
    location: str
    evidence_snippet: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class CBOMIntermediateRepresentation(BaseModel):
    generated_at: datetime = Field(default_factory=utc_now)
    serial_number: str = Field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    components: List[CBOMComponent] = Field(default_factory=list)
    crypto_assets: List[CBOMCryptoAsset] = Field(default_factory=list)

class InternalInventoryMapper:
    """
    Maps internal inventory entities (Asset, Service, CryptoObject, Relationship, CryptoFinding)
    to a version-independent intermediate CBOM representation.
    """

    @classmethod
    def map_to_cbom_ir(cls, db: Session) -> CBOMIntermediateRepresentation:
        findings = db.query(CryptoFinding).all()
        ir = CBOMIntermediateRepresentation()

        for finding in findings:
            norm = db.query(NormalizedAlgorithm).filter(
                NormalizedAlgorithm.canonical_id == finding.normalized_algorithm_id
            ).first()
            asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()

            component_ref = f"component-{finding.asset_id}"
            ir.components.append(CBOMComponent(
                bom_ref=component_ref,
                name=asset.hostname if asset else "Unknown Asset",
                component_type="application" if (asset and getattr(asset, "asset_type", "HOST") == "APPLICATION") else "device"
            ))

            crypto_asset_ref = f"crypto-asset-{finding.id}"
            ir.crypto_assets.append(CBOMCryptoAsset(
                bom_ref=crypto_asset_ref,
                asset_type="algorithm",
                canonical_algorithm=norm.canonical_variant if norm else finding.raw_algorithm_name,
                primitive=norm.primitive_type.value.lower() if norm else "asymmetric-encryption",
                purpose=finding.purpose.value.lower() if hasattr(finding.purpose, 'value') else str(finding.purpose),
                location=finding.location_identifier,
                evidence_snippet=finding.evidence_snippet[:100]
            ))

        return ir

class CBOMSerializer(ABC):
    @abstractmethod
    def serialize(self, ir: CBOMIntermediateRepresentation) -> Dict[str, Any]:
        pass

class CycloneDX16Serializer(CBOMSerializer):
    def serialize(self, ir: CBOMIntermediateRepresentation) -> Dict[str, Any]:
        components_json = [
            {
                "type": c.component_type,
                "bom-ref": c.bom_ref,
                "name": c.name,
                "version": c.version
            }
            for c in ir.components
        ]

        crypto_assets_json = [
            {
                "bom-ref": ca.bom_ref,
                "assetType": ca.asset_type,
                "algorithmProperties": {
                    "primitive": ca.primitive,
                    "parameterSetIdentifier": ca.canonical_algorithm,
                    "executionEnvironment": ca.execution_environment,
                    "certificationLevel": ["none"],
                    "cryptoFunctions": [ca.purpose]
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": ca.location,
                            "symbol": ca.evidence_snippet
                        }
                    ]
                }
            }
            for ca in ir.crypto_assets
        ]

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": ir.serial_number,
            "version": 1,
            "metadata": {
                "timestamp": ir.generated_at.isoformat(),
                "tools": [
                    {
                        "vendor": "Q-Discovery",
                        "name": "Enterprise Cryptographic Discovery Platform",
                        "version": "1.0.0"
                    }
                ]
            },
            "components": components_json,
            "declarations": {
                "cryptographicAssets": crypto_assets_json
            }
        }
