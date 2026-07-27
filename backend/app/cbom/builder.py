import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.models.entities import CryptoFinding, NormalizedAlgorithm, Asset, Service

class CycloneDXCBOMBuilder:
    """
    Generates CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) specification JSON document.
    Spec: https://cyclonedx.org/docs/1.6/json/#cryptographicAssets
    """

    @classmethod
    def generate_cbom_json(cls, db: Session) -> Dict[str, Any]:
        findings = db.query(CryptoFinding).all()

        crypto_assets = []
        components = []

        for finding in findings:
            norm = db.query(NormalizedAlgorithm).filter(
                NormalizedAlgorithm.canonical_id == finding.normalized_algorithm_id
            ).first()
            asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()

            component_id = f"component-{finding.asset_id}"
            components.append({
                "type": "application" if asset and asset.asset_type.value == "APPLICATION" else "device",
                "bom-ref": component_id,
                "name": asset.hostname if asset else "Unknown Asset",
                "version": "1.0.0"
            })

            crypto_asset_id = f"crypto-asset-{finding.id}"
            crypto_assets.append({
                "bom-ref": crypto_asset_id,
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": norm.primitive_type.value if norm else "asymmetric-encryption",
                    "parameterSetIdentifier": finding.raw_algorithm_name,
                    "executionEnvironment": "software-plain-text",
                    "implementationPlatform": norm.implementation_variant or "generic",
                    "certificationLevel": ["none"],
                    "cryptoFunctions": [finding.purpose.value.lower()]
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": finding.location_identifier,
                            "symbol": finding.evidence_snippet[:100]
                        }
                    ]
                }
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "Q-Discovery",
                        "name": "Enterprise Cryptographic Discovery Platform",
                        "version": "0.1.0"
                    }
                ]
            },
            "components": components,
            "declarations": {
                "cryptographicAssets": crypto_assets
            }
        }
