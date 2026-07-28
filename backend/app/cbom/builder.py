from typing import Dict, Any
from sqlalchemy.orm import Session
from app.cbom.mapper import InternalInventoryMapper, CycloneDX16Serializer

class CycloneDXCBOMBuilder:
    """
    Generates CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) specification JSON document.
    Delegates mapping to InternalInventoryMapper and serialization to CycloneDX16Serializer.
    """

    @classmethod
    def generate_cbom_json(cls, db: Session) -> Dict[str, Any]:
        ir = InternalInventoryMapper.map_to_cbom_ir(db)
        serializer = CycloneDX16Serializer()
        return serializer.serialize(ir)
