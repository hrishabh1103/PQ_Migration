import logging
from typing import Dict, Any, List, Set, Tuple
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import Asset, Service, CryptoObject, DataAsset, DataFlow, Relationship

logger = logging.getLogger(__name__)
router = APIRouter()

MAX_ALLOWED_DEPTH = 3
MAX_ALLOWED_NODES = 100

@router.get("/entity/{entity_type}/{entity_id}")
def get_entity_graph(
    entity_type: str,
    entity_id: str,
    depth: int = Query(1, ge=1, le=MAX_ALLOWED_DEPTH),
    max_nodes: int = Query(50, ge=10, le=MAX_ALLOWED_NODES),
    db: Session = Depends(get_db)
):
    """
    Returns a bounded-depth graph representation of surrounding connected nodes and edges for an entity.
    Includes Relationship edges and DataFlow edges up to requested depth limit.
    """
    visited_entities: Set[Tuple[str, str]] = set()
    nodes_map: Dict[str, Dict[str, Any]] = {}
    edges_list: List[Dict[str, Any]] = []
    truncated = False

    queue: List[Tuple[str, str, int]] = [(entity_type, entity_id, 0)]

    while queue and len(nodes_map) < max_nodes:
        curr_type, curr_id, curr_depth = queue.pop(0)

        entity_key = f"{curr_type}:{curr_id}"
        if (curr_type, curr_id) in visited_entities:
            continue
        visited_entities.add((curr_type, curr_id))

        # Resolve entity details
        label = f"{curr_type} ({curr_id[:8]})"
        category = curr_type
        details = {}

        if curr_type.upper() == "ASSET":
            asset = db.query(Asset).filter(Asset.id == curr_id).first()
            if asset:
                label = asset.hostname or asset.ip_address or asset.id[:8]
                category = asset.asset_type
                details = {"environment": asset.environment, "status": asset.status, "os": asset.operating_system}
        elif curr_type.upper() == "SERVICE":
            service = db.query(Service).filter(Service.id == curr_id).first()
            if service:
                label = f"{service.service_name}:{service.port or ''}"
                category = "SERVICE"
                details = {"protocol": service.application_protocol.value}
        elif curr_type.upper() in ["CRYPTOOBJECT", "CRYPTO_OBJECT"]:
            cobj = db.query(CryptoObject).filter(CryptoObject.id == curr_id).first()
            if cobj:
                label = cobj.canonical_name
                category = cobj.object_type
                details = {"provider": cobj.provider, "version": cobj.version, "identity_key": cobj.identity_key}
        elif curr_type.upper() in ["DATAASSET", "DATA_ASSET"]:
            da = db.query(DataAsset).filter(DataAsset.id == curr_id).first()
            if da:
                label = da.name
                category = "DATA_ASSET"
                details = {"classification": da.classification, "criticality": da.business_criticality}

        nodes_map[entity_key] = {
            "id": entity_key,
            "entity_type": curr_type,
            "entity_id": curr_id,
            "label": label,
            "category": category,
            "details": details
        }

        if curr_depth >= depth:
            continue

        # Find outgoing and incoming relationships
        relationships = db.query(Relationship).filter(
            (Relationship.source_entity_id == curr_id) | (Relationship.target_entity_id == curr_id)
        ).all()

        for rel in relationships:
            if len(nodes_map) >= max_nodes:
                truncated = True
                break

            is_source = (rel.source_entity_id == curr_id)
            neighbor_type = rel.target_entity_type if is_source else rel.source_entity_type
            neighbor_id = rel.target_entity_id if is_source else rel.source_entity_id

            neighbor_key = f"{neighbor_type}:{neighbor_id}"
            edge_id = f"rel-{rel.id}"

            edges_list.append({
                "id": edge_id,
                "source": f"{rel.source_entity_type}:{rel.source_entity_id}",
                "target": f"{rel.target_entity_type}:{rel.target_entity_id}",
                "label": rel.relationship_type,
                "confidence": rel.confidence,
                "type": "RELATIONSHIP"
            })

            if (neighbor_type, neighbor_id) not in visited_entities:
                queue.append((neighbor_type, neighbor_id, curr_depth + 1))

        # Find DataFlow connections
        data_flows = db.query(DataFlow).filter(
            (DataFlow.source_entity_id == curr_id) | (DataFlow.destination_entity_id == curr_id)
        ).all()

        for df in data_flows:
            if len(nodes_map) >= max_nodes:
                truncated = True
                break

            is_source = (df.source_entity_id == curr_id)
            neighbor_type = df.destination_entity_type if is_source else df.source_entity_type
            neighbor_id = df.destination_entity_id if is_source else df.source_entity_id

            edges_list.append({
                "id": f"df-{df.id}",
                "source": f"{df.source_entity_type}:{df.source_entity_id}",
                "target": f"{df.destination_entity_type}:{df.destination_entity_id}",
                "label": f"DATA_FLOW ({df.protocol or 'TLS'})",
                "purpose": df.protection_purpose,
                "type": "DATA_FLOW"
            })

            if (neighbor_type, neighbor_id) not in visited_entities:
                queue.append((neighbor_type, neighbor_id, curr_depth + 1))

    if len(queue) > 0 or len(nodes_map) >= max_nodes:
        truncated = True

    return {
        "root_entity": {"entity_type": entity_type, "entity_id": entity_id},
        "depth": depth,
        "requested_depth": depth,
        "actual_depth": min(depth, MAX_ALLOWED_DEPTH),
        "truncated": truncated,
        "nodes_count": len(nodes_map),
        "edges_count": len(edges_list),
        "nodes": list(nodes_map.values()),
        "edges": edges_list
    }
