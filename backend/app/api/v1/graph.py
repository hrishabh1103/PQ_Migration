import logging
from typing import Dict, Any, List, Set, Tuple, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import Asset, Service, CryptoObject, DataAsset, DataFlow, Relationship

logger = logging.getLogger(__name__)
router = APIRouter()

MAX_ALLOWED_DEPTH = 3
MAX_ALLOWED_NODES = 100

SUPPORTED_ENTITY_TYPES = {
    "ASSET": "Asset",
    "SERVICE": "Service",
    "CRYPTOOBJECT": "CryptoObject",
    "CRYPTO_OBJECT": "CryptoObject",
    "DATAASSET": "DataAsset",
    "DATA_ASSET": "DataAsset"
}

def normalize_entity_type(raw_type: str) -> str:
    cleaned = raw_type.upper().strip()
    if cleaned in SUPPORTED_ENTITY_TYPES:
        return SUPPORTED_ENTITY_TYPES[cleaned]
    raise HTTPException(
        status_code=400,
        detail=f"Unsupported entity_type '{raw_type}'. Supported types: Asset, Service, CryptoObject, DataAsset"
    )

@router.get("/entity/{entity_type}/{entity_id}")
def get_entity_graph(
    entity_type: str,
    entity_id: str,
    depth: int = Query(1, ge=1, le=MAX_ALLOWED_DEPTH),
    max_nodes: int = Query(50, ge=10, le=MAX_ALLOWED_NODES),
    relationship_type: Optional[str] = Query(None),
    node_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Returns a bounded-depth graph representation of surrounding connected nodes and edges for an entity.
    Filters strictly on (entity_type, entity_id) pairs to prevent ID collision across entity types.
    Deduplicates edges and strips any edges pointing to truncated nodes.
    """
    root_type = normalize_entity_type(entity_type)
    target_node_type = normalize_entity_type(node_type) if node_type else None

    visited_entities: Set[Tuple[str, str]] = set()
    nodes_map: Dict[str, Dict[str, Any]] = {}
    raw_edges: List[Dict[str, Any]] = []
    truncated = False

    queue: List[Tuple[str, str, int]] = [(root_type, entity_id, 0)]

    while queue and len(nodes_map) < max_nodes:
        curr_type, curr_id, curr_depth = queue.pop(0)

        entity_key = f"{curr_type}:{curr_id}"
        if (curr_type, curr_id) in visited_entities:
            continue
        visited_entities.add((curr_type, curr_id))

        # Check if root entity exists in database
        label = f"{curr_type} ({curr_id[:8]})"
        category = curr_type
        details = {}
        entity_found = False

        if curr_type == "Asset":
            asset = db.query(Asset).filter(Asset.id == curr_id).first()
            if asset:
                entity_found = True
                label = asset.hostname or asset.ip_address or asset.id[:8]
                category = asset.asset_type
                details = {"environment": asset.environment, "status": asset.status, "os": asset.operating_system}
        elif curr_type == "Service":
            service = db.query(Service).filter(Service.id == curr_id).first()
            if service:
                entity_found = True
                label = f"{service.service_name}:{service.port or ''}"
                category = "SERVICE"
                details = {"protocol": service.application_protocol.value if hasattr(service.application_protocol, 'value') else str(service.application_protocol)}
        elif curr_type == "CryptoObject":
            cobj = db.query(CryptoObject).filter(CryptoObject.id == curr_id).first()
            if cobj:
                entity_found = True
                label = cobj.canonical_name
                category = cobj.object_type
                details = {"provider": cobj.provider, "version": cobj.version, "identity_key": cobj.identity_key}
        elif curr_type == "DataAsset":
            da = db.query(DataAsset).filter(DataAsset.id == curr_id).first()
            if da:
                entity_found = True
                label = da.name
                category = "DATA_ASSET"
                details = {"classification": da.classification, "criticality": da.business_criticality}

        if not entity_found and curr_depth == 0:
            raise HTTPException(status_code=404, detail=f"Entity '{curr_type}:{curr_id}' not found")

        # Apply node_type filter if specified
        if not target_node_type or curr_type == target_node_type or curr_depth == 0:
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

        # 1. Query Relationship strictly matching (entity_type, entity_id) pairs
        rel_query = db.query(Relationship).filter(
            ((Relationship.source_entity_type == curr_type) & (Relationship.source_entity_id == curr_id)) |
            ((Relationship.target_entity_type == curr_type) & (Relationship.target_entity_id == curr_id))
        )
        if relationship_type:
            rel_query = rel_query.filter(Relationship.relationship_type == relationship_type)

        relationships = rel_query.all()

        for rel in relationships:
            if len(nodes_map) >= max_nodes:
                truncated = True
                break

            is_source = (rel.source_entity_type == curr_type and rel.source_entity_id == curr_id)
            neighbor_type = rel.target_entity_type if is_source else rel.source_entity_type
            neighbor_id = rel.target_entity_id if is_source else rel.source_entity_id

            edge_id = f"rel-{rel.id}"
            raw_edges.append({
                "id": edge_id,
                "source": f"{rel.source_entity_type}:{rel.source_entity_id}",
                "target": f"{rel.target_entity_type}:{rel.target_entity_id}",
                "label": rel.relationship_type,
                "confidence": rel.confidence,
                "type": "RELATIONSHIP"
            })

            if (neighbor_type, neighbor_id) not in visited_entities:
                queue.append((neighbor_type, neighbor_id, curr_depth + 1))

        # 2. Query DataFlow strictly matching (entity_type, entity_id) pairs
        df_query = db.query(DataFlow).filter(
            ((DataFlow.source_entity_type == curr_type) & (DataFlow.source_entity_id == curr_id)) |
            ((DataFlow.destination_entity_type == curr_type) & (DataFlow.destination_entity_id == curr_id))
        )
        data_flows = df_query.all()

        for df in data_flows:
            if len(nodes_map) >= max_nodes:
                truncated = True
                break

            is_source = (df.source_entity_type == curr_type and df.source_entity_id == curr_id)
            neighbor_type = df.destination_entity_type if is_source else df.source_entity_type
            neighbor_id = df.destination_entity_id if is_source else df.source_entity_id

            raw_edges.append({
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

    # Deduplicate edges & remove edges pointing to truncated/missing nodes
    valid_node_keys = set(nodes_map.keys())
    seen_edge_ids = set()
    valid_edges = []

    for edge in raw_edges:
        if edge["id"] not in seen_edge_ids:
            seen_edge_ids.add(edge["id"])
            if edge["source"] in valid_node_keys and edge["target"] in valid_node_keys:
                valid_edges.append(edge)

    return {
        "root_entity": {"entity_type": root_type, "entity_id": entity_id},
        "depth": depth,
        "requested_depth": depth,
        "actual_depth": min(depth, MAX_ALLOWED_DEPTH),
        "truncated": truncated,
        "nodes_count": len(nodes_map),
        "edges_count": len(valid_edges),
        "nodes": list(nodes_map.values()),
        "edges": valid_edges
    }

@router.get("/crypto/{crypto_object_id}/dependents")
def get_crypto_dependents(
    crypto_object_id: str,
    depth: int = Query(2, ge=1, le=MAX_ALLOWED_DEPTH),
    max_nodes: int = Query(50, ge=10, le=MAX_ALLOWED_NODES),
    db: Session = Depends(get_db)
):
    """
    Returns downstream assets, services, and data flows depending on a given CryptoObject or Certificate.
    Performs bounded graph traversal adhering to Foundation V2.1 constraints.
    """
    cobj = db.query(CryptoObject).filter(
        (CryptoObject.id == crypto_object_id) | (CryptoObject.identity_key == crypto_object_id)
    ).first()
    if not cobj:
        raise HTTPException(status_code=404, detail=f"CryptoObject '{crypto_object_id}' not found")

    return get_entity_graph(
        entity_type="CryptoObject",
        entity_id=cobj.id,
        depth=depth,
        max_nodes=max_nodes,
        relationship_type=None,
        node_type=None,
        db=db
    )
