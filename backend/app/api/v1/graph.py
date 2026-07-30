import logging
from typing import Dict, Any, List, Set, Tuple, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import Asset, Service, CryptoObject, CryptoFinding, DataAsset, DataFlow, Relationship

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

def normalize_entity_type(raw_type: Optional[str]) -> Optional[str]:
    if not raw_type or not isinstance(raw_type, str):
        return None
    cleaned = raw_type.upper().strip()
    if cleaned in ["ALL", "*", "NONE", ""]:
        return None
    if cleaned in SUPPORTED_ENTITY_TYPES:
        return SUPPORTED_ENTITY_TYPES[cleaned]
    raise HTTPException(
        status_code=400,
        detail=f"Unsupported entity_type '{raw_type}'. Supported types: Asset, Service, CryptoObject, DataAsset"
    )

@router.get("")
@router.get("/overview")
def get_global_graph_overview(
    max_nodes: int = Query(50, ge=10, le=MAX_ALLOWED_NODES),
    relationship_type: Optional[str] = Query(None),
    node_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Returns global graph overview of all persisted relationships in inventory.
    """
    rel_filter = relationship_type if isinstance(relationship_type, str) and relationship_type.upper() not in ["ALL", ""] else None
    target_node_filter = normalize_entity_type(node_type)

    query = db.query(Relationship)
    if rel_filter:
        query = query.filter(Relationship.relationship_type == rel_filter)
    
    max_nodes_val = max_nodes if isinstance(max_nodes, int) else 50
    rels = query.limit(max_nodes_val).all()

    nodes_map: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    for r in rels:
        s_key = f"{r.source_entity_type}:{r.source_entity_id}"
        t_key = f"{r.target_entity_type}:{r.target_entity_id}"

        if s_key not in nodes_map:
            nodes_map[s_key] = {
                "id": s_key,
                "entity_type": r.source_entity_type,
                "entity_id": r.source_entity_id,
                "label": f"{r.source_entity_type} ({r.source_entity_id[:8]})",
                "category": r.source_entity_type,
                "details": {}
            }

        if t_key not in nodes_map:
            nodes_map[t_key] = {
                "id": t_key,
                "entity_type": r.target_entity_type,
                "entity_id": r.target_entity_id,
                "label": f"{r.target_entity_type} ({r.target_entity_id[:8]})",
                "category": r.target_entity_type,
                "details": {}
            }

        edges.append({
            "id": r.id,
            "source": s_key,
            "target": t_key,
            "label": r.relationship_type,
            "type": r.relationship_type,
            "confidence": r.confidence
        })

    # Also synthesize Asset <-> CryptoFinding virtual edges if Relationship table is sparse
    # This ensures the graph is populated from real scan evidence even if relationship ingestion hasn't run
    findings = db.query(CryptoFinding).limit(max_nodes_val - len(nodes_map)).all()
    for f in findings:
        if not f.asset_id:
            continue
        a_key = f"Asset:{f.asset_id}"
        f_key = f"Finding:{f.id}"

        if a_key not in nodes_map:
            asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
            label = asset.hostname or asset.provider_resource_id or f.asset_id[:8] if asset else f.asset_id[:8]
            nodes_map[a_key] = {
                "id": a_key,
                "entity_type": "Asset",
                "entity_id": f.asset_id,
                "label": label,
                "category": asset.asset_type if asset else "HOST",
                "details": {}
            }

        if f_key not in nodes_map:
            nodes_map[f_key] = {
                "id": f_key,
                "entity_type": "CryptoFinding",
                "entity_id": f.id,
                "label": f.raw_algorithm_name or f_key,
                "category": f.finding_type or "UNKNOWN",
                "details": {"finding_type": f.finding_type, "location": f.location_identifier}
            }

        edges.append({
            "id": f"synthetic-{f.id}",
            "source": a_key,
            "target": f_key,
            "label": "HAS_CRYPTO_FINDING",
            "type": "HAS_CRYPTO_FINDING",
            "confidence": "OBSERVED"
        })

    return {
        "root_entity_id": None,
        "nodes": list(nodes_map.values()),
        "edges": edges,
        "total_nodes": len(nodes_map),
        "total_edges": len(edges)
    }

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
    """
    root_type = normalize_entity_type(entity_type)
    if not root_type:
        raise HTTPException(status_code=400, detail=f"Invalid root entity_type '{entity_type}'")

    target_node_type = normalize_entity_type(node_type)
    rel_type_str = relationship_type if isinstance(relationship_type, str) and relationship_type.upper() not in ["ALL", ""] else None
    max_nodes_val = max_nodes if isinstance(max_nodes, int) else 50

    visited_entities: Set[Tuple[str, str]] = set()
    nodes_map: Dict[str, Dict[str, Any]] = {}
    raw_edges: List[Dict[str, Any]] = []
    truncated = False

    queue: List[Tuple[str, str, int]] = [(root_type, entity_id, 0)]

    while queue and len(nodes_map) < max_nodes_val:
        curr_type, curr_id, curr_depth = queue.pop(0)

        entity_key = f"{curr_type}:{curr_id}"
        if (curr_type, curr_id) in visited_entities:
            continue
        visited_entities.add((curr_type, curr_id))

        # Lookup entity for label
        label = f"{curr_type} ({curr_id[:8]})"
        category = curr_type
        details = {}
        entity_found = False

        if curr_type == "Asset":
            a = db.query(Asset).filter(Asset.id == curr_id).first()
            if a:
                entity_found = True
                label = a.hostname or a.ip_address or a.provider_resource_id or f"Asset:{a.id[:8]}"
                category = a.asset_type
                details = {"environment": a.environment, "ip": a.ip_address}
        elif curr_type == "Service":
            s = db.query(Service).filter(Service.id == curr_id).first()
            if s:
                entity_found = True
                label = f"{s.service_name}:{s.port}"
                category = s.application_protocol.value if hasattr(s.application_protocol, 'value') else str(s.application_protocol)
                details = {"port": s.port, "protocol": s.transport_protocol.value if hasattr(s.transport_protocol, 'value') else str(s.transport_protocol)}
        elif curr_type == "CryptoObject":
            c = db.query(CryptoObject).filter(CryptoObject.id == curr_id).first()
            if c:
                entity_found = True
                label = c.canonical_name
                category = c.object_type.value if hasattr(c.object_type, 'value') else str(c.object_type)
                details = {"algorithm": c.canonical_name, "key_size": c.key_size_bits}

        if not entity_found and curr_depth == 0:
            raise HTTPException(
                status_code=404,
                detail=f"Entity {curr_type}:{curr_id} not found in inventory database"
            )

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

        query_out = db.query(Relationship).filter(
            Relationship.source_entity_type == curr_type,
            Relationship.source_entity_id == curr_id
        )
        query_in = db.query(Relationship).filter(
            Relationship.target_entity_type == curr_type,
            Relationship.target_entity_id == curr_id
        )

        if rel_type_str:
            query_out = query_out.filter(Relationship.relationship_type == rel_type_str)
            query_in = query_in.filter(Relationship.relationship_type == rel_type_str)

        for rel in query_out.all():
            next_t = rel.target_entity_type
            if target_node_type and next_t != target_node_type:
                continue
            raw_edges.append({
                "id": rel.id,
                "source": entity_key,
                "target": f"{next_t}:{rel.target_entity_id}",
                "label": rel.relationship_type.value if hasattr(rel.relationship_type, 'value') else str(rel.relationship_type),
                "type": rel.relationship_type.value if hasattr(rel.relationship_type, 'value') else str(rel.relationship_type),
                "confidence": rel.confidence.value if hasattr(rel.confidence, 'value') else str(rel.confidence)
            })
            if (next_t, rel.target_entity_id) not in visited_entities:
                queue.append((next_t, rel.target_entity_id, curr_depth + 1))

        for rel in query_in.all():
            prev_t = rel.source_entity_type
            if target_node_type and prev_t != target_node_type:
                continue
            raw_edges.append({
                "id": rel.id,
                "source": f"{prev_t}:{rel.source_entity_id}",
                "target": entity_key,
                "label": rel.relationship_type.value if hasattr(rel.relationship_type, 'value') else str(rel.relationship_type),
                "type": rel.relationship_type.value if hasattr(rel.relationship_type, 'value') else str(rel.relationship_type),
                "confidence": rel.confidence.value if hasattr(rel.confidence, 'value') else str(rel.confidence)
            })
            if (prev_t, rel.source_entity_id) not in visited_entities:
                queue.append((prev_t, rel.source_entity_id, curr_depth + 1))

    valid_edges = []
    seen_edge_ids = set()
    for edge in raw_edges:
        if edge["id"] not in seen_edge_ids:
            if edge["source"] in nodes_map and edge["target"] in nodes_map:
                valid_edges.append(edge)
                seen_edge_ids.add(edge["id"])

    return {
        "root_entity_id": f"{root_type}:{entity_id}",
        "nodes": list(nodes_map.values()),
        "edges": valid_edges
    }
