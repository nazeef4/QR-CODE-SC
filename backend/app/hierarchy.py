"""Configurable supply-chain hierarchy: schema validation and binding rules.

A company's hierarchy is *data*, not code. The schema definition is JSON:

{
  "version": 1,
  "entity_types": {
    "medicine_pack": {"kind": "object", "serial_required": true,
                      "lifecycle": ["registered","manufactured","packed", …]},
    "product_box":   {"kind": "packaging", …},
    "distributor":   {"kind": "party", …}
  },
  "relations": [
    {"parent": "product_box", "child": "medicine_pack", "label": "contains"}
  ],
  "default_lifecycle": ["registered", …]
}

Different schemas can be active side by side inside one company so different
product families can follow different structures.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Entity, HierarchySchema

KINDS = {"object", "packaging", "lot", "party", "location", "shipment"}

DEFAULT_LIFECYCLE = [
    "registered",
    "manufactured",
    "packed",
    "dispatched",
    "received",
    "on_sale",
    "sold",
    "recalled",
    "destroyed",
]

# --------------------------------------------------------------------------- #
# Starter templates offered by the onboarding wizard
# --------------------------------------------------------------------------- #
def _types(*specs: tuple[str, str, bool]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, kind, serial in specs:
        out[name] = {"kind": kind, "serial_required": serial, "lifecycle": list(DEFAULT_LIFECYCLE)}
    return out


PHARMA_TEMPLATE: dict[str, Any] = {
    "name": "pharma-classic",
    "definition": {
        "version": 1,
        "default_lifecycle": DEFAULT_LIFECYCLE,
        "entity_types": _types(
            ("manufacturer", "party", False),
            ("batch", "lot", True),
            ("medicine_pack", "object", True),
            ("product_box", "packaging", True),
            ("shipping_carton", "packaging", True),
            ("container", "shipment", True),
            ("distributor", "party", False),
            ("retailer", "party", False),
        ),
        "relations": [
            {"parent": "manufacturer", "child": "batch", "label": "produces"},
            {"parent": "batch", "child": "medicine_pack", "label": "filled_from"},
            {"parent": "product_box", "child": "medicine_pack", "label": "contains"},
            {"parent": "shipping_carton", "child": "product_box", "label": "contains"},
            {"parent": "container", "child": "shipping_carton", "label": "loads"},
            {"parent": "distributor", "child": "container", "label": "custody_of"},
            {"parent": "retailer", "child": "distributor", "label": "supplied_by"},
        ],
    },
}

GENERAL_TEMPLATE: dict[str, Any] = {
    "name": "general-manufacturing",
    "definition": {
        "version": 1,
        "default_lifecycle": DEFAULT_LIFECYCLE,
        "entity_types": _types(
            ("raw_material_supplier", "party", False),
            ("manufacturing_batch", "lot", True),
            ("product_unit", "object", True),
            ("packaging", "packaging", True),
            ("warehouse", "location", False),
            ("distributor", "party", False),
            ("retailer", "party", False),
        ),
        "relations": [
            {"parent": "raw_material_supplier", "child": "manufacturing_batch", "label": "supplies"},
            {"parent": "manufacturing_batch", "child": "product_unit", "label": "produces"},
            {"parent": "packaging", "child": "product_unit", "label": "contains"},
            {"parent": "warehouse", "child": "packaging", "label": "stores"},
            {"parent": "distributor", "child": "warehouse", "label": "collects_from"},
            {"parent": "retailer", "child": "distributor", "label": "supplied_by"},
        ],
    },
}

TEMPLATES = [PHARMA_TEMPLATE, GENERAL_TEMPLATE]


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def validate_definition(defn: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(defn, dict):
        return ["definition must be a JSON object"]
    types = defn.get("entity_types")
    rels = defn.get("relations")
    if not isinstance(types, dict) or not types:
        errors.append("'entity_types' must be a non-empty object")
        types = {}
    if not isinstance(rels, list):
        errors.append("'relations' must be a list")
        rels = []
    for tname, tdef in types.items():
        if not isinstance(tdef, dict):
            errors.append(f"entity type '{tname}' must be an object")
            continue
        kind = tdef.get("kind", "object")
        if kind not in KINDS:
            errors.append(f"entity type '{tname}': kind '{kind}' not in {sorted(KINDS)}")
        lc = tdef.get("lifecycle") or defn.get("default_lifecycle") or DEFAULT_LIFECYCLE
        if not isinstance(lc, list) or not lc:
            errors.append(f"entity type '{tname}': lifecycle must be a non-empty list")
    for i, rel in enumerate(rels):
        if not isinstance(rel, dict):
            errors.append(f"relations[{i}] must be an object")
            continue
        p, c = rel.get("parent"), rel.get("child")
        if p not in types:
            errors.append(f"relations[{i}]: unknown parent type '{p}'")
        if c not in types:
            errors.append(f"relations[{i}]: unknown child type '{c}'")
        if p == c:
            errors.append(f"relations[{i}]: parent and child must differ")
    # cycle detection over type-level relation graph
    graph = {k: [] for k in types}
    for rel in rels:
        if isinstance(rel, dict) and rel.get("parent") in graph and rel.get("child") in graph:
            graph[rel["child"]].append(rel["parent"])  # child → parent direction
    def visit(node: str, stack: set[str]) -> bool:
        if node in stack:
            return True
        stack.add(node)
        for nxt in graph.get(node, []):
            if visit(nxt, stack):
                return True
        stack.discard(node)
        return False
    if any(visit(n, set()) for n in graph):
        errors.append("relations form a cycle at the type level")
    return errors


def lifecycle_for(defn: dict[str, Any], entity_type: str) -> list[str]:
    t = defn.get("entity_types", {}).get(entity_type, {})
    return list(t.get("lifecycle") or defn.get("default_lifecycle") or DEFAULT_LIFECYCLE)


# --------------------------------------------------------------------------- #
# Runtime helpers
# --------------------------------------------------------------------------- #
def active_schema(db: Session, company_id: str) -> HierarchySchema:
    row = db.scalar(
        select(HierarchySchema)
        .where(HierarchySchema.company_id == company_id, HierarchySchema.is_active.is_(True))
        .order_by(HierarchySchema.version.desc())
    )
    if row is None:
        raise HTTPException(409, "Company has no active hierarchy schema")
    return row


def schema_def(row: HierarchySchema) -> dict[str, Any]:
    return json.loads(row.definition_json)


def allowed_child_types(defn: dict[str, Any], parent_type: str) -> set[str]:
    return {r["child"] for r in defn.get("relations", []) if r.get("parent") == parent_type}


def check_binding(db: Session, defn: dict[str, Any], child: Entity, parent: Entity) -> None:
    """Raise HTTPException when child→parent violates the configured hierarchy."""
    if child.company_id != parent.company_id:
        raise HTTPException(403, "Cross-company bindings are forbidden")
    if child.id == parent.id:
        raise HTTPException(400, "An entity cannot be its own parent")
    if child.revoked_at or parent.revoked_at:
        raise HTTPException(409, "Cannot bind revoked entities")
    if child.parent_id:
        raise HTTPException(409, "Child already bound — unbind first (audited operation)")
    rels = [
        r for r in defn.get("relations", [])
        if r.get("parent") == parent.entity_type and r.get("child") == child.entity_type
    ]
    if not rels:
        raise HTTPException(
            400,
            f"Relation '{parent.entity_type}' → '{child.entity_type}' is not defined "
            "in the company hierarchy schema",
        )
    # walk ancestors to prevent cycles
    seen = {child.id}
    cursor: Entity | None = parent
    while cursor is not None:
        if cursor.id in seen:
            raise HTTPException(409, "Binding would create a cycle")
        seen.add(cursor.id)
        cursor = db.get(Entity, cursor.parent_id) if cursor.parent_id else None


def entity_lifecycle(defn: dict[str, Any], entity_type: str) -> list[str]:
    return lifecycle_for(defn, entity_type)
