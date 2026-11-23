"""Company onboarding: creates tenant, admin, signing keys and hierarchy schema."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, security
from ..config import MASTER_KEY
from ..db import get_db
from ..hierarchy import PHARMA_TEMPLATE, TEMPLATES, validate_definition
from ..models import Company, HierarchySchema, SigningKey, User
from ..schemas import OnboardingIn, SchemaOut

router = APIRouter(prefix="/api/v1", tags=["onboarding"])


def provision_company(
    db: Session,
    *,
    company_name: str,
    admin_email: str,
    admin_password: str,
    admin_name: str,
    definition: dict,
    schema_name: str,
) -> tuple[Company, User, HierarchySchema]:
    company = Company(
        id=crypto.new_id("org"),
        name=company_name,
        settings_json=json.dumps({"alert_emails": []}),
    )
    db.add(company)

    admin = User(
        id=crypto.new_id("usr"),
        company_id=company.id,
        email=admin_email.lower(),
        name=admin_name,
        password_hash=security.hash_password(admin_password),
        role="org_admin",
    )
    db.add(admin)

    # Signing keys — one per purpose. kid embeds org + purpose + public prefix.
    short = company.id.split("_")[1][:8]
    keys: dict[str, SigningKey] = {}
    for purpose in ("entity_qr", "relationship"):
        pub, priv = crypto.generate_keypair()
        kid = f"kid_{short}_{purpose}_{pub[:10]}"
        key = SigningKey(
            id=kid,
            company_id=company.id,
            purpose=purpose,
            public_key=pub,
            private_key_wrapped=crypto.wrap_private_key(priv, MASTER_KEY),
        )
        db.add(key)
        keys[purpose] = key

    errors = validate_definition(definition)
    if errors:
        raise HTTPException(400, {"schema_errors": errors})

    schema = HierarchySchema(
        id=crypto.new_id("sch"),
        company_id=company.id,
        name=schema_name,
        version=1,
        is_active=True,
        definition_json=json.dumps(definition, sort_keys=True),
        created_by=admin.id,
    )
    db.add(schema)
    db.flush()

    audit.record(
        db,
        company_id=company.id,
        action="company.onboard",
        subject_type="company",
        subject_id=company.id,
        data={
            "name": company_name,
            "schema": schema_name,
            "keys": sorted(keys),
            "admin": admin_email.lower(),
        },
        actor_id=admin.id,
        actor_role="org_admin",
    )
    db.commit()
    return company, admin, schema


@router.get("/templates")
def list_templates():
    return [
        {"name": t["name"], "definition": t["definition"]}
        for t in TEMPLATES
    ]


@router.post("/onboarding/company", status_code=201)
def onboard(body: OnboardingIn, db: Session = Depends(get_db)):
    """Guided-onboarding API. The UI wizard (docs/02) collects the answers and
    posts the resulting configuration here."""
    existing = db.scalar(
        select(User).where(User.email == body.admin.email.lower())
    )
    if existing is not None:
        raise HTTPException(409, "An account with this email already exists")

    if body.hierarchy is not None:
        definition = body.hierarchy
        schema_name = "custom"
    else:
        template = next(
            (t for t in TEMPLATES if t["name"] == body.template), PHARMA_TEMPLATE
        )
        definition = template["definition"]
        schema_name = template["name"]

    company, admin, schema = provision_company(
        db,
        company_name=body.company_name,
        admin_email=body.admin.email,
        admin_password=body.admin.password,
        admin_name=body.admin.name,
        definition=definition,
        schema_name=schema_name,
    )
    token = security.create_access_token(admin)
    return {
        "company_id": company.id,
        "schema_id": schema.id,
        "admin": {"id": admin.id, "email": admin.email, "role": admin.role},
        "access_token": token,
        "token_type": "bearer",
    }


@router.get("/schema-preview/{template_name}")
def schema_preview(template_name: str):
    template = next((t for t in TEMPLATES if t["name"] == template_name), None)
    if template is None:
        raise HTTPException(404, "Unknown template")
    return {"name": template["name"], "definition": template["definition"]}
