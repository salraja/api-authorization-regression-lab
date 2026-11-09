"""Two deliberately comparable local fixtures. No external targets are used."""
from copy import deepcopy
from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field


@dataclass(frozen=True)
class Principal:
    name: str
    tenant: str
    role: str = "member"


# These are public fixture identifiers, not credentials for a deployed service.
ACTORS = {
    "alice": Principal("alice", "north"),
    "bob": Principal("bob", "north"),
    "nora": Principal("nora", "north", "admin"),
    "eve": Principal("eve", "south"),
    "sam": Principal("sam", "south", "admin"),
}
INITIAL_INVOICES = {
    "inv-100": {"id": "inv-100", "tenant": "north", "owner": "alice", "memo": "Synthetic north invoice"},
    "inv-200": {"id": "inv-200", "tenant": "south", "owner": "eve", "memo": "Synthetic south invoice"},
}
bearer = HTTPBearer(auto_error=False)


def principal(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]) -> Principal:
    if not credentials or credentials.credentials not in ACTORS:
        raise HTTPException(status_code=401, detail="Authentication required")
    return ACTORS[credentials.credentials]


class MemoUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    memo: str = Field(min_length=1, max_length=120)


def create_app(mode: Literal["secure", "vulnerable"] = "secure") -> FastAPI:
    if mode not in {"secure", "vulnerable"}:
        raise ValueError("Unsupported fixture mode")
    app = FastAPI(title="API Authorization Regression Lab", version="0.1.0")
    invoices = deepcopy(INITIAL_INVOICES)

    def authorized_invoice(invoice_id: str, actor: Principal) -> dict:
        invoice = invoices.get(invoice_id)
        if invoice is None:
            raise HTTPException(status_code=404, detail="Invoice not found")
        # Vulnerable mode intentionally authenticates without checking object access.
        if mode == "secure" and (
            actor.tenant != invoice["tenant"]
            or (actor.name != invoice["owner"] and actor.role != "admin")
        ):
            raise HTTPException(status_code=403, detail="Object access denied")
        return invoice

    @app.get("/catalog")
    def catalog() -> dict:
        return {"items": ["Synthetic public product"]}

    @app.get("/invoices/{invoice_id}")
    def read_invoice(invoice_id: str, actor: Annotated[Principal, Depends(principal)]) -> dict:
        return dict(authorized_invoice(invoice_id, actor))

    @app.patch("/invoices/{invoice_id}")
    def update_invoice(invoice_id: str, update: MemoUpdate, actor: Annotated[Principal, Depends(principal)]) -> dict:
        invoice = authorized_invoice(invoice_id, actor)
        invoice["memo"] = update.memo
        return dict(invoice)

    return app


# The optional web server always uses the secure fixture. The CLI selects its own mode.
app = create_app()
