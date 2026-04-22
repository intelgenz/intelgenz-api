"""
Intelgenz Dummy API
===================
FastAPI 0.115 · Python 3.12

Endpoints
---------
POST /auth/login                          – Login (email + password)
GET  /auth/me                             – Current user profile
GET  /clients                             – List client profiles for logged-in user
GET  /blogs?page=1&page_size=5            – Paginated blog list
GET  /news?page=1&page_size=5             – Paginated news list
GET  /threats?page=1&page_size=6          – Paginated emerging threats (card / customized view)
GET  /threats/all?page=1&page_size=10     – All threats flat table view
GET  /threats/{threat_id}/report         – Full threat report detail
GET  /health                              – Health check
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SECRET_KEY = "intelgenz-super-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours

DATA_FILE = Path(__file__).parent / "data.json"

# ---------------------------------------------------------------------------
# Load dummy data once at startup
# ---------------------------------------------------------------------------
with DATA_FILE.open("r", encoding="utf-8") as _f:
    _DB: dict[str, list[dict]] = json.load(_f)

USERS: list[dict] = _DB["users"]
CLIENTS: list[dict] = _DB["clients"]
BLOGS: list[dict] = _DB["blogs"]
NEWS: list[dict] = _DB["news"]
THREATS: list[dict] = _DB["emerging_threats"]

# ---------------------------------------------------------------------------
# Password / JWT helpers
# ---------------------------------------------------------------------------
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def _find_user_by_email(email: str) -> Optional[dict]:
    return next((u for u in USERS if u["email"].lower() == email.lower()), None)


def _find_user_by_id(user_id: int) -> Optional[dict]:
    return next((u for u in USERS if u["id"] == user_id), None)


def _verify_password(plain: str, stored: str) -> bool:
    # Dummy data stores plain text passwords for demo purposes
    return plain == stored


def _create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def _get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Any = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = _find_user_by_id(int(user_id))
    if user is None:
        raise credentials_exception
    return user


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60  # seconds


class UserProfile(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    avatar: str
    organization: str
    plan: str


class ClientProfile(BaseModel):
    id: int
    name: str
    industry: str
    type: str
    region: str
    reviewed_by: str
    logo: str
    risk_score: int
    status: str


class BlogItem(BaseModel):
    id: int
    title: str
    summary: str
    image: str
    author: str
    published_at: str
    category: str
    read_time: str
    url: str


class NewsItem(BaseModel):
    id: int
    title: str
    summary: str
    image: str
    source: str
    published_at: str
    category: str
    url: str


class ThreatCard(BaseModel):
    id: int
    date: str
    title: str
    threat_type: str
    threat_group_names: list[str]
    malware_name: str
    target_regions: list[str]
    target_countries: list[str]
    target_sectors: list[str]
    severity: str
    report_url: str


class ThreatRow(BaseModel):
    id: int
    date: str
    title: str
    threat_type: str
    threat_group_names: list[str]
    malware_name: str
    target_sectors: list[str]
    target_regions: list[str]
    severity: str
    report_url: str


class ThreatReport(BaseModel):
    id: int
    date: str
    title: str
    threat_type: str
    threat_group_names: list[str]
    malware_name: str
    target_regions: list[str]
    target_countries: list[str]
    target_sectors: list[str]
    severity: str
    description: str
    iocs: dict
    mitre_ttps: list[str]
    report_url: str


class PaginatedResponse(BaseModel):
    page: int
    page_size: int
    total: int
    total_pages: int
    data: list[Any]


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Intelgenz Dummy API",
    description="Dummy REST API for the Intelgenz Cyber Threat Intelligence platform.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"], summary="Health check")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.post(
    "/auth/login",
    response_model=TokenResponse,
    tags=["Auth"],
    summary="Login with email and password",
)
def login(body: LoginRequest):
    """
    Authenticate a user with **email** and **password**.

    Demo credentials (any of these work):
    | Email | Password |
    |---|---|
    | john.blackwell@intelgenz.com | Pass@1234 |
    | alice.chen@intelgenz.com | SecurePass#99 |
    | marcos.silva@intelgenz.com | M@rcos2025 |
    | priya.nair@intelgenz.com | Priya$2024 |
    | david.osei@intelgenz.com | D@vid!Africa |
    """
    user = _find_user_by_email(body.email)
    if not user or not _verify_password(body.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    token = _create_access_token({"sub": str(user["id"])})
    return TokenResponse(access_token=token)


# OAuth2 form-based login (for Swagger "Authorize" button)
@app.post(
    "/auth/token",
    response_model=TokenResponse,
    tags=["Auth"],
    summary="OAuth2 token endpoint (Swagger UI)",
    include_in_schema=False,
)
def token_form(form_data: OAuth2PasswordRequestForm = Depends()):
    user = _find_user_by_email(form_data.username)
    if not user or not _verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    token = _create_access_token({"sub": str(user["id"])})
    return TokenResponse(access_token=token)


@app.get(
    "/auth/me",
    response_model=UserProfile,
    tags=["Auth"],
    summary="Get current user profile",
)
def me(current_user: dict = Depends(_get_current_user)):
    """Returns the profile of the authenticated user."""
    return UserProfile(**{k: current_user[k] for k in UserProfile.model_fields})


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------
@app.get(
    "/clients",
    response_model=list[ClientProfile],
    tags=["Clients"],
    summary="List client / vendor profiles",
)
def get_clients(current_user: dict = Depends(_get_current_user)):
    """Returns all client profiles visible to the authenticated user."""
    return [ClientProfile(**c) for c in CLIENTS]


@app.get(
    "/clients/{client_id}",
    response_model=ClientProfile,
    tags=["Clients"],
    summary="Get a single client profile",
)
def get_client(client_id: int, current_user: dict = Depends(_get_current_user)):
    client = next((c for c in CLIENTS if c["id"] == client_id), None)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return ClientProfile(**client)


# ---------------------------------------------------------------------------
# Blogs
# ---------------------------------------------------------------------------
@app.get(
    "/blogs",
    response_model=PaginatedResponse,
    tags=["Blogs & News"],
    summary="List blog posts (paginated)",
)
def get_blogs(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(5, ge=1, le=20, description="Items per page"),
    current_user: dict = Depends(_get_current_user),
):
    """Returns a paginated list of blog articles."""
    total = len(BLOGS)
    start = (page - 1) * page_size
    end = start + page_size
    items = [BlogItem(**b) for b in BLOGS[start:end]]
    return PaginatedResponse(
        page=page,
        page_size=page_size,
        total=total,
        total_pages=-((-total) // page_size),
        data=items,
    )


# ---------------------------------------------------------------------------
# News
# ---------------------------------------------------------------------------
@app.get(
    "/news",
    response_model=PaginatedResponse,
    tags=["Blogs & News"],
    summary="List news items (paginated)",
)
def get_news(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(5, ge=1, le=20, description="Items per page"),
    current_user: dict = Depends(_get_current_user),
):
    """Returns a paginated list of cybersecurity news items."""
    total = len(NEWS)
    start = (page - 1) * page_size
    end = start + page_size
    items = [NewsItem(**n) for n in NEWS[start:end]]
    return PaginatedResponse(
        page=page,
        page_size=page_size,
        total=total,
        total_pages=-((-total) // page_size),
        data=items,
    )


# ---------------------------------------------------------------------------
# Emerging Threats – Customized Card View
# ---------------------------------------------------------------------------
@app.get(
    "/threats",
    response_model=PaginatedResponse,
    tags=["Emerging Threats"],
    summary="Emerging threats – card / customized view (paginated)",
)
def get_threats_cards(
    page: int = Query(1, ge=1),
    page_size: int = Query(6, ge=1, le=20),
    severity: Optional[str] = Query(None, description="Filter by severity: High | Medium | Low | Critical"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type e.g. Ransomware"),
    current_user: dict = Depends(_get_current_user),
):
    """
    Returns paginated emerging threat cards for the **Customized View**.
    Supports optional filtering by `severity` and `threat_type`.
    """
    filtered = THREATS
    if severity:
        filtered = [t for t in filtered if t["severity"].lower() == severity.lower()]
    if threat_type:
        filtered = [t for t in filtered if t["threat_type"].lower() == threat_type.lower()]

    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    items = [ThreatCard(**t) for t in filtered[start:end]]
    return PaginatedResponse(
        page=page,
        page_size=page_size,
        total=total,
        total_pages=-((-total) // page_size),
        data=items,
    )


# ---------------------------------------------------------------------------
# Emerging Threats – All View (table)
# ---------------------------------------------------------------------------
@app.get(
    "/threats/all",
    response_model=PaginatedResponse,
    tags=["Emerging Threats"],
    summary="Emerging threats – all / table view (paginated)",
)
def get_threats_all(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
    severity: Optional[str] = Query(None),
    threat_type: Optional[str] = Query(None),
    current_user: dict = Depends(_get_current_user),
):
    """
    Returns paginated emerging threats for the **All View** flat table.
    Supports optional filtering by `severity` and `threat_type`.
    """
    filtered = THREATS
    if severity:
        filtered = [t for t in filtered if t["severity"].lower() == severity.lower()]
    if threat_type:
        filtered = [t for t in filtered if t["threat_type"].lower() == threat_type.lower()]

    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    items = [ThreatRow(**t) for t in filtered[start:end]]
    return PaginatedResponse(
        page=page,
        page_size=page_size,
        total=total,
        total_pages=-((-total) // page_size),
        data=items,
    )


# ---------------------------------------------------------------------------
# Threat Report Detail
# ---------------------------------------------------------------------------
@app.get(
    "/threats/{threat_id}/report",
    response_model=ThreatReport,
    tags=["Emerging Threats"],
    summary="Get full threat report by ID",
)
def get_threat_report(
    threat_id: int,
    current_user: dict = Depends(_get_current_user),
):
    """
    Returns the full detailed threat report for a given threat ID,
    including description, IOCs, and MITRE ATT&CK TTPs.
    """
    threat = next((t for t in THREATS if t["id"] == threat_id), None)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat report not found")
    return ThreatReport(**threat)
