import os
import re
import hmac
import hashlib
import base64
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, String, DateTime, Integer, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./empiremaps.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
if DATABASE_URL.startswith("sqlite"):
    # SQLite has no schemas. Translate the logical PostgreSQL schema for ALL
    # connections, including request sessions, not only during create_all().
    engine = engine.execution_options(schema_translate_map={"empiremaps": None})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

if not DATABASE_URL.startswith("sqlite"):
    with engine.begin() as connection:
        connection.execute(text('CREATE SCHEMA IF NOT EXISTS empiremaps'))

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "web_users"
    __table_args__ = {"schema": "empiremaps"}
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)

app = FastAPI(title="Empiremaps API", version="0.1.0", docs_url="/api/docs", redoc_url=None)
SECRET = os.getenv("JWT_SECRET_KEY", "")
if not SECRET:
    SECRET = "local-development-only-change-before-deploy"

class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

class GameQuery(BaseModel):
    server: str = Field(default="PL1", min_length=2, max_length=24)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return base64.urlsafe_b64encode(salt).decode().rstrip("=") + "." + base64.urlsafe_b64encode(digest).decode().rstrip("=")

def verify_password(password: str, encoded: str) -> bool:
    try:
        salt_s, digest_s = encoded.split(".", 1)
        salt = base64.urlsafe_b64decode(salt_s + "=" * (-len(salt_s) % 4))
        expected = base64.urlsafe_b64decode(digest_s + "=" * (-len(digest_s) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def make_token(user: User) -> str:
    header = b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    payload = b64(json.dumps({"sub":str(user.id),"email":user.email,"exp":int(time.time())+60*60*24*7}).encode())
    body = f"{header}.{payload}"
    sig = b64(hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"

def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Zaloguj się, aby kontynuować.")
    try:
        token = authorization[7:]
        head, payload, signature = token.split(".")
        body = f"{head}.{payload}"
        expected = b64(hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if data["exp"] < time.time():
            raise ValueError("expired")
        user = db.get(User, int(data["sub"]))
        if not user:
            raise ValueError("user")
        return user
    except Exception:
        raise HTTPException(401, "Sesja wygasła. Zaloguj się ponownie.")

@app.get("/api/health")
def health():
    return {"ok": True, "service": "Empiremaps Web API", "version": "0.1.0", "time": datetime.now(timezone.utc).isoformat()}

@app.post("/api/auth/register")
def register(body: Credentials, db: Session = Depends(get_db)):
    email = str(body.email).lower().strip()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Konto z tym adresem e-mail już istnieje.")
    user = User(email=email, password_hash=password_hash(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"token": make_token(user), "user": {"id": user.id, "email": user.email}}

@app.post("/api/auth/login")
def login(body: Credentials, db: Session = Depends(get_db)):
    email = str(body.email).lower().strip()
    user = db.scalar(select(User).where(User.email == email))
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Nieprawidłowy e-mail lub hasło.")
    return {"token": make_token(user), "user": {"id": user.id, "email": user.email}}

@app.get("/api/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "created_at": user.created_at.isoformat()}

SERVERS = ["PL1","PL2","INT1","DE1","FR1","E4K_PL1","E4K_FR1","E4K_DE1","E4K_INT1"]
def game_headers(server: str):
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,24}", server):
        raise HTTPException(400, "Nieprawidłowy identyfikator serwera.")
    headers = {"Accept":"application/json","gge-server":server.upper(),"User-Agent":"Empiremaps-Web/0.1"}
    key = os.getenv("GGETRACKER_API_KEY")
    if key:
        headers["X-Api-Key"] = key
    return headers

async def tracker_get(path: str, server: str):
    url = "https://api.gge-tracker.com/api/v1/" + path.lstrip("/")
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            response = await client.get(url, headers=game_headers(server))
        if response.status_code == 404:
            raise HTTPException(404, "Nie znaleziono danych. Sprawdź nazwę i serwer.")
        if response.status_code == 429:
            raise HTTPException(429, "Limit zapytań do GGE Tracker. Spróbuj za chwilę.")
        if response.status_code >= 400:
            raise HTTPException(502, f"GGE Tracker zwrócił błąd {response.status_code}.")
        return response.json()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "Nie udało się połączyć z GGE Tracker.")

@app.get("/api/game/servers")
def servers(user: User = Depends(current_user)):
    return {"servers": SERVERS}

@app.get("/api/game/player/{name}")
async def player(name: str, server: str = "PL1", user: User = Depends(current_user)):
    if len(name) > 80 or not name.strip():
        raise HTTPException(400, "Podaj prawidłową nazwę gracza.")
    data = await tracker_get("players/" + quote(name.strip(), safe=""), server)
    if isinstance(data, list):
        data = data[0] if data else {}
    return {"data": data, "server": server.upper()}

@app.get("/api/game/alliance/{name}")
async def alliance(name: str, server: str = "PL1", user: User = Depends(current_user)):
    if len(name) > 100 or not name.strip():
        raise HTTPException(400, "Podaj prawidłową nazwę sojuszu.")
    data = await tracker_get("alliances/name/" + quote(name.strip(), safe=""), server)
    if isinstance(data, list):
        data = data[0] if data else {}
    return {"data": data, "server": server.upper()}

@app.get("/api/game/player/{name}/fortress-history")
async def fortress_history(name: str, server: str = "PL1", user: User = Depends(current_user)):
    profile = await tracker_get("players/" + quote(name.strip(), safe=""), server)
    if isinstance(profile, list):
        profile = profile[0] if profile else {}
    player_id = profile.get("player_id") or profile.get("id")
    if not player_id:
        raise HTTPException(404, "Nie znaleziono gracza w tym serwerze.")
    history = await tracker_get(f"dungeons/player/{player_id}?lastDays=365", server)
    return {"player": profile, "dungeons": history.get("dungeons", []), "server": server.upper()}

@app.get("/api/game/server/statistics")
async def server_statistics(server: str = "PL1", user: User = Depends(current_user)):
    return {"data": await tracker_get("server/statistics", server), "server": server.upper()}

@app.get("/api/features")
def features(user: User = Depends(current_user)):
    return {
        "available": ["player_profile","alliance_profile","server_statistics","fortress_history"],
        "in_development": ["live_map","target_radar","fortress_scanner","storm_islands","event_calendar","rankings","web_notifications"],
        "note": "Funkcje zewnętrzne wymagają доступności GGE Tracker i właściwego serwera."
    }

if SITE.exists():
    app.mount("/", StaticFiles(directory=str(SITE), html=True), name="site")
