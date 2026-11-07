import os
import asyncio
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
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

if not DATABASE_URL.startswith("sqlite"):
    with engine.begin() as connection:
        connection.execute(text('CREATE SCHEMA IF NOT EXISTS empiremaps'))

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "web_users"
    __table_args__ = {"schema": None} if DATABASE_URL.startswith("sqlite") else {"schema": "empiremaps"}
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

SERVERS = ["PL1","PL2","INT1","DE1","FR1","E4K_PL1","E4K_PL1_BETA","E4K_FR1","E4K_DE1","E4K_INT1"]
def game_headers(server: str):
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,40}", server):
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



# Discord-bot feature port: HTTP services for the Empiremaps web interface.
BOT_API_BASE = "https://api.gge-tracker.com/api/v1"

def bot_headers(server: str):
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,40}", server):
        raise HTTPException(400, "Nieprawidłowy identyfikator serwera.")
    headers = {
        "Accept": "application/json",
        "gge-server": server.upper(),
        "User-Agent": "Mozilla/5.0 Empiremaps-Web/1.0 (GGE Assistant web port)",
    }
    key = os.getenv("GGETRACKER_API_KEY")
    if key:
        headers["X-Api-Key"] = key
    return headers

async def bot_tracker_get(path: str, server: str, params: dict | None = None):
    url = BOT_API_BASE + "/" + path.lstrip("/")
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
            response = await client.get(url, headers=bot_headers(server), params=params)
        if response.status_code == 404:
            raise HTTPException(404, "Brak danych dla wybranego serwera lub obiektu.")
        if response.status_code == 429:
            raise HTTPException(429, "API GGE Tracker ograniczyło liczbę zapytań. Spróbuj ponownie za chwilę.")
        if response.status_code >= 400:
            raise HTTPException(502, f"GGE Tracker zwrócił błąd {response.status_code}.")
        return response.json()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "Nie udało się połączyć z API GGE Tracker.")


BOT_SUGGEST_CACHE: dict[str, dict] = {}
BOT_SCAN_STATUS: dict[str, dict] = {}
BOT_SCAN_TASKS: dict[str, asyncio.Task] = {}

async def _scan_server_for_suggestions(server: str):
    """Pobiera indeks nazw graczy/sojuszy z paginowanego API; bez zależności od Discorda."""
    key = server.upper()
    status = BOT_SCAN_STATUS.setdefault(key, {})
    status.update({"running": True, "started_at": datetime.now(timezone.utc).isoformat(), "error": None})
    try:
        first = await bot_tracker_get("players", key, {
            "limit": 100, "page": 1, "banFilter": 0, "allianceFilter": -1,
            "protectionFilter": -1, "inactiveFilter": 1, "kingdomFilter": 999,
            "orderBy": "might_current", "orderType": "DESC",
        })
        def unpack(payload):
            if isinstance(payload, list):
                return payload, {}
            if not isinstance(payload, dict):
                return [], {}
            items = payload.get("players", payload.get("items", payload.get("data", [])))
            if isinstance(items, dict):
                items = items.get("players", items.get("items", []))
            meta = payload.get("pagination", payload)
            return (items if isinstance(items, list) else []), (meta if isinstance(meta, dict) else {})
        rows, meta = unpack(first)
        if not rows:
            raise RuntimeError("API nie zwróciło listy graczy.")
        total_pages = int(meta.get("total_pages", meta.get("totalPages", meta.get("last_page", 1))) or 1)
        total_pages = max(1, min(total_pages, 200))
        players = {}
        def add_rows(items):
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = item.get("player_name") or item.get("name")
                if not name:
                    continue
                alliance = item.get("alliance_name") or item.get("alliance") or ""
                if isinstance(alliance, dict):
                    alliance = alliance.get("name", "")
                if isinstance(alliance, str) and alliance.startswith("[") and alliance.endswith("]"):
                    alliance = alliance[1:-1]
                players[str(name).strip()] = str(alliance).strip()
        add_rows(rows)
        for page in range(2, total_pages + 1):
            payload = await bot_tracker_get("players", key, {
                "limit": 100, "page": page, "banFilter": 0, "allianceFilter": -1,
                "protectionFilter": -1, "inactiveFilter": 1, "kingdomFilter": 999,
                "orderBy": "might_current", "orderType": "DESC",
            })
            page_rows, _ = unpack(payload)
            add_rows(page_rows)
            if page < total_pages:
                await asyncio.sleep(1.2)
        alliances = sorted({v for v in players.values() if v and v.casefold() != "sans alliance"}, key=str.casefold)
        BOT_SUGGEST_CACHE[key] = {
            "loaded": time.time(), "players": sorted(players.keys(), key=str.casefold),
            "alliances": alliances, "scan_available": bool(players),
            "player_count": len(players), "page_count": total_pages,
        }
        status.update({"running": False, "finished_at": datetime.now(timezone.utc).isoformat(),
                       "players": len(players), "alliances": len(alliances), "pages": total_pages, "error": None})
    except Exception as exc:
        status.update({"running": False, "finished_at": datetime.now(timezone.utc).isoformat(),
                       "error": str(exc)[:300]})
    finally:
        BOT_SCAN_TASKS.pop(key, None)

@app.get("/api/bot/scan/status")
def bot_scan_status(server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    key = server.upper()
    cached = BOT_SUGGEST_CACHE.get(key, {})
    return {"server": key, "scan": BOT_SCAN_STATUS.get(key, {"running": False}),
            "cached": bool(cached.get("scan_available")), "cached_at": cached.get("loaded"),
            "players": cached.get("player_count", 0), "alliances": len(cached.get("alliances", []))}

@app.post("/api/bot/scan/{server}")
async def bot_scan_start(server: str, user: User = Depends(current_user)):
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,40}", server):
        raise HTTPException(400, "Nieprawidłowy serwer.")
    key = server.upper()
    if key not in BOT_SCAN_TASKS:
        BOT_SCAN_TASKS[key] = asyncio.create_task(_scan_server_for_suggestions(key))
    return {"server": key, "running": True, "message": "Skan graczy i sojuszy został uruchomiony w tle."}

@app.get("/api/bot/suggestions")
async def bot_suggestions(
    q: str = "",
    kind: str = "players",
    server: str = "E4K_PL1_BETA",
    user: User = Depends(current_user),
):
    if kind not in ("players", "alliances"):
        raise HTTPException(400, "Nieprawidłowy typ podpowiedzi.")
    if len(q) > 80:
        raise HTTPException(400, "Fraza jest zbyt długa.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,40}", server):
        raise HTTPException(400, "Nieprawidłowy serwer.")
    key = server.upper()
    cache = BOT_SUGGEST_CACHE.get(key)
    if not cache or time.time() - cache["loaded"] > 21600:
        if key not in BOT_SCAN_TASKS:
            BOT_SCAN_TASKS[key] = asyncio.create_task(_scan_server_for_suggestions(key))
        return {"items": [], "kind": kind, "server": key, "source": "live_player_scan",
                "scan_available": False, "scan_running": True,
                "message": "Trwa pobieranie listy graczy i sojuszy z serwera. Podpowiedzi pojawią się po zakończeniu skanu."}
    needle = q.casefold().strip()
    values = cache[kind]
    if needle:
        values = [name for name in values if needle in name.casefold()]
        values.sort(key=lambda name: (not name.casefold().startswith(needle), name.casefold()))
    else:
        values = values[:25]
    return {"items": values[:25], "kind": kind, "server": key, "source": "live_player_scan",
            "scan_available": True, "scan_running": False, "message": None,
            "cached_at": cache["loaded"]}

@app.get("/api/bot/fortresses/meta")
async def bot_fortress_meta(server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    return {"data": await bot_tracker_get("dungeons/meta", server), "server": server.upper()}

@app.get("/api/bot/fortresses")
async def bot_fortresses(
    server: str = "E4K_PL1_BETA",
    player: str = "",
    kingdom_ids: str = "",
    page: int = 1,
    size: int = 100,
    user: User = Depends(current_user),
):
    if page < 1 or size < 1 or size > 500:
        raise HTTPException(400, "Nieprawidłowy zakres strony lub liczby wyników.")
    params = {"page": page, "size": size}
    if player.strip():
        params["filterByPlayerName"] = player.strip()[:80]
        params["nearPlayerName"] = player.strip()[:80]
    if kingdom_ids.strip():
        params["filterByKid"] = kingdom_ids.strip()[:200]
    return {"data": await bot_tracker_get("dungeons", server, params), "server": server.upper()}

@app.get("/api/bot/storms/meta")
async def bot_storm_meta(server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    return {"data": await bot_tracker_get("storms/meta", server), "server": server.upper()}

@app.get("/api/bot/storms/forts")
async def bot_storm_forts(server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    return {"data": await bot_tracker_get("storms/forts", server), "server": server.upper()}

@app.get("/api/bot/storms/isles")
async def bot_storm_isles(
    server: str = "E4K_PL1_BETA",
    occupier: str = "",
    page: int = 1,
    size: int = 100,
    user: User = Depends(current_user),
):
    if page < 1 or size < 1 or size > 500:
        raise HTTPException(400, "Nieprawidłowy zakres strony lub liczby wyników.")
    params = {"page": page, "size": size}
    if occupier.strip():
        params["filterByOccupierName"] = occupier.strip()[:80]
    return {"data": await bot_tracker_get("storms/isles", server, params), "server": server.upper()}

@app.get("/api/bot/castles/search/{name}")
async def bot_castle_search(name: str, server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    if not name.strip() or len(name) > 100:
        raise HTTPException(400, "Podaj prawidłową nazwę zamku lub gracza.")
    return {"data": await bot_tracker_get("castle/search/" + quote(name.strip(), safe=""), server), "server": server.upper()}

@app.get("/api/bot/castles/{castle_id}/analysis")
async def bot_castle_analysis(castle_id: int, kingdom_id: int = 0, server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    if castle_id <= 0 or kingdom_id < 0:
        raise HTTPException(400, "Nieprawidłowy identyfikator zamku lub królestwa.")
    return {"data": await bot_tracker_get(f"castle/analysis/{castle_id}", server, {"kingdomId": kingdom_id}), "server": server.upper()}

@app.get("/api/bot/player-ranking/{player_id}")
async def bot_player_ranking(player_id: int, server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    if player_id <= 0:
        raise HTTPException(400, "Nieprawidłowy identyfikator gracza.")
    return {"data": await bot_tracker_get(f"statistics/ranking/player/{player_id}", server), "server": server.upper()}

@app.get("/api/bot/player-statistics/{player_id}")
async def bot_player_statistics(player_id: int, server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    if player_id <= 0:
        raise HTTPException(400, "Nieprawidłowy identyfikator gracza.")
    return {"data": await bot_tracker_get(f"statistics/player/{player_id}", server), "server": server.upper()}


@app.get("/api/bot/radar/movements")
async def bot_radar_movements(
    server: str = "E4K_PL1_BETA",
    page: int = 1,
    castle_type: int = 1,
    movement_type: int = 3,
    user: User = Depends(current_user),
):
    if page < 1 or page > 100 or castle_type < 0 or movement_type < 0:
        raise HTTPException(400, "Nieprawidłowe filtry radaru.")
    url = "https://api-beta.gge-tracker.com/api/v1/server/movements"
    params = {"page": page, "castleType": castle_type, "movementType": movement_type}
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            response = await client.get(url, headers=bot_headers(server), params=params)
        if response.status_code == 404:
            raise HTTPException(404, "Brak ruchów dla wybranego serwera.")
        if response.status_code == 429:
            raise HTTPException(429, "API radaru ograniczyło liczbę zapytań. Spróbuj później.")
        if response.status_code >= 400:
            raise HTTPException(502, f"API radaru zwróciło błąd {response.status_code}.")
        return {"data": response.json(), "server": server.upper()}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "Nie udało się połączyć z API radaru.")

@app.get("/api/features")
def features(user: User = Depends(current_user)):
    return {
        "available": ["player_profile","alliance_profile","server_statistics","fortress_history"],
        "in_development": ["live_map","target_radar","fortress_scanner","storm_islands","event_calendar","rankings","web_notifications"],
        "note": "Funkcje zewnętrzne wymagają dostępności GGE Tracker i prawidłowego serwera."
    }

if SITE.exists():
    app.mount("/", StaticFiles(directory=str(SITE), html=True), name="site")
