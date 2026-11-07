import os
import asyncio
import re
import hmac
import hashlib
import base64
import json
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, String, DateTime, Integer, Float, Text, select, text
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

# A single session factory is required for both SQLite and PostgreSQL.
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

class BotPlayerIndex(Base):
    __tablename__ = "bot_player_index"
    __table_args__ = {"schema": None} if DATABASE_URL.startswith("sqlite") else {"schema": "empiremaps"}
    server: Mapped[str] = mapped_column(String(40), primary_key=True)
    payload: Mapped[str] = mapped_column(Text)
    loaded_at: Mapped[float] = mapped_column(Float)

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
BOT_DOVE_CACHE: dict[str, dict] = {}

def load_persisted_bot_index(server: str):
    key = server.upper()
    try:
        with SessionLocal() as db:
            row = db.get(BotPlayerIndex, key)
            if not row:
                return None
            payload = json.loads(row.payload)
            if not isinstance(payload, dict) or not isinstance(payload.get("players"), list) or not isinstance(payload.get("alliances"), list):
                return None
            payload["loaded"] = float(row.loaded_at)
            return payload
    except Exception:
        logging.exception("Nie udało się odczytać trwałego indeksu graczy %s", key)
        return None

def save_persisted_bot_index(server: str, payload: dict):
    key = server.upper()
    try:
        with SessionLocal() as db:
            row = db.get(BotPlayerIndex, key)
            serialized = json.dumps({k: v for k, v in payload.items() if k != "loaded"}, ensure_ascii=False)
            if row:
                row.payload = serialized
                row.loaded_at = float(payload["loaded"])
            else:
                db.add(BotPlayerIndex(server=key, payload=serialized, loaded_at=float(payload["loaded"])))
            db.commit()
    except Exception:
        logging.exception("Nie udało się zapisać trwałego indeksu graczy %s", key)


async def _scan_server_for_suggestions(server: str):
    """Pobiera indeks nazw graczy/sojuszy z paginowanego API; bez zależności od Discorda."""
    key = server.upper()
    status = BOT_SCAN_STATUS.setdefault(key, {})
    status.update({"running": True, "started_at": datetime.now(timezone.utc).isoformat(), "error": None, "pages_completed": 0, "total_pages": None, "players_found": 0, "alliances_found": 0})
    try:
        # Mirror the proven player-scan query used by the source bot.
        # Tracker returns pagination.total_pages; request the same 100 rows/page.
        scan_params = {
            "limit": 100, "page": 1, "banFilter": 0,
            "allianceFilter": -1, "protectionFilter": -1,
            "inactiveFilter": 1, "kingdomFilter": 999,
            "orderBy": "might_current", "orderType": "DESC",
        }
        first = await bot_tracker_get("players", key, scan_params)
        def unpack(payload):
            if isinstance(payload, list):
                return payload, {}
            if not isinstance(payload, dict):
                return [], {}
            items = payload.get("players", payload.get("items", payload.get("data", [])))
            if isinstance(items, dict):
                items = items.get("players", items.get("items", items.get("data", [])))
            meta = payload.get("pagination", payload)
            return (items if isinstance(items, list) else []), (meta if isinstance(meta, dict) else {})
        rows, meta = unpack(first)
        if not rows:
            raise RuntimeError("API nie zwróciło listy graczy.")
        total_pages_value = meta.get("total_pages", meta.get("totalPages", meta.get("last_page")))
        if total_pages_value is None:
            total_count = meta.get("total_items_count", meta.get("total", meta.get("totalItemsCount")))
            if isinstance(total_count, (int, float)):
                total_pages_value = max(1, (int(total_count) + 99) // 100)
        total_pages = max(1, min(int(total_pages_value or 1), 200))
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
        status.update({"pages_completed": 1, "total_pages": total_pages, "players_found": len(players)})
        for page in range(2, total_pages + 1):
            page_params = dict(scan_params)
            page_params["page"] = page
            payload = await bot_tracker_get("players", key, page_params)
            page_rows, _ = unpack(payload)
            add_rows(page_rows)
            alliances_progress = {v for v in players.values() if v and v.casefold() != "sans alliance"}
            status.update({"pages_completed": page, "total_pages": total_pages,
                           "players_found": len(players), "alliances_found": len(alliances_progress)})
            if page < total_pages:
                await asyncio.sleep(1.2)
        alliances = sorted({v for v in players.values() if v and v.casefold() != "sans alliance"}, key=str.casefold)
        BOT_SUGGEST_CACHE[key] = {
            "loaded": time.time(), "players": sorted(players.keys(), key=str.casefold),
            "alliances": alliances, "scan_available": bool(players),
            "player_count": len(players), "page_count": total_pages,
        }
        save_persisted_bot_index(key, BOT_SUGGEST_CACHE[key])
        status.update({"running": False, "finished_at": datetime.now(timezone.utc).isoformat(),
                       "players": len(players), "alliances": len(alliances), "pages": total_pages,
                       "pages_completed": total_pages, "total_pages": total_pages,
                       "players_found": len(players), "alliances_found": len(alliances), "error": None})
    except Exception as exc:
        status.update({"running": False, "finished_at": datetime.now(timezone.utc).isoformat(),
                       "error": str(exc)[:300], "players_found": status.get("players_found", 0)})
    finally:
        BOT_SCAN_TASKS.pop(key, None)

@app.get("/api/bot/scan/status")
def bot_scan_status(server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    key = server.upper()
    cached = BOT_SUGGEST_CACHE.get(key)
    if not cached:
        cached = load_persisted_bot_index(key) or {}
        if cached:
            BOT_SUGGEST_CACHE[key] = cached
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
    if not cache:
        cache = load_persisted_bot_index(key)
        if cache:
            BOT_SUGGEST_CACHE[key] = cache
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

@app.get("/api/bot/doves/alliances")
async def bot_dove_alliances(server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,40}", server):
        raise HTTPException(400, "Nieprawidłowy serwer.")
    key = server.upper()
    cache = BOT_SUGGEST_CACHE.get(key) or load_persisted_bot_index(key)
    if cache:
        BOT_SUGGEST_CACHE[key] = cache
        return {"server": key, "items": cache.get("alliances", []), "count": len(cache.get("alliances", [])), "ready": True}
    if key not in BOT_SCAN_TASKS:
        BOT_SCAN_TASKS[key] = asyncio.create_task(_scan_server_for_suggestions(key))
    return {"server": key, "items": [], "count": 0, "ready": False, "message": "Trwa skanowanie sojuszy. Odśwież listę za chwilę."}

@app.get("/api/bot/doves")
async def bot_doves(server: str = "E4K_PL1_BETA", page_limit: int = 200, alliance: str = "", player: str = "", user: User = Depends(current_user)):
    """Aktywne okresy ochrony Dove ze wszystkich sojuszy serwera."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,40}", server):
        raise HTTPException(400, "Nieprawidłowy serwer.")
    page_limit = max(1, min(int(page_limit), 200))
    cache_key = server.upper()
    cached = BOT_DOVE_CACHE.get(cache_key)
    if cached and time.time() - cached.get("loaded", 0) < 300:
        all_items = cached["items"]
        filtered = [x for x in all_items
                    if (not alliance.strip() or x["alliance"].casefold() == alliance.strip().casefold())
                    and (not player.strip() or player.strip().casefold() in x["player"].casefold())]
        filtered.sort(key=lambda item: item["peace_disabled_at"])
        return {"server": cache_key, "items": filtered, "count": len(filtered),
                "alliances": cached["alliances"], "scanned_players": cached["scanned_players"],
                "cached": True, "generated_at": cached["generated_at"]}
    params = {
        "limit": 100, "page": 1, "banFilter": 0,
        "allianceFilter": -1, "protectionFilter": -1,
        "inactiveFilter": -1, "kingdomFilter": 999,
        "orderBy": "might_current", "orderType": "DESC",
    }
    def unpack(payload):
        if isinstance(payload, list):
            return payload, {}
        if not isinstance(payload, dict):
            return [], {}
        rows = payload.get("players", payload.get("items", payload.get("data", [])))
        if isinstance(rows, dict):
            rows = rows.get("players", rows.get("items", rows.get("data", [])))
        meta = payload.get("pagination", payload)
        return (rows if isinstance(rows, list) else []), (meta if isinstance(meta, dict) else {})
    try:
        first = await bot_tracker_get("players", server, params)
        rows, meta = unpack(first)
        total_value = meta.get("total_pages", meta.get("totalPages", meta.get("last_page")))
        if total_value is None:
            total_count = meta.get("total_items_count", meta.get("total", meta.get("totalItemsCount")))
            if total_count is not None:
                total_value = max(1, (int(total_count) + 99) // 100)
        total_pages = max(1, min(int(total_value or 1), page_limit))
        all_rows = list(rows)
        for page in range(2, total_pages + 1):
            next_params = dict(params)
            next_params["page"] = page
            payload = await bot_tracker_get("players", server, next_params)
            page_rows, _ = unpack(payload)
            all_rows.extend(page_rows)
            if page < total_pages:
                await asyncio.sleep(1.2)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Nie udało się pobrać listy ochron Dove: {exc}")
    now = datetime.now(timezone.utc)
    items = []
    all_alliances = set()
    for row in all_rows:
        if not isinstance(row, dict):
            continue
        until = row.get("peace_disabled_at")
        if not until or str(until).lower() == "null":
            continue
        try:
            end = datetime.fromisoformat(str(until).replace("Z", "+00:00"))
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            end = end.astimezone(timezone.utc)
        except (TypeError, ValueError):
            continue
        if end <= now:
            continue
        alliance = row.get("alliance_name") or row.get("alliance") or "Bez sojuszu"
        if isinstance(alliance, dict):
            alliance = alliance.get("name") or "Bez sojuszu"
        alliance = str(alliance).strip() or "Bez sojuszu"
        if alliance.casefold() not in ("bez sojuszu", "sans alliance"):
            all_alliances.add(alliance)
        items.append({
            "player": row.get("player_name") or row.get("name") or "—",
            "alliance": alliance,
            "player_id": row.get("player_id") or row.get("id"),
            "peace_disabled_at": end.isoformat(),
            "updated_at": row.get("updated_at"),
            "might": row.get("might_current"),
        })
    all_alliances = sorted(all_alliances, key=str.casefold)
    BOT_DOVE_CACHE[cache_key] = {"loaded": time.time(), "items": items,
        "alliances": all_alliances, "scanned_players": len(all_rows), "generated_at": now.isoformat()}
    if alliance.strip():
        wanted_alliance = alliance.strip().casefold()
        items = [item for item in items if item["alliance"].casefold() == wanted_alliance]
    if player.strip():
        wanted_player = player.strip().casefold()
        items = [item for item in items if wanted_player in item["player"].casefold()]
    items.sort(key=lambda item: item["peace_disabled_at"])
    return {"server": server.upper(), "items": items, "count": len(items),
            "alliances": all_alliances, "pages_scanned": total_pages,
            "pages_available": total_value or total_pages,
            "scanned_players": len(all_rows), "cached": False, "generated_at": now.isoformat()}

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
        selected_kids = [part.strip() for part in kingdom_ids.split(",") if part.strip().isdigit()]
        if selected_kids:
            params["filterByKid"] = "[" + ",".join(f'"{kid}"' for kid in selected_kids) + "]"
    return {"data": await bot_tracker_get("dungeons", server, params), "server": server.upper()}

@app.get("/api/bot/storms/meta")
async def bot_storm_meta(server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    return {"data": await bot_tracker_get("storms/meta", server), "server": server.upper()}

@app.get("/api/bot/storms/forts")
async def bot_storm_forts(
    server: str = "E4K_PL1_BETA",
    page: int = 1,
    size: int = 500,
    availability: int = 1,
    levels: str = "",
    min_attacks: int = 0,
    user: User = Depends(current_user),
):
    if page < 1 or size < 1 or size > 500 or availability not in (0, 1, 2, 3) or not 0 <= min_attacks <= 10:
        raise HTTPException(400, "Nieprawidłowe filtry fortów sztormowych.")
    level_map = {"40":[10], "50":[11], "60":[7,12], "70":[8,13], "80":[9,14]}
    selected = [item.strip() for item in levels.split(",") if item.strip()]
    if any(item not in level_map for item in selected):
        raise HTTPException(400, "Nieprawidłowy poziom fortu.")
    isle_ids = [i for level in selected for i in level_map[level]] if selected else [7,8,9,10,11,12,13,14]
    params = {
        "page": page, "size": size, "minAttacksLeft": min_attacks,
        "filterByIsleIds": "[" + ",".join(map(str, isle_ids)) + "]",
        "orderDirection": "desc",
    }
    if availability:
        params["filterByAvailability"] = availability
    return {"data": await bot_tracker_get("storms/forts", server, params), "server": server.upper(),
            "filters": {"availability": availability, "levels": selected or ["40","50","60","70","80"], "min_attacks": min_attacks}}

@app.get("/api/bot/storms/isles")
async def bot_storm_isles(
    server: str = "E4K_PL1_BETA",
    occupier: str = "",
    page: int = 1,
    size: int = 500,
    state: int = 0,
    resource: int = 0,
    user: User = Depends(current_user),
):
    if page < 1 or size < 1 or size > 500 or state not in (0,1,2,3) or resource not in (0,1,2,3):
        raise HTTPException(400, "Nieprawidłowe filtry wysp sztormowych.")
    params = {"page": page, "size": size}
    if state:
        params["filterByState"] = state
    if occupier.strip():
        params["filterByOccupierName"] = occupier.strip()[:80]
    payload = await bot_tracker_get("storms/isles", server, params)
    allowed = {1:[3,6], 2:[1,4], 3:[2,5]}.get(resource)
    if allowed and isinstance(payload, dict) and isinstance(payload.get("isles"), list):
        payload = dict(payload)
        payload["isles"] = [item for item in payload["isles"] if isinstance(item, dict) and item.get("isle_id") in allowed]
    return {"data": payload, "server": server.upper(),
            "filters": {"state": state, "resource": resource, "occupier": occupier.strip()}}


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
    params = {"page": page, "castleType": castle_type, "movementType": movement_type}
    # The original bot used the beta hostname. The public GGE Tracker API now
    # documents /server/movements on the primary API host; try it first and
    # keep the legacy host as a compatibility fallback.
    last_status = None
    for base_url in (BOT_API_BASE, "https://api-beta.gge-tracker.com/api/v1"):
        try:
            async with httpx.AsyncClient(timeout=18, follow_redirects=True) as client:
                response = await client.get(
                    base_url + "/server/movements",
                    headers=bot_headers(server),
                    params=params,
                )
            if response.status_code == 200:
                try:
                    payload = response.json()
                except Exception:
                    raise HTTPException(502, "API radaru zwróciło nieprawidłowy format danych.")
                return {"data": payload, "server": server.upper(), "source": base_url}
            if response.status_code == 429:
                raise HTTPException(429, "API radaru ograniczyło liczbę zapytań. Spróbuj później.")
            last_status = response.status_code
        except HTTPException:
            raise
        except Exception:
            last_status = "connection_error"
            continue
    if last_status == "connection_error":
        raise HTTPException(502, "Nie udało się połączyć z żadnym hostem API radaru.")
    raise HTTPException(502, f"API radaru nie udostępniło danych (ostatni kod: {last_status}).")



# Read-only calendar port from the GGE Assistant bot. No Discord alerts or guild settings.
from html.parser import HTMLParser

CALENDAR_SOURCE_URL = "https://communityhub.goodgamestudios.com/newshube4k"
CALENDAR_EVENTS = {
    "samurai invasion": {"name":"Samuraje","start":"11:00","end":"09:00"},
    "nomad invasion": {"name":"Nomadzi","start":"11:00","end":"09:00"},
    "bloodcrow invasion": {"name":"Kruki krwi","start":"11:00","end":"09:00"},
    "war of the realms": {"name":"Wojna królestw","start":"11:00","end":"09:00"},
    "berimond": {"name":"Berimond","start":"11:00","end":"08:30"},
    "bladecoast": {"name":"Côte Tranchante","start":"11:00","end":"09:00"},
    "rift raid": {"name":"Raid Szczeliny","start":"11:00","end":"09:00"},
    "grand tournament": {"name":"Wielki Turniej","start":"11:00","end":"12:00"},
    "beyond the horizon": {"name":"Poza horyzontem","start":"11:00","end":"00:40"},
    "outer realms": {"name":"Zewnętrzne krainy","start":"11:00","end":"00:40"},
    "imperial patronage": {"name":"Cesarski patronat","start":"11:00","end":"09:30"},
    "grand nobility contest": {"name":"Wielki konkurs szlachectwa","start":"11:00","end":"09:00"},
}
CALENDAR_ALLIANCE_KEYS = {"grand tournament", "rift raid", "beyond the horizon"}
CALENDAR_CACHE = {"at": 0.0, "events": [], "last_error": None}
CALENDAR_LOCK = asyncio.Lock()

class _CalendarTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip_depth = 0
    def handle_starttag(self, tag, attrs):
        if tag.lower() in ("script", "style", "noscript"):
            self.skip_depth += 1
    def handle_endtag(self, tag):
        if tag.lower() in ("script", "style", "noscript") and self.skip_depth:
            self.skip_depth -= 1
    def handle_data(self, data):
        if not self.skip_depth and data.strip():
            self.parts.append(data.strip())

def _parse_calendar_html(html_text: str):
    parser = _CalendarTextParser()
    parser.feed(html_text)
    now = datetime.now(timezone.utc)
    found, seen = [], set()
    current_key = None
    date_pattern = re.compile(r"(\d{2}[/.-]\d{2})[/.-]?\s*(?:-|à|to|au|–|—)\s*(\d{2}[/.-]\d{2})", re.I)
    for part in parser.parts:
        lower = part.casefold()
        matched = next((key for key in CALENDAR_EVENTS if key in lower), None)
        if matched:
            current_key = matched
        if not current_key:
            continue
        for start_s, end_s in date_pattern.findall(lower):
            try:
                start_s = start_s.replace(".", "/").replace("-", "/")
                end_s = end_s.replace(".", "/").replace("-", "/")
                meta = CALENDAR_EVENTS[current_key]
                start_dt = datetime.strptime(f"{start_s}/{now.year} {meta['start']}", "%d/%m/%Y %H:%M").replace(tzinfo=timezone.utc)
                end_dt = datetime.strptime(f"{end_s}/{now.year} {meta['end']}", "%d/%m/%Y %H:%M").replace(tzinfo=timezone.utc)
                if start_dt < now - timedelta(days=180):
                    start_dt = start_dt.replace(year=start_dt.year + 1)
                    end_dt = end_dt.replace(year=end_dt.year + 1)
                if end_dt < start_dt:
                    end_dt = end_dt.replace(year=end_dt.year + 1)
                uid = f"{current_key}_{int(start_dt.timestamp())}"
                if uid not in seen:
                    found.append({"id": hashlib.sha1(uid.encode()).hexdigest()[:8],
                                  "key": current_key, "name": meta["name"],
                                  "start": start_dt.isoformat(), "end": end_dt.isoformat()})
                    seen.add(uid)
            except (ValueError, OverflowError):
                continue
    return sorted(found, key=lambda event: event["start"])

async def _get_live_calendar(force: bool = False):
    now_ts = time.time()
    if not force and CALENDAR_CACHE["at"] and now_ts - CALENDAR_CACHE["at"] < 600:
        return CALENDAR_CACHE["events"]
    async with CALENDAR_LOCK:
        now_ts = time.time()
        if not force and CALENDAR_CACHE["at"] and now_ts - CALENDAR_CACHE["at"] < 600:
            return CALENDAR_CACHE["events"]
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                response = await client.get(CALENDAR_SOURCE_URL, headers={
                    "User-Agent":"Mozilla/5.0 (compatible; Empiremaps-Web/1.0)",
                    "Accept":"text/html,application/xhtml+xml"
                })
            if response.status_code != 200:
                CALENDAR_CACHE["last_error"] = f"Community Hub zwrócił HTTP {response.status_code}."
                if CALENDAR_CACHE["events"]:
                    return CALENDAR_CACHE["events"]
                raise HTTPException(502, CALENDAR_CACHE["last_error"])
            events = _parse_calendar_html(response.text)
            if not events:
                CALENDAR_CACHE["last_error"] = "Strona źródłowa nie zwróciła rozpoznawalnych wydarzeń. Parser wymaga aktualizacji."
                if CALENDAR_CACHE["events"]:
                    return CALENDAR_CACHE["events"]
            else:
                CALENDAR_CACHE.update({"events": events, "at": time.time(), "last_error": None})
            return CALENDAR_CACHE["events"]
        except HTTPException:
            raise
        except Exception as exc:
            CALENDAR_CACHE["last_error"] = str(exc)[:200]
            if CALENDAR_CACHE["events"]:
                return CALENDAR_CACHE["events"]
            raise HTTPException(502, "Nie udało się pobrać kalendarza z Community Hub.")


@app.get("/api/bot/targets/search")
async def bot_target_search(
    origin_player: str,
    server: str = "E4K_PL1_BETA",
    target_alliance: str = "",
    level_min: int = -1, level_max: int = -1,
    might_min: int = -1, might_max: int = -1,
    distance_min: float = -1, distance_max: float = -1,
    honor_min: int = -1, honor_max: int = -1,
    glory_min: int = -1, glory_max: int = -1,
    loot_min: int = -1, loot_max: int = -1,
    show_doves: bool = False, only_with_alliance: bool = False,
    excluded_alliances: str = "", activity_filter: str = "all",
    user: User = Depends(current_user),
):
    """Web port of the bot's configurable target radar, with bounded API fan-out."""
    origin_player = origin_player.strip()
    if not origin_player or len(origin_player) > 80:
        raise HTTPException(400, "Podaj nazwę gracza bazowego.")
    if activity_filter not in ("all", "active", "inactive"):
        raise HTTPException(400, "Nieprawidłowy filtr aktywności.")
    bounds = [
        (level_min, level_max, "poziomu"), (might_min, might_max, "mocy"),
        (distance_min, distance_max, "odległości"), (honor_min, honor_max, "honoru"),
        (glory_min, glory_max, "chwały"), (loot_min, loot_max, "łupu"),
    ]
    for low, high, label in bounds:
        if low != -1 and high != -1 and low > high:
            raise HTTPException(400, f"Minimum nie może być większe od maksimum ({label}).")
    if len(target_alliance) > 100 or len(excluded_alliances) > 1000:
        raise HTTPException(400, "Wartość filtra jest zbyt długa.")

    headers = bot_headers(server)
    base = BOT_API_BASE.rstrip("/")
    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
        async def fetch(path: str, params: dict | None = None, missing_ok: bool = False):
            response = await client.get(base + "/" + path.lstrip("/"), headers=headers, params=params)
            if response.status_code == 429:
                raise HTTPException(429, "API GGE Tracker ograniczyło liczbę zapytań. Spróbuj za chwilę.")
            if response.status_code == 404 and missing_ok:
                return None
            if response.status_code >= 400:
                raise HTTPException(502, f"GGE Tracker zwrócił błąd {response.status_code}.")
            try:
                return response.json()
            except Exception:
                raise HTTPException(502, "API GGE Tracker zwróciło nieprawidłowy format danych.")

        origin = await fetch("players/" + quote(origin_player, safe=""), missing_ok=True)
        if isinstance(origin, list):
            origin = origin[0] if origin else None
        if not isinstance(origin, dict):
            raise HTTPException(404, f"Nie znaleziono gracza bazowego: {origin_player}.")
        origin_name = str(origin.get("playerName") or origin.get("player_name") or origin.get("name") or origin_player)
        origin_castles = await fetch("castle/search/" + quote(origin_name, safe=""), missing_ok=True)
        if isinstance(origin_castles, dict):
            origin_castles = [origin_castles]
        origin_coords = None
        for castle in origin_castles if isinstance(origin_castles, list) else []:
            if not isinstance(castle, dict):
                continue
            kid = castle.get("kingdomId", castle.get("kingdom_id", -1))
            ctype = castle.get("type", castle.get("castle_type", -1))
            x = castle.get("positionX", castle.get("position_x", castle.get("x")))
            y = castle.get("positionY", castle.get("position_y", castle.get("y")))
            if str(kid) == "0" and str(ctype) == "1" and x is not None and y is not None:
                try:
                    origin_coords = (float(x), float(y))
                    break
                except (TypeError, ValueError):
                    continue
        if not origin_coords:
            raise HTTPException(404, "Nie znaleziono głównego zamku gracza bazowego (królestwo 0).")

        params = {
            "page": 1, "orderBy": "distance", "orderType": "ASC",
            "playerNameForDistance": origin_name,
            "minMight": might_min, "maxMight": might_max,
            "minHonor": honor_min, "maxHonor": honor_max,
            "minLoot": loot_min, "maxLoot": loot_max,
            "minLevel": -1, "minLegendaryLevel": -1,
            "maxLevel": -1, "maxLegendaryLevel": -1,
            "allianceFilter": 1 if only_with_alliance else -1,
            "protectionFilter": -1 if show_doves else 0,
            "banFilter": -1, "inactiveFilter": -1,
        }
        if activity_filter == "active":
            params["inactiveFilter"] = 0
        elif activity_filter == "inactive":
            params["inactiveFilter"] = 1
        if level_min != -1:
            if level_min <= 70:
                params["minLevel"] = level_min
            else:
                params["minLevel"] = 70
                params["minLegendaryLevel"] = level_min - 70
        if level_max != -1:
            if level_max <= 70:
                params["maxLevel"] = level_max
            else:
                params["maxLevel"] = 70
                params["maxLegendaryLevel"] = level_max - 70
        if target_alliance.strip():
            params["alliance"] = target_alliance.strip()

        first = await fetch("players", params)
        def unpack(payload):
            if isinstance(payload, list):
                return payload, {}
            if not isinstance(payload, dict):
                return [], {}
            rows = payload.get("players", payload.get("items", payload.get("data", [])))
            meta = payload.get("pagination", payload)
            return (rows if isinstance(rows, list) else []), (meta if isinstance(meta, dict) else {})
        first_rows, meta = unpack(first)
        total_pages = meta.get("total_pages", meta.get("totalPages", meta.get("last_page", 1))) or 1
        if meta.get("total") and not meta.get("total_pages") and not meta.get("totalPages"):
            try:
                total_pages = max(1, (int(meta["total"]) + 49) // 50)
            except (TypeError, ValueError):
                total_pages = 1
        try:
            total_pages = max(1, min(int(total_pages), 200))
        except (TypeError, ValueError):
            total_pages = 1

        pages = [(1, first_rows)]
        max_pages = min(total_pages, 12)
        for page_number in range(2, max_pages + 1):
            page_params = dict(params)
            page_params["page"] = page_number
            payload = await fetch("players", page_params)
            rows, _ = unpack(payload)
            pages.append((page_number, rows))

        excluded = {
            "".join(ch for ch in item.casefold() if ch.isalnum())
            for item in excluded_alliances.split(",") if item.strip()
        }
        semaphore = asyncio.Semaphore(6)
        checked_names = set()
        results = []
        async def evaluate(player):
            if not isinstance(player, dict):
                return None
            name = str(player.get("player_name") or player.get("name") or "").strip()
            if not name or name.casefold() == origin_name.casefold() or name.casefold() in checked_names:
                return None
            checked_names.add(name.casefold())
            alliance = player.get("alliance_name") or player.get("alliance") or ""
            if isinstance(alliance, dict):
                alliance = alliance.get("name", "")
            alliance = str(alliance or "")
            if alliance.startswith("[") and alliance.endswith("]"):
                alliance = alliance[1:-1]
            alliance_key = "".join(ch for ch in alliance.casefold() if ch.isalnum())
            if alliance_key in excluded or any(alliance_key == banned or banned in alliance_key for banned in excluded if banned):
                return None
            try:
                level = int(player.get("level") or 0)
                legendary = int(player.get("legendary_level") or 0)
                might = int(player.get("might_current") or 0)
                honor = int(player.get("honor") or 0)
                glory = int(player.get("current_fame", player.get("highest_fame", 0)) or 0)
                loot = int(player.get("loot_current") or 0)
            except (TypeError, ValueError):
                return None
            absolute_level = level + legendary
            for value, low, high in (
                (absolute_level, level_min, level_max), (might, might_min, might_max),
                (honor, honor_min, honor_max), (glory, glory_min, glory_max), (loot, loot_min, loot_max),
            ):
                if (low != -1 and value < low) or (high != -1 and value > high):
                    return None
            async with semaphore:
                castles = await fetch("castle/search/" + quote(name, safe=""), missing_ok=True)
            if isinstance(castles, dict):
                castles = [castles]
            coords = None
            for castle in castles if isinstance(castles, list) else []:
                if not isinstance(castle, dict):
                    continue
                if str(castle.get("kingdomId", castle.get("kingdom_id", -1))) == "0" and str(castle.get("type", castle.get("castle_type", -1))) == "1":
                    x = castle.get("positionX", castle.get("position_x", castle.get("x")))
                    y = castle.get("positionY", castle.get("position_y", castle.get("y")))
                    if x is not None and y is not None:
                        try:
                            coords = (float(x), float(y))
                            break
                        except (TypeError, ValueError):
                            pass
            if not coords:
                return None
            distance = ((coords[0] - origin_coords[0]) ** 2 + (coords[1] - origin_coords[1]) ** 2) ** 0.5
            if (distance_min != -1 and distance < distance_min) or (distance_max != -1 and distance > distance_max):
                return None
            peace_until = player.get("peace_disabled_at")
            has_protection = False
            if peace_until and str(peace_until).lower() != "null":
                try:
                    peace_dt = datetime.fromisoformat(str(peace_until).replace("Z", "+00:00"))
                    if peace_dt.tzinfo is None:
                        peace_dt = peace_dt.replace(tzinfo=timezone.utc)
                    has_protection = peace_dt > datetime.now(timezone.utc)
                except (TypeError, ValueError):
                    has_protection = False
            wall_terms = ("repos", "deuil", "hospitalisé", "rest", "hospital", "mourning", "ruhe", "krankenhaus")
            wall_warning = any(term in alliance.casefold() for term in wall_terms)
            return {
                "name": name, "alliance": alliance, "level": level, "legendary_level": legendary,
                "absolute_level": absolute_level, "might": might, "honor": honor, "glory": glory,
                "loot": loot, "distance": round(distance, 2), "x": coords[0], "y": coords[1],
                "peace_disabled_at": peace_until, "has_protection": has_protection,
                "wall_warning": wall_warning,
            }

        valid_count = 0
        scanned_pages = []
        for page_number, rows in pages:
            scanned_pages.append(page_number)
            evaluated = await asyncio.gather(*(evaluate(player) for player in rows))
            page_results = [item for item in evaluated if item]
            valid_count += len(page_results)
            results.extend(page_results)
            if len(results) >= 10:
                break
        results.sort(key=lambda item: item["distance"])
        return {
            "server": server.upper(), "origin_player": origin_name,
            "origin_coordinates": {"x": origin_coords[0], "y": origin_coords[1]},
            "results": results[:10], "valid_targets_found": valid_count,
            "scanned_pages": scanned_pages, "total_pages_available": total_pages,
            "truncated": len(scanned_pages) < total_pages,
        }

@app.get("/api/bot/player-history/{player_id}")
async def bot_player_history(player_id: int, player: str = "", server: str = "E4K_PL1_BETA", user: User = Depends(current_user)):
    if player_id <= 0 or len(player) > 80:
        raise HTTPException(400, "Nieprawidłowy identyfikator lub nazwa gracza.")
    async def safe_get(path: str, params: dict | None = None):
        try:
            return await bot_tracker_get(path, server, params)
        except HTTPException as exc:
            if exc.status_code in (404, 502):
                return {}
            raise
    names, alliances = await asyncio.gather(
        safe_get(f"updates/players/{player_id}/names"),
        safe_get(f"updates/players/{player_id}/alliances"),
    )
    movements = {}
    if player.strip():
        try:
            url = "https://api.gge-tracker.com/api/v1/server/movements"
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                response = await client.get(url, headers=bot_headers(server), params={
                    "page": 1, "castleType": 1, "movementType": 3,
                    "search": player.strip(), "searchType": "player",
                })
            if response.status_code == 200:
                movements = response.json()
            elif response.status_code not in (404, 429):
                raise HTTPException(502, f"GGE Tracker zwrócił błąd {response.status_code} przy historii ruchów.")
        except HTTPException:
            raise
        except Exception:
            movements = {}
    def rows(payload, key):
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            value = payload.get(key, [])
            return value if isinstance(value, list) else []
        return []
    return {
        "player_id": player_id, "player": player, "server": server.upper(),
        "names": rows(names, "updates"),
        "alliances": rows(alliances, "updates"),
        "movements": rows(movements, "movements"),
        "partial": not bool(names) or not bool(alliances),
    }

@app.get("/api/bot/calendar")
async def bot_calendar(view: str = "main", refresh: bool = False, user: User = Depends(current_user)):
    if view not in ("main", "future", "alliance"):
        raise HTTPException(400, "Nieprawidłowy widok kalendarza.")
    events = await _get_live_calendar(force=refresh)
    now = datetime.now(timezone.utc)
    visible = []
    for event in events:
        start_dt = datetime.fromisoformat(event["start"])
        end_dt = datetime.fromisoformat(event["end"])
        if end_dt < now:
            continue
        if view == "future" and not (start_dt > now and start_dt - now <= timedelta(days=7)):
            continue
        if view == "alliance" and event["key"] not in CALENDAR_ALLIANCE_KEYS:
            continue
        visible.append(event)
    return {"view": view, "events": visible, "total": len(visible),
            "updated_at": datetime.fromtimestamp(CALENDAR_CACHE["at"], timezone.utc).isoformat() if CALENDAR_CACHE["at"] else None,
            "source": CALENDAR_SOURCE_URL, "warning": CALENDAR_CACHE["last_error"]}


@app.get("/api/features")
def features(user: User = Depends(current_user)):
    return {
        "available": ["player_profile","alliance_profile","server_statistics","fortress_history","event_calendar"],
        "in_development": ["live_map","target_radar","fortress_scanner","storm_islands","rankings","web_notifications"],
        "note": "Funkcje zewnętrzne wymagają dostępności GGE Tracker i prawidłowego serwera."
    }

if SITE.exists():
    app.mount("/", StaticFiles(directory=str(SITE), html=True), name="site")
