"""
GitHub Repository Visibility Manager

A dependency-free Windows desktop app for safely changing many GitHub
repositories between public and private visibility.

Security:
- The GitHub token is never written as plain text.
- When "Save securely" is enabled, Windows DPAPI encrypts it for the current
  Windows user before it is stored under %APPDATA%.

Python: 3.10+
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import re
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Callable, Iterable
from contextlib import suppress
from datetime import datetime, timezone
from tkinter import (
    BOTH,
    END,
    LEFT,
    RIGHT,
    VERTICAL,
    W,
    BooleanVar,
    StringVar,
    Tk,
    filedialog,
    messagebox,
)
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any

# Never create .pyc files for this standalone app.
sys.dont_write_bytecode = True


def enable_dark_titlebar(root: Tk) -> None:
    """Use the Windows dark title bar when the OS supports it."""
    if os.name != "nt":
        return
    with suppress(Exception):
        root.update_idletasks()
        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        dwmapi.DwmSetWindowAttribute.argtypes = [
            wintypes.HWND,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long

        dark_mode = ctypes.c_int(1)
        for attribute in (20, 19):  # Windows 11, then Windows 10 attribute IDs.
            result = dwmapi.DwmSetWindowAttribute(
                root.winfo_id(),
                attribute,
                ctypes.byref(dark_mode),
                ctypes.sizeof(dark_mode),
            )
            if result == 0:
                break


APP_NAME = "GitHub Repository Visibility Manager"
APP_SLUG = "GitHubRepoVisibilityManager"
APP_VERSION = "1.4.1"
API_BASE = "https://api.github.com"
API_VERSION = "2026-03-10"
TOKEN_PAGE = "https://github.com/settings/personal-access-tokens/new"
TOKEN_SETTINGS_PAGE = "https://github.com/settings/personal-access-tokens"
TOKEN_DOCS = "https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
VISIBILITY_DOCS = "https://docs.github.com/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility"

APP_DIR = Path(os.getenv("APPDATA") or Path.home()) / APP_SLUG
SETTINGS_FILE = APP_DIR / "settings.json"
SNAPSHOT_DIR = APP_DIR / "snapshots"
LOG_DIR = APP_DIR / "logs"
SCRIPT_DIR = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()
PACKAGE_CACHE_DIR = SCRIPT_DIR / "cache"
APPDATA_CACHE_DIR = APP_DIR / "cache"
CACHE_SCHEMA_VERSION = 1
CACHE_MAX_AGE_SECONDS = 30 * 60


class AppError(RuntimeError):
    """Expected, user-facing application error."""


class GitHubAPIError(AppError):
    def __init__(
        self,
        status: int,
        message: str,
        details: str = "",
        *,
        accepted_permissions: str = "",
        oauth_scopes: str = "",
        accepted_oauth_scopes: str = "",
        request_id: str = "",
    ) -> None:
        self.status = status
        self.message = message
        self.details = details
        self.accepted_permissions = accepted_permissions
        self.oauth_scopes = oauth_scopes
        self.accepted_oauth_scopes = accepted_oauth_scopes
        self.request_id = request_id
        text = f"GitHub API error {status}: {message}"
        if details and details != message and not details.startswith("http"):
            text += f"\n{details}"
        super().__init__(text)


class GitHubPermissionError(AppError):
    """A token is valid for reading, but cannot modify repository settings."""

    def __init__(self, full_name: str, api_error: GitHubAPIError) -> None:
        self.full_name = full_name
        self.api_error = api_error
        owner = full_name.split("/", 1)[0] if "/" in full_name else full_name
        required = api_error.accepted_permissions or "administration=write"
        scopes = (
            api_error.oauth_scopes or "not reported (normal for fine-grained tokens)"
        )
        request_id = (
            f"\nGitHub request ID: {api_error.request_id}"
            if api_error.request_id
            else ""
        )
        super().__init__(
            f"GitHub denied repository-settings access for {full_name}.\n\n"
            "For a fine-grained personal access token, edit or create the token with:\n"
            f" Resource owner: {owner}\n"
            f" Repository access: {full_name} or All repositories\n"
            " Repository permissions  Administration: Read and write\n\n"
            "For a classic personal access token, enable the full repo scope.\n\n"
            f"GitHub required permission: {required}\n"
            f"Classic-token scopes reported: {scopes}"
            f"{request_id}"
        )


# ---------------------------------------------------------------------------
# Windows DPAPI token protection (standard library only)
# ---------------------------------------------------------------------------


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _blob_from_bytes(data: bytes) -> tuple[DATA_BLOB, Any]:
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = DATA_BLOB(
        len(data),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buffer


def _dpapi_libraries() -> tuple[Any, Any]:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def dpapi_encrypt(text: str) -> str:
    if os.name != "nt":
        raise AppError("Secure token saving requires Windows.")

    crypt32, kernel32 = _dpapi_libraries()
    raw = text.encode("utf-8")
    in_blob, _buffer = _blob_from_bytes(raw)
    out_blob = DATA_BLOB()

    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "GitHub token",
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()

    try:
        protected = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return base64.b64encode(protected).decode("ascii")
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))


def dpapi_decrypt(encoded: str) -> str:
    if os.name != "nt":
        raise AppError("Secure token loading requires Windows.")

    crypt32, kernel32 = _dpapi_libraries()
    protected = base64.b64decode(encoded.encode("ascii"), validate=True)
    in_blob, _buffer = _blob_from_bytes(protected)
    out_blob = DATA_BLOB()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()

    try:
        raw = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return raw.decode("utf-8")
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------


def ensure_app_dirs() -> Path:
    """Create data folders and return a writable repository-cache directory."""
    for path in (APP_DIR, SNAPSHOT_DIR, LOG_DIR):
        path.mkdir(parents=True, exist_ok=True)

    for candidate in (PACKAGE_CACHE_DIR, APPDATA_CACHE_DIR):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return candidate
        except OSError:
            continue
    raise AppError("The app could not create a writable cache folder.")


def token_fingerprint(token: str) -> str:
    """Create a non-reversible identifier so caches never cross tokens."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()[:20]


def repository_cache_path(cache_dir: Path, token: str, login: str) -> Path:
    safe_login = re.sub(r"[^A-Za-z0-9_.-]+", "_", login.strip().lower()) or "github"
    return cache_dir / f"repo_cache_{safe_login}_{token_fingerprint(token)}.json"


def remove_file_safely(path: Path) -> None:
    with suppress(OSError):
        path.unlink(missing_ok=True)


def save_repository_cache(
    cache_dir: Path,
    token: str,
    login: str,
    repositories: list[dict[str, Any]],
) -> Path:
    path = repository_cache_path(cache_dir, token, login)
    payload = {
        "cache_schema": CACHE_SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "created_at": utc_now_iso(),
        "created_at_epoch": time.time(),
        "github_user": login,
        "token_fingerprint": token_fingerprint(token),
        "repository_count": len(repositories),
        "repositories": repositories,
    }
    atomic_write_json(path, payload)
    return path


def load_repository_cache(
    cache_dir: Path,
    token: str,
    login: str,
) -> tuple[list[dict[str, Any]] | None, str]:
    path = repository_cache_path(cache_dir, token, login)
    if not path.exists():
        return None, "no cache exists for this token"

    payload = load_json(path, None)
    if not isinstance(payload, dict):
        remove_file_safely(path)
        return None, "cache file was invalid and was removed"
    if payload.get("cache_schema") != CACHE_SCHEMA_VERSION:
        remove_file_safely(path)
        return None, "cache format was outdated and was removed"
    if payload.get("app_version") != APP_VERSION:
        remove_file_safely(path)
        return None, "cache belonged to an older app version and was removed"
    if payload.get("github_user") != login:
        remove_file_safely(path)
        return None, "cache user did not match and was removed"
    if payload.get("token_fingerprint") != token_fingerprint(token):
        remove_file_safely(path)
        return None, "cache token did not match and was removed"

    try:
        created = float(payload.get("created_at_epoch", 0))
    except (TypeError, ValueError):
        created = 0
    age = max(0.0, time.time() - created)
    if created <= 0 or age > CACHE_MAX_AGE_SECONDS:
        remove_file_safely(path)
        return None, "cache had expired and was removed"

    repositories = payload.get("repositories")
    if not isinstance(repositories, list) or not all(
        is_repository_record(item) for item in repositories
    ):
        remove_file_safely(path)
        return None, "cached repository data was invalid and was removed"

    minutes = max(0, int(age // 60))
    return repositories, f"fresh cache ({minutes} minute(s) old)"


def clear_repository_cache(cache_dir: Path) -> int:
    removed = 0
    for pattern in ("repo_cache_*.json", "repo_cache_*.json.tmp"):
        for item in cache_dir.glob(pattern):
            try:
                item.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def prune_runtime_cache(cache_dir: Path) -> list[str]:
    """Remove only invalid/expired app caches and this app's bytecode."""
    removed: list[str] = []
    now = time.time()

    for item in cache_dir.glob("repo_cache_*.json"):
        payload = load_json(item, None)
        invalid = not isinstance(payload, dict)
        if isinstance(payload, dict):
            invalid = (
                payload.get("cache_schema") != CACHE_SCHEMA_VERSION
                or payload.get("app_version") != APP_VERSION
            )
            try:
                created = float(payload.get("created_at_epoch", 0))
            except (TypeError, ValueError):
                created = 0
            invalid = invalid or created <= 0 or (now - created) > CACHE_MAX_AGE_SECONDS
        if invalid:
            try:
                item.unlink()
                removed.append(str(item))
            except OSError:
                pass

    for item in cache_dir.glob("repo_cache_*.json.tmp"):
        try:
            item.unlink()
            removed.append(str(item))
        except OSError:
            pass

    try:
        pycache = SCRIPT_DIR / "__pycache__"
        if pycache.is_dir():
            for pattern in (
                "github_repo_visibility_manager*.pyc",
                "GitHub_Repo_Visibility_Manager*.pyc",
            ):
                for cached_file in pycache.glob(pattern):
                    try:
                        cached_file.unlink()
                        removed.append(str(cached_file))
                    except OSError:
                        pass
            with suppress(OSError):
                pycache.rmdir()
    except OSError:
        pass

    return removed


def load_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    try:
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        temp.replace(path)
    except Exception:
        remove_file_safely(temp)
        raise


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def local_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def format_updated(value: str) -> str:
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


def repository_visibility(repo: dict[str, Any]) -> str:
    """Return GitHub's visibility value, including organization-internal repos."""
    return str(
        repo.get("visibility") or ("private" if repo.get("private") else "public")
    )


def repository_owner(repo: dict[str, Any]) -> str:
    owner = repo.get("owner")
    return str(owner.get("login", "")) if isinstance(owner, dict) else ""


def repository_has_admin_access(repo: dict[str, Any]) -> bool:
    permissions = repo.get("permissions")
    return (
        bool(permissions.get("admin", False))
        if isinstance(permissions, dict)
        else False
    )


def is_repository_record(value: Any) -> bool:
    """Check the minimum shape required by the UI and repository PATCH calls."""
    if not isinstance(value, dict):
        return False
    repo_id = value.get("id")
    full_name = value.get("full_name")
    return (
        isinstance(repo_id, (int, str))
        and bool(str(repo_id))
        and isinstance(full_name, str)
        and full_name.count("/") == 1
        and all(full_name.split("/"))
    )


# ---------------------------------------------------------------------------
# GitHub REST API client
# ---------------------------------------------------------------------------


class GitHubClient:
    def __init__(self, token: str, logger: Callable[[str], None]) -> None:
        self.token = token.strip()
        self.logger = logger
        self.last_rate_remaining = "?"
        self.last_rate_limit = "?"
        self.last_rate_reset = ""

    @property
    def headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": f"{APP_SLUG}/{APP_VERSION}",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
        }

    def _extract_error(self, raw: bytes) -> tuple[str, str]:
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return "Request failed", ""
        try:
            payload = json.loads(text)
            if not isinstance(payload, dict):
                return text[:500], ""
            message = str(payload.get("message") or "Request failed")
            details_obj = (
                payload.get("errors") or payload.get("documentation_url") or ""
            )
            if isinstance(details_obj, (dict, list)):
                details = json.dumps(details_obj, ensure_ascii=False)
            else:
                details = str(details_obj)
            return message, details
        except json.JSONDecodeError:
            return text[:500], ""

    def _update_rate_info(self, headers: Any) -> None:
        self.last_rate_remaining = headers.get(
            "X-RateLimit-Remaining", self.last_rate_remaining
        )
        self.last_rate_limit = headers.get("X-RateLimit-Limit", self.last_rate_limit)
        reset = headers.get("X-RateLimit-Reset")
        if reset:
            try:
                dt = datetime.fromtimestamp(int(reset)).astimezone()
                self.last_rate_reset = dt.strftime("%H:%M:%S")
            except (TypeError, ValueError, OSError):
                self.last_rate_reset = ""

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        retries: int = 4,
    ) -> tuple[Any, Any]:
        url = path if path.startswith("http") else f"{API_BASE}{path}"
        if query:
            encoded = urllib.parse.urlencode(query, doseq=True, safe=",")
            url = f"{url}{'&' if '?' in url else '?'}{encoded}"

        payload = None
        headers = self.headers.copy()
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        retryable_codes = {429, 500, 502, 503, 504}
        last_error: Exception | None = None

        for attempt in range(1, retries + 1):
            request = urllib.request.Request(
                url=url,
                data=payload,
                headers=headers,
                method=method.upper(),
            )
            try:
                with urllib.request.urlopen(request, timeout=35) as response:
                    raw = response.read()
                    self._update_rate_info(response.headers)
                    if not raw:
                        return None, response.headers
                    return json.loads(raw.decode("utf-8")), response.headers
            except urllib.error.HTTPError as exc:
                raw = exc.read()
                self._update_rate_info(exc.headers)
                message, details = self._extract_error(raw)
                message_lower = message.lower()

                remaining = exc.headers.get("X-RateLimit-Remaining", "")
                retry_after = exc.headers.get("Retry-After", "")
                secondary_limit = exc.code == 403 and (
                    "secondary rate limit" in message_lower
                    or "abuse detection" in message_lower
                    or remaining == "0"
                )

                if (
                    exc.code in retryable_codes or secondary_limit
                ) and attempt < retries:
                    try:
                        delay = (
                            max(float(retry_after), 1.0)
                            if retry_after
                            else min(2**attempt, 20)
                        )
                    except ValueError:
                        delay = min(2**attempt, 20)
                    self.logger(
                        f"Temporary GitHub response ({exc.code}); retrying in {delay:.0f}s "
                        f"[{attempt}/{retries - 1}]."
                    )
                    time.sleep(delay)
                    continue

                raise GitHubAPIError(
                    exc.code,
                    message,
                    details,
                    accepted_permissions=exc.headers.get(
                        "X-Accepted-GitHub-Permissions", ""
                    ),
                    oauth_scopes=exc.headers.get("X-OAuth-Scopes", ""),
                    accepted_oauth_scopes=exc.headers.get(
                        "X-Accepted-OAuth-Scopes", ""
                    ),
                    request_id=exc.headers.get("X-GitHub-Request-Id", ""),
                ) from None
            except (
                http.client.IncompleteRead,
                urllib.error.URLError,
                TimeoutError,
                OSError,
            ) as exc:
                last_error = exc
                if attempt < retries:
                    delay = min(2**attempt, 15)
                    self.logger(
                        f"Network error: {exc}. Retrying in {delay}s "
                        f"[{attempt}/{retries - 1}]."
                    )
                    time.sleep(delay)
                    continue
                break
            except json.JSONDecodeError as exc:
                raise AppError(f"GitHub returned invalid JSON: {exc}") from None

        raise AppError(f"GitHub request failed after retries: {last_error}")

    def get_authenticated_user(self) -> dict[str, Any]:
        data, _headers = self.request("GET", "/user")
        if not isinstance(data, dict) or not data.get("login"):
            raise AppError("GitHub did not return a valid authenticated user.")
        return data

    def list_repositories(self) -> list[dict[str, Any]]:
        repositories: list[dict[str, Any]] = []
        page = 1
        while True:
            data, _headers = self.request(
                "GET",
                "/user/repos",
                query={
                    "visibility": "all",
                    "affiliation": "owner,organization_member,collaborator",
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": 100,
                    "page": page,
                },
            )
            if not isinstance(data, list):
                raise AppError(
                    "GitHub returned an unexpected repository list response."
                )
            if not all(is_repository_record(item) for item in data):
                raise AppError(
                    "GitHub returned a repository record with an unexpected format."
                )
            repositories.extend(data)
            self.logger(f"Fetched page {page}: {len(data)} repositories.")
            if len(data) < 100:
                break
            page += 1
        return repositories

    def _patch_repository(self, full_name: str, body: dict[str, Any]) -> dict[str, Any]:
        if full_name.count("/") != 1 or not all(full_name.split("/")):
            raise AppError(f"Invalid GitHub repository name: {full_name!r}")
        owner, repo = full_name.split("/", 1)
        path = f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"
        try:
            data, _headers = self.request("PATCH", path, body=body)
        except GitHubAPIError as exc:
            message = exc.message.lower()
            if exc.status == 403 and (
                "resource not accessible by personal access token" in message
                or "resource not accessible by integration" in message
            ):
                raise GitHubPermissionError(full_name, exc) from None
            raise
        if not isinstance(data, dict):
            raise AppError(f"Unexpected response while updating {full_name}.")
        return data

    def verify_update_access(self, full_name: str, current_visibility: str) -> None:
        """Harmless no-op PATCH that verifies Administration:write before a bulk run."""
        if current_visibility not in {"public", "private", "internal"}:
            raise AppError(
                f"Unsupported current repository visibility: {current_visibility!r}"
            )
        self._patch_repository(full_name, {"visibility": current_visibility})

    def set_visibility(self, full_name: str, visibility: str) -> dict[str, Any]:
        if visibility not in {"public", "private"}:
            raise ValueError("visibility must be public or private")
        return self._patch_repository(full_name, {"visibility": visibility})


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------


class RepoVisibilityApp:
    BG = "#070b14"
    PANEL = "#0f172a"
    PANEL_ALT = "#172554"
    FIELD = "#0b1426"
    TEXT = "#e6edf7"
    MUTED = "#8da2bd"
    BORDER = "#203557"
    ACCENT = "#22d3ee"
    ACCENT_ACTIVE = "#06b6d4"
    BUTTON_ACCENT = "#0e7490"
    BUTTON_ACCENT_ACTIVE = "#155e75"
    DANGER = "#be123c"
    DANGER_ACTIVE = "#9f1239"
    SUCCESS = "#34d399"
    WARNING = "#fbbf24"

    def __init__(self, root: Tk) -> None:
        self.root = root
        enable_dark_titlebar(root)
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("1180x780")
        self.root.minsize(980, 650)
        self.root.configure(bg=self.BG)

        self.cache_dir = ensure_app_dirs()
        self.startup_cache_removed = prune_runtime_cache(self.cache_dir)
        self.settings = load_json(SETTINGS_FILE, {})
        self.repositories: list[dict[str, Any]] = []
        self.repo_by_id: dict[str, dict[str, Any]] = {}
        self.checked_repo_ids: set[str] = set()
        self.client: GitHubClient | None = None
        self.login = ""
        self.worker_thread: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self.ui_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.busy = False
        self.last_snapshot: Path | None = None
        self.log_lines: list[str] = []
        self.pending_filter_job: str | None = None
        self.cache_dirty = False

        self.token_var = StringVar()
        self.save_token_var = BooleanVar(
            value=bool(self.settings.get("save_token", True))
        )
        self.show_token_var = BooleanVar(value=False)
        self.search_var = StringVar()
        self.search_scope_var = StringVar(value="All fields")
        self.visibility_filter_var = StringVar(value="All visibility")
        self.owner_filter_var = StringVar(value="All owners")
        self.admin_only_var = BooleanVar(value=True)
        self.include_forks_var = BooleanVar(value=True)
        self.include_archived_var = BooleanVar(value=True)
        self.dry_run_var = BooleanVar(value=False)
        self.auto_snapshot_var = BooleanVar(value=True)
        self.connection_var = StringVar(value="Not connected")
        self.summary_var = StringVar(value="0 repositories")
        self.selection_var = StringVar(value="0 ticked")
        self.rate_var = StringVar(value="Rate limit: -")
        self.progress_var = StringVar(value="Ready")

        self._configure_styles()
        self._build_menu()
        self._build_ui()
        saved_token_loaded = self._load_saved_token()
        if getattr(self, "startup_cache_removed", None):
            self._log(
                f"Removed {len(self.startup_cache_removed)} expired or incompatible cache item(s)."
            )
        self._log(f"Running v{APP_VERSION}. Cache folder: {self.cache_dir}")
        self._log(
            "Connect & Load may use repository data cached for up to 30 minutes; Refresh from GitHub always loads live data."
        )
        self._install_exception_handler()
        self._poll_ui_queue()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        if saved_token_loaded:
            self.root.after(250, self._auto_connect_saved_token)

    # ----- UI setup --------------------------------------------------------

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        with suppress(Exception):
            style.theme_use("clam")

        default_font = ("Segoe UI", 10)
        style.configure(
            ".", font=default_font, background=self.BG, foreground=self.TEXT
        )
        style.configure("App.TFrame", background=self.BG)
        style.configure("Panel.TFrame", background=self.PANEL)
        style.configure("PanelAlt.TFrame", background=self.PANEL_ALT)
        style.configure(
            "Title.TLabel",
            background=self.BG,
            foreground=self.TEXT,
            font=("Segoe UI Semibold", 20),
        )
        style.configure(
            "Subtitle.TLabel",
            background=self.BG,
            foreground=self.MUTED,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Section.TLabel",
            background=self.PANEL,
            foreground=self.TEXT,
            font=("Segoe UI Semibold", 11),
        )
        style.configure("Panel.TLabel", background=self.PANEL, foreground=self.TEXT)
        style.configure("Muted.TLabel", background=self.PANEL, foreground=self.MUTED)
        style.configure("Status.TLabel", background=self.BG, foreground=self.MUTED)
        style.configure(
            "StatusBadge.TLabel",
            background=self.PANEL_ALT,
            foreground=self.ACCENT,
            padding=(10, 5),
            font=("Segoe UI Semibold", 9),
        )
        style.configure(
            "StatusMutedBadge.TLabel",
            background=self.PANEL_ALT,
            foreground=self.MUTED,
            padding=(10, 5),
            font=("Segoe UI", 9),
        )
        style.configure(
            "TEntry",
            fieldbackground=self.FIELD,
            foreground=self.TEXT,
            insertcolor=self.TEXT,
            bordercolor=self.BORDER,
            lightcolor=self.BORDER,
            darkcolor=self.BORDER,
            padding=(10, 8),
        )
        style.map("TEntry", bordercolor=[("focus", self.ACCENT)])
        style.configure(
            "Search.TEntry",
            fieldbackground=self.FIELD,
            foreground=self.TEXT,
            insertcolor=self.ACCENT,
            bordercolor=self.BORDER,
            lightcolor=self.BORDER,
            darkcolor=self.BORDER,
            padding=(11, 9),
        )
        style.map("Search.TEntry", bordercolor=[("focus", self.ACCENT)])
        style.configure(
            "TCombobox",
            fieldbackground=self.FIELD,
            background=self.FIELD,
            foreground=self.TEXT,
            arrowcolor=self.TEXT,
            bordercolor=self.BORDER,
            padding=(8, 7),
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", self.FIELD)],
            foreground=[("readonly", self.TEXT)],
            selectbackground=[("readonly", self.FIELD)],
            selectforeground=[("readonly", self.TEXT)],
        )
        style.configure(
            "TCheckbutton",
            background=self.PANEL,
            foreground=self.TEXT,
            indicatorcolor=self.FIELD,
            padding=(2, 4),
        )
        style.map(
            "TCheckbutton",
            background=[("active", self.PANEL)],
            foreground=[("disabled", self.MUTED)],
            indicatorcolor=[
                ("selected", self.ACCENT),
                ("pressed", self.ACCENT_ACTIVE),
                ("!selected", self.FIELD),
            ],
        )

        style.configure(
            "TButton",
            background=self.PANEL_ALT,
            foreground=self.TEXT,
            bordercolor=self.BORDER,
            relief="flat",
            borderwidth=0,
            focusthickness=1,
            focuscolor=self.ACCENT,
            padding=(13, 8),
        )
        style.map(
            "TButton",
            background=[("active", "#244064"), ("disabled", "#1b2940")],
            foreground=[("disabled", "#64748b")],
        )
        style.configure(
            "Primary.TButton",
            background=self.BUTTON_ACCENT,
            foreground="white",
            bordercolor=self.BUTTON_ACCENT,
        )
        style.map(
            "Primary.TButton",
            background=[
                ("active", self.BUTTON_ACCENT_ACTIVE),
                ("disabled", "#1e3a5f"),
            ],
        )
        style.configure(
            "Danger.TButton",
            background=self.DANGER,
            foreground="white",
            bordercolor=self.DANGER,
        )
        style.map(
            "Danger.TButton",
            background=[("active", self.DANGER_ACTIVE), ("disabled", "#4a2025")],
        )

        style.configure(
            "Treeview",
            background=self.FIELD,
            fieldbackground=self.FIELD,
            foreground=self.TEXT,
            rowheight=32,
            bordercolor=self.BORDER,
            lightcolor=self.BORDER,
            darkcolor=self.BORDER,
        )
        style.map(
            "Treeview",
            background=[("selected", "#155e75")],
            foreground=[("selected", "white")],
        )
        style.configure(
            "Treeview.Heading",
            background=self.PANEL_ALT,
            foreground=self.TEXT,
            relief="flat",
            padding=(8, 9),
            font=("Segoe UI Semibold", 9),
        )
        style.map("Treeview.Heading", background=[("active", "#244064")])
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=self.FIELD,
            background=self.ACCENT,
            bordercolor=self.FIELD,
            lightcolor=self.ACCENT,
            darkcolor=self.ACCENT,
        )
        style.configure(
            "Vertical.TScrollbar",
            background=self.PANEL_ALT,
            troughcolor=self.FIELD,
            arrowcolor=self.TEXT,
        )

    def _build_menu(self) -> None:
        import tkinter as tk

        menu_options = {
            "background": self.PANEL,
            "foreground": self.TEXT,
            "activebackground": self.PANEL_ALT,
            "activeforeground": self.ACCENT,
            "borderwidth": 0,
            "relief": "flat",
            "activeborderwidth": 0,
        }
        menu = tk.Menu(self.root, **menu_options)
        file_menu = tk.Menu(menu, tearoff=False, **menu_options)
        file_menu.add_command(label="Export log...", command=self._export_log)
        file_menu.add_command(
            label="Open app data folder", command=lambda: self._open_folder(APP_DIR)
        )
        file_menu.add_command(
            label="Open cache folder", command=lambda: self._open_folder(self.cache_dir)
        )
        file_menu.add_command(
            label="Clear repository cache", command=self._clear_repository_cache
        )
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menu.add_cascade(label="File", menu=file_menu)

        token_menu = tk.Menu(menu, tearoff=False, **menu_options)
        token_menu.add_command(
            label="Create fine-grained token",
            command=lambda: webbrowser.open(TOKEN_PAGE),
        )
        token_menu.add_command(
            label="Manage token permissions",
            command=lambda: webbrowser.open(TOKEN_SETTINGS_PAGE),
        )
        token_menu.add_command(
            label="Token documentation", command=lambda: webbrowser.open(TOKEN_DOCS)
        )
        token_menu.add_command(label="Forget saved token", command=self._forget_token)
        menu.add_cascade(label="Token", menu=token_menu)

        help_menu = tk.Menu(menu, tearoff=False, **menu_options)
        help_menu.add_command(
            label="GitHub visibility consequences",
            command=lambda: webbrowser.open(VISIBILITY_DOCS),
        )
        help_menu.add_command(label="About", command=self._show_about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.root.configure(menu=menu)

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, style="App.TFrame", padding=(22, 18, 22, 14))
        outer.pack(fill=BOTH, expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(3, weight=1)

        header = ttk.Frame(outer, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        header.columnconfigure(0, weight=1)
        ttk.Label(
            header,
            text=f"GitHub Repository Visibility Manager  v{APP_VERSION}",
            style="Title.TLabel",
        ).grid(row=0, column=0, sticky=W)
        ttk.Label(
            header,
            text="Tick only the repositories you want, then change them in bulk with secure snapshots and logs.",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky=W, pady=(3, 0))
        ttk.Label(
            header,
            textvariable=self.connection_var,
            style="StatusBadge.TLabel",
        ).grid(row=0, column=1, sticky="e")
        ttk.Label(
            header,
            textvariable=self.rate_var,
            style="StatusMutedBadge.TLabel",
        ).grid(row=1, column=1, sticky="e", pady=(5, 0))

        token_panel = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        token_panel.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        token_panel.columnconfigure(1, weight=1)
        ttk.Label(token_panel, text="GitHub access token", style="Section.TLabel").grid(
            row=0, column=0, sticky=W, padx=(0, 12)
        )
        self.token_entry = ttk.Entry(token_panel, textvariable=self.token_var, show="")
        self.token_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.connect_button = ttk.Button(
            token_panel,
            text="Connect & Load",
            style="Primary.TButton",
            command=self._connect_and_load,
        )
        self.connect_button.grid(row=0, column=2, padx=(0, 8))
        ttk.Button(token_panel, text="Forget", command=self._forget_token).grid(
            row=0, column=3
        )

        token_options = ttk.Frame(token_panel, style="Panel.TFrame")
        token_options.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(9, 0))
        ttk.Checkbutton(
            token_options,
            text="Save securely with Windows DPAPI",
            variable=self.save_token_var,
        ).pack(side=LEFT)
        ttk.Checkbutton(
            token_options,
            text="Show token",
            variable=self.show_token_var,
            command=self._toggle_token_visibility,
        ).pack(side=LEFT, padx=(18, 0))
        ttk.Button(
            token_options,
            text="Manage permissions",
            command=lambda: webbrowser.open(TOKEN_SETTINGS_PAGE),
        ).pack(side=RIGHT)
        ttk.Button(
            token_options,
            text="Create token",
            command=lambda: webbrowser.open(TOKEN_PAGE),
        ).pack(side=RIGHT, padx=(0, 8))
        ttk.Label(
            token_panel,
            text="Required: Resource owner must match the repository owner  Repository access includes it  Administration: Read and write.",
            style="Muted.TLabel",
        ).grid(row=2, column=1, columnspan=3, sticky=W, pady=(7, 0))
        ttk.Label(
            token_panel,
            text="Repository cache: up to 30 minutes. Use Refresh from GitHub to bypass it immediately.",
            style="Muted.TLabel",
        ).grid(row=3, column=1, columnspan=3, sticky=W, pady=(3, 0))

        filter_panel = ttk.Frame(outer, style="Panel.TFrame", padding=12)
        filter_panel.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        filter_panel.columnconfigure(0, weight=1)

        self.search_entry = ttk.Entry(
            filter_panel,
            textvariable=self.search_var,
            style="Search.TEntry",
        )
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.search_var.trace_add("write", self._schedule_filter)

        self.search_scope_combo = ttk.Combobox(
            filter_panel,
            textvariable=self.search_scope_var,
            values=(
                "All fields",
                "Repository name",
                "Full name",
                "Owner",
                "Description",
            ),
            state="readonly",
            width=18,
        )
        self.search_scope_combo.grid(row=0, column=1, padx=(0, 8))
        self.search_scope_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self._apply_filters()
        )

        self.visibility_combo = ttk.Combobox(
            filter_panel,
            textvariable=self.visibility_filter_var,
            values=("All visibility", "Public only", "Private only"),
            state="readonly",
            width=16,
        )
        self.visibility_combo.grid(row=0, column=2, padx=(0, 8))
        self.visibility_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self._apply_filters()
        )

        self.owner_combo = ttk.Combobox(
            filter_panel,
            textvariable=self.owner_filter_var,
            values=("All owners",),
            state="readonly",
            width=20,
        )
        self.owner_combo.grid(row=0, column=3, padx=(0, 8))
        self.owner_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self._apply_filters()
        )

        self.refresh_button = ttk.Button(
            filter_panel,
            text="Refresh from GitHub",
            command=lambda: self._connect_and_load(force_live=True),
        )
        self.refresh_button.grid(row=0, column=4, padx=(0, 8))
        ttk.Button(
            filter_panel, text="Clear filters", command=self._clear_filters
        ).grid(row=0, column=5)

        filter_checks = ttk.Frame(filter_panel, style="Panel.TFrame")
        filter_checks.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(9, 0))
        for text, var in (
            ("Admin access only", self.admin_only_var),
            ("Include forks", self.include_forks_var),
            ("Include archived", self.include_archived_var),
        ):
            ttk.Checkbutton(
                filter_checks, text=text, variable=var, command=self._apply_filters
            ).pack(side=LEFT, padx=(0, 16))
        ttk.Label(
            filter_checks, textvariable=self.summary_var, style="Muted.TLabel"
        ).pack(side=RIGHT)

        content = ttk.Frame(outer, style="App.TFrame")
        content.grid(row=3, column=0, sticky="nsew")
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)
        content.rowconfigure(0, weight=1)

        repo_panel = ttk.Frame(content, style="Panel.TFrame", padding=10)
        repo_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        repo_panel.columnconfigure(0, weight=1)
        repo_panel.rowconfigure(1, weight=1)

        repo_header = ttk.Frame(repo_panel, style="Panel.TFrame")
        repo_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(repo_header, text="Repositories", style="Section.TLabel").pack(
            side=LEFT
        )
        ttk.Label(
            repo_header, textvariable=self.selection_var, style="Muted.TLabel"
        ).pack(side=RIGHT)

        tree_wrap = ttk.Frame(repo_panel, style="Panel.TFrame")
        tree_wrap.grid(row=1, column=0, sticky="nsew")
        tree_wrap.columnconfigure(0, weight=1)
        tree_wrap.rowconfigure(0, weight=1)

        columns = (
            "repository",
            "visibility",
            "owner",
            "updated",
            "fork",
            "archived",
            "access",
        )
        self.tree = ttk.Treeview(
            tree_wrap, columns=columns, show="tree headings", selectmode="browse"
        )
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(tree_wrap, orient=VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.heading("#0", text="Tick")
        self.tree.heading("repository", text="Repository")
        self.tree.heading("visibility", text="Visibility")
        self.tree.heading("owner", text="Owner")
        self.tree.heading("updated", text="Updated")
        self.tree.heading("fork", text="Fork")
        self.tree.heading("archived", text="Archived")
        self.tree.heading("access", text="Admin")
        self.tree.column("#0", width=52, minwidth=52, anchor="center", stretch=False)
        self.tree.column("repository", width=235, minwidth=170, stretch=True)
        self.tree.column("visibility", width=82, anchor="center", stretch=False)
        self.tree.column("owner", width=130, minwidth=90)
        self.tree.column("updated", width=130, anchor="center", stretch=False)
        self.tree.column("fork", width=54, anchor="center", stretch=False)
        self.tree.column("archived", width=68, anchor="center", stretch=False)
        self.tree.column("access", width=58, anchor="center", stretch=False)
        self.tree.tag_configure("public", foreground="#86efac")
        self.tree.tag_configure("private", foreground="#93c5fd")
        self.tree.tag_configure("noadmin", foreground="#94a3b8")
        self.tree.bind("<Button-1>", self._on_tree_click, add="+")
        self.tree.bind("<space>", self._toggle_focused_repository)
        self.tree.bind("<Double-1>", self._open_selected_repository)

        select_bar = ttk.Frame(repo_panel, style="Panel.TFrame")
        select_bar.grid(row=2, column=0, sticky="ew", pady=(9, 0))
        ttk.Button(
            select_bar, text="Tick all visible", command=self._select_all_visible
        ).pack(side=LEFT)
        ttk.Button(
            select_bar, text="Untick visible", command=self._clear_visible_selection
        ).pack(side=LEFT, padx=(8, 0))
        ttk.Button(select_bar, text="Untick all", command=self._clear_selection).pack(
            side=LEFT, padx=(8, 0)
        )
        ttk.Button(
            select_bar, text="Open on GitHub", command=self._open_selected_repository
        ).pack(side=RIGHT)

        log_panel = ttk.Frame(content, style="Panel.TFrame", padding=10)
        log_panel.grid(row=0, column=1, sticky="nsew")
        log_panel.columnconfigure(0, weight=1)
        log_panel.rowconfigure(1, weight=1)
        log_header = ttk.Frame(log_panel, style="Panel.TFrame")
        log_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(log_header, text="Activity log", style="Section.TLabel").pack(
            side=LEFT
        )
        ttk.Button(log_header, text="Export", command=self._export_log).pack(side=RIGHT)
        ttk.Button(log_header, text="Clear", command=self._clear_log).pack(
            side=RIGHT, padx=(0, 8)
        )
        self.log_text = ScrolledText(
            log_panel,
            wrap="word",
            background=self.FIELD,
            foreground=self.TEXT,
            insertbackground=self.TEXT,
            selectbackground="#155e75",
            relief="flat",
            borderwidth=0,
            font=("Cascadia Mono", 9),
            padx=10,
            pady=10,
            state="disabled",
        )
        self.log_text.grid(row=1, column=0, sticky="nsew")

        action_panel = ttk.Frame(outer, style="Panel.TFrame", padding=12)
        action_panel.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        action_panel.columnconfigure(1, weight=1)

        action_left = ttk.Frame(action_panel, style="Panel.TFrame")
        action_left.grid(row=0, column=0, sticky=W)
        self.public_button = ttk.Button(
            action_left,
            text="Make ticked PUBLIC",
            style="Danger.TButton",
            command=lambda: self._start_visibility_change("public"),
        )
        self.public_button.pack(side=LEFT)
        self.private_button = ttk.Button(
            action_left,
            text="Make ticked PRIVATE",
            style="Primary.TButton",
            command=lambda: self._start_visibility_change("private"),
        )
        self.private_button.pack(side=LEFT, padx=(8, 0))
        self.restore_button = ttk.Button(
            action_left, text="Restore snapshot...", command=self._restore_snapshot
        )
        self.restore_button.pack(side=LEFT, padx=(8, 0))

        action_middle = ttk.Frame(action_panel, style="Panel.TFrame")
        action_middle.grid(row=0, column=1, sticky=W, padx=(18, 0))
        ttk.Checkbutton(action_middle, text="Dry run", variable=self.dry_run_var).pack(
            side=LEFT
        )
        ttk.Checkbutton(
            action_middle,
            text="Auto snapshot before change",
            variable=self.auto_snapshot_var,
        ).pack(side=LEFT, padx=(14, 0))

        self.stop_button = ttk.Button(
            action_panel, text="Stop", command=self._request_cancel, state="disabled"
        )
        self.stop_button.grid(row=0, column=2, sticky="e")

        progress_row = ttk.Frame(action_panel, style="Panel.TFrame")
        progress_row.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        progress_row.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(progress_row, mode="determinate", maximum=100)
        self.progress.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        ttk.Label(
            progress_row, textvariable=self.progress_var, style="Muted.TLabel"
        ).grid(row=0, column=1, sticky="e")

    # ----- settings/token --------------------------------------------------

    def _load_saved_token(self) -> bool:
        encrypted = self.settings.get("token_dpapi")
        if not encrypted:
            return False
        try:
            token = dpapi_decrypt(str(encrypted))
            self.token_var.set(token)
            self._log("Loaded the securely saved token for this Windows user.")
            return bool(token.strip())
        except Exception as exc:
            self._log(f"Could not decrypt the saved token: {exc}")
            return False

    def _auto_connect_saved_token(self) -> None:
        """Connect automatically after the window is visible and responsive."""
        if self.busy or not self.token_var.get().strip():
            return
        self._log("Automatically connecting with the securely saved token...")
        self._connect_and_load()

    def _save_settings(self, token: str | None = None) -> None:
        settings = dict(self.settings)
        settings["save_token"] = bool(self.save_token_var.get())
        if token is not None:
            if self.save_token_var.get() and token:
                settings["token_dpapi"] = dpapi_encrypt(token)
            else:
                settings.pop("token_dpapi", None)
        atomic_write_json(SETTINGS_FILE, settings)
        self.settings = settings

    def _forget_token(self) -> None:
        if self.busy:
            messagebox.showwarning(
                APP_NAME, "Stop the current operation before forgetting the token."
            )
            return
        settings = dict(self.settings)
        settings.pop("token_dpapi", None)
        settings["save_token"] = bool(self.save_token_var.get())
        atomic_write_json(SETTINGS_FILE, settings)
        self.settings = settings
        self.token_var.set("")
        self.client = None
        self.login = ""
        self.connection_var.set("Not connected")
        self.rate_var.set("Rate limit: -")
        self.repositories.clear()
        self.repo_by_id.clear()
        self.checked_repo_ids.clear()
        self._apply_filters()
        self._log("Saved token removed from this computer.")

    def _toggle_token_visibility(self) -> None:
        self.token_entry.configure(show="" if self.show_token_var.get() else "")

    # ----- background task plumbing --------------------------------------

    def _start_worker(self, target: Callable[[], None]) -> None:
        if self.busy:
            messagebox.showinfo(APP_NAME, "Another operation is already running.")
            return
        self.busy = True
        self.cancel_event.clear()
        self._set_busy_ui(True)
        self.worker_thread = threading.Thread(target=target, daemon=True)
        self.worker_thread.start()

    def _finish_worker(self) -> None:
        try:
            if self.cache_dirty and self.repositories and self.login and self.client:
                try:
                    cache_path = save_repository_cache(
                        self.cache_dir,
                        self.client.token,
                        self.login,
                        self.repositories,
                    )
                    self._log(
                        f"Updated repository cache after visibility changes: {cache_path}"
                    )
                except Exception as exc:
                    self._log(f"Could not update repository cache: {exc}")
        finally:
            self.cache_dirty = False
            self.busy = False
            self._set_busy_ui(False)
            self.worker_thread = None

    def _set_busy_ui(self, busy: bool) -> None:
        regular_state = "disabled" if busy else "normal"
        for widget in (
            self.token_entry,
            self.connect_button,
            self.refresh_button,
            self.public_button,
            self.private_button,
            self.restore_button,
        ):
            widget.configure(state=regular_state)
        self.stop_button.configure(state="normal" if busy else "disabled")
        if not busy:
            self.progress.configure(value=0)

    def _poll_ui_queue(self) -> None:
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "progress":
                    value, text = payload
                    self.progress.configure(value=value)
                    self.progress_var.set(text)
                elif kind == "loaded":
                    user, repos, client, source = payload
                    self._on_repositories_loaded(user, repos, client, source)
                elif kind == "repo_updated":
                    full_name, visibility, updated_data = payload
                    self._apply_repo_update(full_name, visibility, updated_data)
                elif kind == "error":
                    title, message = payload
                    messagebox.showerror(title, message)
                elif kind == "warning":
                    title, message = payload
                    messagebox.showwarning(title, message)
                elif kind == "info":
                    title, message = payload
                    messagebox.showinfo(title, message)
                elif kind == "permission_error":
                    open_settings = messagebox.askyesno(
                        "GitHub token permission required",
                        f"{payload}\n\nOpen GitHub token settings now?",
                        icon="error",
                    )
                    if open_settings:
                        webbrowser.open(TOKEN_SETTINGS_PAGE)
                elif kind == "finished":
                    self._finish_worker()
                    self._apply_filters()
                elif kind == "rate":
                    self._update_rate_label(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_ui_queue)

    def _queue_log(self, message: str) -> None:
        self.ui_queue.put(("log", message))

    def _queue_progress(self, value: float, text: str) -> None:
        self.ui_queue.put(("progress", (value, text)))

    def _request_cancel(self) -> None:
        if self.busy:
            self.cancel_event.set()
            self._log(
                "Cancellation requested. The current GitHub request will finish first."
            )
            self.stop_button.configure(state="disabled")

    # ----- connect and list ----------------------------------------------

    def _connect_and_load(self, force_live: bool = False) -> None:
        token = self.token_var.get().strip()
        if not token:
            messagebox.showwarning(
                APP_NAME, "Enter a GitHub personal access token first."
            )
            self.token_entry.focus_set()
            return
        if any(char.isspace() for char in token):
            messagebox.showwarning(
                APP_NAME,
                "The token contains spaces or line breaks. Paste only the token value.",
            )
            return

        try:
            self._save_settings(token)
            if self.save_token_var.get():
                self._log("Token saved securely for this Windows user.")
        except Exception as exc:
            self._log(f"Token could not be saved securely: {exc}")
            messagebox.showwarning(
                APP_NAME,
                f"The connection will continue, but the token could not be saved securely:\n\n{exc}",
            )

        def worker() -> None:
            try:
                self._queue_progress(5, "Connecting to GitHub...")
                client = GitHubClient(token, self._queue_log)
                user = client.get_authenticated_user()
                login = str(user.get("login", ""))
                self._queue_log(f"Authenticated as {login}.")

                repos: list[dict[str, Any]] | None = None
                source = "GitHub"
                if not force_live:
                    repos, cache_status = load_repository_cache(
                        self.cache_dir, token, login
                    )
                    if repos is not None:
                        source = "cache"
                        self._queue_log(
                            f"Loaded {len(repos)} repositories from {cache_status}."
                        )
                        self._queue_progress(80, "Loading fresh repository cache...")
                    else:
                        self._queue_log(f"Repository cache not used: {cache_status}.")

                if repos is None:
                    self._queue_progress(18, "Loading repositories from GitHub...")
                    repos = client.list_repositories()
                    try:
                        cache_path = save_repository_cache(
                            self.cache_dir, token, login, repos
                        )
                        self._queue_log(f"Saved fresh repository cache: {cache_path}")
                    except Exception as exc:
                        self._queue_log(
                            f"Repository list loaded, but cache could not be saved: {exc}"
                        )
                    source = "GitHub"

                self.ui_queue.put(("loaded", (user, repos, client, source)))
                self.ui_queue.put(("rate", client))
            except Exception as exc:
                self.ui_queue.put(("error", ("GitHub connection failed", str(exc))))
                self._queue_log(f"ERROR: {exc}")
            finally:
                self.ui_queue.put(("finished", None))

        self._start_worker(worker)

    def _on_repositories_loaded(
        self,
        user: dict[str, Any],
        repos: list[dict[str, Any]],
        client: GitHubClient,
        source: str,
    ) -> None:
        self.client = client
        self.login = str(user.get("login", ""))
        self.repositories = repos
        self.repo_by_id = {
            str(repo.get("id")): repo for repo in repos if repo.get("id") is not None
        }
        self.checked_repo_ids.intersection_update(self.repo_by_id.keys())
        self.cache_dirty = False
        source_label = "cached" if source == "cache" else "live"
        self.connection_var.set(f"Connected: {self.login} ({source_label})")

        owners = sorted(
            {repository_owner(repo) for repo in repos if repository_owner(repo)}
        )
        values = ("All owners", *owners)
        self.owner_combo.configure(values=values)
        if self.owner_filter_var.get() not in values:
            self.owner_filter_var.set("All owners")

        self._apply_filters()
        self._log(
            f"Loaded {len(repos)} repositories visible to this token from {source_label} data."
        )
        self.progress_var.set(f"Loaded {len(repos)} repositories ({source_label})")

    def _update_rate_label(self, client: GitHubClient) -> None:
        reset = f", resets {client.last_rate_reset}" if client.last_rate_reset else ""
        self.rate_var.set(
            f"Rate limit: {client.last_rate_remaining}/{client.last_rate_limit}{reset}"
        )

    # ----- filters/tree ----------------------------------------------------

    def _schedule_filter(self, *_args: Any) -> None:
        if self.pending_filter_job:
            self.root.after_cancel(self.pending_filter_job)
        self.pending_filter_job = self.root.after(180, self._apply_filters)

    def _clear_filters(self) -> None:
        self.search_var.set("")
        self.search_scope_var.set("All fields")
        self.visibility_filter_var.set("All visibility")
        self.owner_filter_var.set("All owners")
        self.admin_only_var.set(True)
        self.include_forks_var.set(True)
        self.include_archived_var.set(True)
        self._apply_filters()

    def _filtered_repositories(self) -> list[dict[str, Any]]:
        search = self.search_var.get().strip().lower()
        visibility_filter = self.visibility_filter_var.get()
        owner_filter = self.owner_filter_var.get()
        admin_only = self.admin_only_var.get()
        include_forks = self.include_forks_var.get()
        include_archived = self.include_archived_var.get()

        result = []
        for repo in self.repositories:
            full_name = str(repo.get("full_name", ""))
            name = str(repo.get("name", ""))
            description = str(repo.get("description") or "")
            owner = repository_owner(repo)
            visibility = repository_visibility(repo)
            admin = repository_has_admin_access(repo)

            search_text = {
                "Repository name": name,
                "Full name": full_name,
                "Owner": owner,
                "Description": description,
            }.get(
                self.search_scope_var.get(),
                f"{full_name} {name} {owner} {description}",
            )

            if search and search not in search_text.lower():
                continue
            if visibility_filter == "Public only" and visibility != "public":
                continue
            if visibility_filter == "Private only" and visibility != "private":
                continue
            if owner_filter != "All owners" and owner != owner_filter:
                continue
            if admin_only and not admin:
                continue
            if not include_forks and repo.get("fork"):
                continue
            if not include_archived and repo.get("archived"):
                continue
            result.append(repo)
        return result

    def _apply_filters(self) -> None:
        self.pending_filter_job = None
        highlighted_ids = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())

        filtered = self._filtered_repositories()
        public_count = 0
        private_count = 0
        admin_count = 0

        for repo in filtered:
            repo_id = str(repo.get("id"))
            visibility = repository_visibility(repo)
            admin = repository_has_admin_access(repo)
            if visibility == "public":
                public_count += 1
            else:
                private_count += 1
            if admin:
                admin_count += 1

            tag = visibility if admin else "noadmin"
            self.tree.insert(
                "",
                END,
                iid=repo_id,
                text="?" if repo_id in self.checked_repo_ids else "?",
                values=(
                    str(repo.get("name", "")),
                    visibility.upper(),
                    repository_owner(repo),
                    format_updated(str(repo.get("updated_at", ""))),
                    "Yes" if repo.get("fork") else "No",
                    "Yes" if repo.get("archived") else "No",
                    "Yes" if admin else "No",
                ),
                tags=(tag,),
            )
            if repo_id in highlighted_ids:
                self.tree.selection_set(repo_id)
                self.tree.focus(repo_id)

        self.summary_var.set(
            f"Showing {len(filtered)} of {len(self.repositories)}    "
            f"Public {public_count}    Private {private_count}    Admin {admin_count}"
        )
        self._update_selection_label()

    def _visible_repo_ids(self) -> set[str]:
        return {str(repo_id) for repo_id in self.tree.get_children()}

    def _update_selection_label(self) -> None:
        total = len(self.checked_repo_ids)
        visible = len(self.checked_repo_ids & self._visible_repo_ids())
        if total == visible:
            self.selection_var.set(f"{total} ticked")
        else:
            self.selection_var.set(f"{total} ticked  {visible} visible")

    def _refresh_checkmarks(self, repo_ids: Iterable[str] | None = None) -> None:
        targets = set(repo_ids) if repo_ids is not None else self._visible_repo_ids()
        visible_ids = self._visible_repo_ids()
        for repo_id in targets & visible_ids:
            self.tree.item(
                repo_id, text="?" if repo_id in self.checked_repo_ids else "?"
            )
        self._update_selection_label()

    def _toggle_repository_check(self, repo_id: str) -> None:
        if repo_id not in self.repo_by_id:
            return
        if repo_id in self.checked_repo_ids:
            self.checked_repo_ids.remove(repo_id)
        else:
            self.checked_repo_ids.add(repo_id)
        self._refresh_checkmarks((repo_id,))

    def _on_tree_click(self, event: Any) -> str | None:
        region = self.tree.identify_region(event.x, event.y)
        column = self.tree.identify_column(event.x)
        repo_id = self.tree.identify_row(event.y)
        if region == "tree" and column == "#0" and repo_id:
            self.tree.selection_set(repo_id)
            self.tree.focus(repo_id)
            self._toggle_repository_check(str(repo_id))
            return "break"
        return None

    def _toggle_focused_repository(self, _event: Any = None) -> str:
        repo_id = self.tree.focus()
        if repo_id:
            self._toggle_repository_check(str(repo_id))
        return "break"

    def _select_all_visible(self) -> None:
        visible_ids = self._visible_repo_ids()
        self.checked_repo_ids.update(visible_ids)
        self._refresh_checkmarks(visible_ids)

    def _clear_visible_selection(self) -> None:
        visible_ids = self._visible_repo_ids()
        self.checked_repo_ids.difference_update(visible_ids)
        self._refresh_checkmarks(visible_ids)

    def _clear_selection(self) -> None:
        self.checked_repo_ids.clear()
        self._refresh_checkmarks()

    def _selected_repositories(self) -> list[dict[str, Any]]:
        return [
            repo
            for repo in self.repositories
            if str(repo.get("id")) in self.checked_repo_ids
        ]

    def _open_selected_repository(self, event: Any = None) -> None:
        if event is not None:
            column = self.tree.identify_column(event.x)
            if column == "#0":
                return
            repo_id = self.tree.identify_row(event.y)
            if repo_id:
                self.tree.selection_set(repo_id)
                self.tree.focus(repo_id)

        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo(APP_NAME, "Click a repository row first.")
            return
        repo = self.repo_by_id.get(str(selection[0]))
        if repo and repo.get("html_url"):
            webbrowser.open(str(repo["html_url"]))

    # ----- snapshots -------------------------------------------------------

    def _create_snapshot(self, repos: Iterable[dict[str, Any]], reason: str) -> Path:
        items = []
        for repo in repos:
            visibility = repository_visibility(repo)
            items.append(
                {
                    "id": repo.get("id"),
                    "full_name": repo.get("full_name"),
                    "visibility": visibility,
                    "html_url": repo.get("html_url"),
                }
            )
        snapshot = {
            "app": APP_NAME,
            "app_version": APP_VERSION,
            "created_at": utc_now_iso(),
            "github_user": self.login,
            "reason": reason,
            "repositories": items,
        }
        path = (
            SNAPSHOT_DIR
            / f"visibility_snapshot_{local_timestamp()}_{time.time_ns() % 1_000_000:06d}.json"
        )
        atomic_write_json(path, snapshot)
        atomic_write_json(SNAPSHOT_DIR / "latest.json", snapshot)
        self.last_snapshot = path
        self._queue_log(f"Snapshot saved: {path}")
        return path

    def _restore_snapshot(self) -> None:
        if not self.client or not self.repositories:
            messagebox.showwarning(
                APP_NAME, "Connect to GitHub and load repositories first."
            )
            return
        initial = str(self.last_snapshot or (SNAPSHOT_DIR / "latest.json"))
        path_str = filedialog.askopenfilename(
            title="Choose visibility snapshot",
            initialdir=str(Path(initial).parent),
            filetypes=(("JSON snapshots", "*.json"), ("All files", "*.*")),
        )
        if not path_str:
            return
        path = Path(path_str)
        data = load_json(path, None)
        if not isinstance(data, dict) or not isinstance(data.get("repositories"), list):
            messagebox.showerror(
                APP_NAME, "The selected file is not a valid visibility snapshot."
            )
            return

        current_by_name = {
            str(repo.get("full_name")): repo for repo in self.repositories
        }
        targets: list[tuple[dict[str, Any], str]] = []
        unavailable: list[str] = []
        for item in data["repositories"]:
            if not isinstance(item, dict):
                continue
            full_name = str(item.get("full_name", ""))
            visibility = str(item.get("visibility", ""))
            repo = current_by_name.get(full_name)
            if repo and visibility in {"public", "private"}:
                targets.append((repo, visibility))
            elif full_name:
                unavailable.append(full_name)

        if not targets:
            messagebox.showwarning(
                APP_NAME,
                "None of the snapshot repositories are currently available to this token.",
            )
            return

        details = (
            f"Restore visibility for {len(targets)} repositories from:\n{path.name}?"
        )
        if unavailable:
            details += f"\n\n{len(unavailable)} repository/repositories are unavailable and will be skipped."
        if not messagebox.askyesno(
            "Restore visibility snapshot", details, icon="warning"
        ):
            return

        self._run_mixed_visibility_operation(
            targets, operation_name=f"Restore {path.name}"
        )

    # ----- visibility operations -----------------------------------------

    def _start_visibility_change(self, target: str) -> None:
        if not self.client or not self.repositories:
            messagebox.showwarning(
                APP_NAME, "Connect to GitHub and load repositories first."
            )
            return

        ticked = self._selected_repositories()
        if not ticked:
            messagebox.showwarning(APP_NAME, "Tick one or more repositories first.")
            return

        no_admin = [repo for repo in ticked if not repository_has_admin_access(repo)]
        eligible = [repo for repo in ticked if repository_has_admin_access(repo)]
        already_target = [
            repo for repo in eligible if repository_visibility(repo) == target
        ]
        targets = [repo for repo in eligible if repo not in already_target]

        if no_admin:
            self._log(
                f"Skipping {len(no_admin)} ticked repositories without admin access."
            )
        if already_target:
            self._log(f"Skipping {len(already_target)} repositories already {target}.")
        if not targets:
            messagebox.showinfo(
                APP_NAME, f"No ticked repository needs to be changed to {target}."
            )
            return

        self._log(
            f"Starting direct {target.upper()} action for {len(targets)} repository/repositories."
        )
        pairs = [(repo, target) for repo in targets]
        self._run_mixed_visibility_operation(pairs, operation_name=f"Set {target}")

    def _run_mixed_visibility_operation(
        self,
        targets: list[tuple[dict[str, Any], str]],
        *,
        operation_name: str,
    ) -> None:
        client = self.client
        if client is None:
            return
        dry_run = bool(self.dry_run_var.get())
        auto_snapshot = bool(self.auto_snapshot_var.get())

        def worker() -> None:
            success = 0
            failed = 0
            skipped = 0
            total = len(targets)
            try:
                self._queue_log("=" * 66)
                self._queue_log(
                    f"{operation_name} started for {total} repositories. Dry run: {dry_run}."
                )

                if not dry_run and targets:
                    first_repo = targets[0][0]
                    first_name = str(first_repo.get("full_name", ""))
                    first_visibility = repository_visibility(first_repo)
                    self._queue_progress(
                        2, f"Checking token write permission on {first_name}..."
                    )
                    self._queue_log(
                        f"CHECK {first_name}: verifying Administration write permission (no visibility change)."
                    )
                    try:
                        client.verify_update_access(first_name, first_visibility)
                    except GitHubPermissionError as exc:
                        failed = 1
                        skipped = max(total - 1, 0)
                        self._queue_log(
                            f"STOP  {first_name}: token lacks repository Administration write permission."
                        )
                        self._queue_log(str(exc).replace("\n", " | "))
                        self._queue_progress(
                            100,
                            "Stopped before making changes: token permission is insufficient",
                        )
                        self.ui_queue.put(("permission_error", str(exc)))
                        self.ui_queue.put(("rate", client))
                        return
                    self._queue_log(
                        f"PASS  {first_name}: token write permission confirmed."
                    )

                if not dry_run and auto_snapshot:
                    unique_repos = list(
                        {
                            str(repo.get("id")): repo for repo, _target in targets
                        }.values()
                    )
                    self._create_snapshot(unique_repos, operation_name)

                permission_failure: GitHubPermissionError | None = None
                for index, (repo, target) in enumerate(targets, start=1):
                    if self.cancel_event.is_set():
                        self._queue_log("Operation cancelled by user.")
                        skipped += total - index + 1
                        break

                    full_name = str(repo.get("full_name", ""))
                    current = repository_visibility(repo)
                    percent = ((index - 1) / max(total, 1)) * 100
                    self._queue_progress(percent, f"{index}/{total}: {full_name}")

                    if current == target:
                        skipped += 1
                        self._queue_log(f"SKIP  {full_name}: already {target}.")
                        continue

                    if dry_run:
                        success += 1
                        self._queue_log(f"DRY   {full_name}: {current}  {target}")
                        continue

                    try:
                        updated = client.set_visibility(full_name, target)
                        success += 1
                        self._queue_log(f"OK    {full_name}: {current}  {target}")
                        self.ui_queue.put(
                            ("repo_updated", (full_name, target, updated))
                        )
                    except GitHubPermissionError as exc:
                        failed += 1
                        skipped += total - index
                        permission_failure = exc
                        self._queue_log(
                            f"STOP  {full_name}: token cannot update this repository; remaining repositories were not attempted."
                        )
                        break
                    except Exception as exc:
                        failed += 1
                        self._queue_log(f"FAIL  {full_name}: {exc}")

                    # A small pause reduces the chance of GitHub secondary-rate-limit responses.
                    time.sleep(0.18)

                self._queue_progress(
                    100,
                    f"Finished: {success} successful, {failed} failed, {skipped} skipped",
                )
                self._queue_log(
                    f"{operation_name} finished. Successful: {success}; failed: {failed}; skipped: {skipped}."
                )
                self.ui_queue.put(("rate", client))

                if permission_failure is not None:
                    self.ui_queue.put(("permission_error", str(permission_failure)))
                elif failed:
                    self.ui_queue.put(
                        (
                            "warning",
                            (
                                "Operation completed with errors",
                                f"Successful: {success}\nFailed: {failed}\nSkipped: {skipped}\n\nReview the activity log for details.",
                            ),
                        )
                    )
                else:
                    mode = (
                        "Preview complete" if dry_run else "Visibility change complete"
                    )
                    self.ui_queue.put(
                        (
                            "info",
                            (
                                mode,
                                f"Successful: {success}\nFailed: {failed}\nSkipped: {skipped}",
                            ),
                        )
                    )
            except Exception as exc:
                self._queue_log(f"ERROR: {exc}")
                self.ui_queue.put(("error", ("Operation failed", str(exc))))
            finally:
                self.ui_queue.put(("finished", None))

        self._start_worker(worker)

    def _apply_repo_update(
        self, full_name: str, visibility: str, updated_data: dict[str, Any]
    ) -> None:
        for index, repo in enumerate(self.repositories):
            if str(repo.get("full_name")) == full_name:
                merged = dict(repo)
                merged.update(updated_data)
                merged["visibility"] = visibility
                merged["private"] = visibility == "private"
                self.repositories[index] = merged
                if merged.get("id") is not None:
                    self.repo_by_id[str(merged["id"])] = merged
                self.cache_dirty = True
                break

    # ----- logging/utilities ----------------------------------------------

    def _clear_repository_cache(self) -> None:
        if self.busy:
            messagebox.showwarning(
                APP_NAME, "Stop the current operation before clearing the cache."
            )
            return
        removed = clear_repository_cache(self.cache_dir)
        self._log(f"Cleared {removed} repository cache file(s) from {self.cache_dir}.")
        messagebox.showinfo(
            APP_NAME,
            f"Repository cache cleared.\n\nRemoved files: {removed}\n\n"
            "The next Connect & Load will fetch live data from GitHub.",
        )

    def _log(self, message: str) -> None:
        self._append_log(message)

    def _append_log(self, message: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
        self.log_lines.append(line)
        self.log_text.configure(state="normal")
        self.log_text.insert(END, line + "\n")
        self.log_text.see(END)
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_lines.clear()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", END)
        self.log_text.configure(state="disabled")

    def _export_log(self) -> None:
        if not self.log_lines:
            messagebox.showinfo(APP_NAME, "There is no log to export.")
            return
        default_name = f"github_visibility_log_{local_timestamp()}.txt"
        path_str = filedialog.asksaveasfilename(
            title="Export activity log",
            initialdir=str(LOG_DIR),
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
        )
        if not path_str:
            return
        try:
            Path(path_str).write_text(
                "\n".join(self.log_lines) + "\n", encoding="utf-8"
            )
            self._log(f"Log exported: {path_str}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not export the log:\n\n{exc}")

    def _open_folder(self, path: Path) -> None:
        ensure_app_dirs()
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                import subprocess

                subprocess.Popen(["open", str(path)])
            else:
                import subprocess

                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not open the folder:\n\n{exc}")

    def _show_about(self) -> None:
        messagebox.showinfo(
            f"About {APP_NAME}",
            f"{APP_NAME}\nVersion {APP_VERSION}\n\n"
            "Dependency-free Windows application using GitHub's REST API.\n"
            "Repository lists may be cached for up to 30 minutes for faster reopening.\n"
            "Caches are tied to the token, user, app version, and cache schema.\n"
            "Refresh from GitHub always bypasses the cache.\n"
            "Saved tokens are encrypted with Windows DPAPI for the current Windows user.\n\n"
            f"Application data:\n{APP_DIR}\n\nCache folder:\n{self.cache_dir}",
        )

    def _install_exception_handler(self) -> None:
        def handle(exc_type: Any, exc_value: BaseException, exc_tb: Any) -> None:
            details = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
            try:
                crash_file = LOG_DIR / f"crash_{local_timestamp()}.txt"
                crash_file.write_text(details, encoding="utf-8")
            except OSError:
                crash_file = None
            message = f"Unexpected error:\n\n{exc_value}"
            if crash_file:
                message += f"\n\nA crash report was saved to:\n{crash_file}"
            messagebox.showerror(APP_NAME, message)

        self.root.report_callback_exception = handle

    def _on_close(self) -> None:
        if self.busy:
            close = messagebox.askyesno(
                APP_NAME,
                "An operation is running. Request cancellation and close the app?",
                icon="warning",
            )
            if not close:
                return
            self.cancel_event.set()
        with suppress(Exception):
            self._save_settings(self.token_var.get().strip())
        self.root.destroy()


def main() -> None:
    root = Tk()
    RepoVisibilityApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

