"""Safe, configuration-driven HTTP integration engine for IntegrateX.

Supports auth, endpoint-specific headers and JSON bodies, query parameters,
bounded pagination, explicit response paths, and SSRF checks.
"""
import ipaddress
import socket
from urllib.parse import urlparse, urljoin
from typing import Any

import httpx
from app.config import settings


class IntegrationError(Exception):
    pass


def validate_config(config: dict) -> list[str]:
    errors = []
    for field in ("name", "base_url", "auth", "endpoints", "schedule", "mapping"):
        if field not in config:
            errors.append(f"Missing required field: {field}")
    auth = config.get("auth", {})
    if not isinstance(auth, dict):
        errors.append("auth must be an object")
    else:
        typ = auth.get("type", "none")
        if typ not in {"none", "api_key", "bearer", "basic", "oauth2_client_credentials"}:
            errors.append("Unsupported auth.type")
        if typ == "bearer" and not auth.get("token"):
            errors.append("auth.token is required for bearer authentication")
        if typ == "api_key" and not auth.get("key"):
            errors.append("auth.key is required for API key authentication")
        if typ == "basic" and (not auth.get("username") or not auth.get("password")):
            errors.append("auth.username and auth.password are required for basic authentication")
    endpoints = config.get("endpoints", [])
    if not isinstance(endpoints, list) or not endpoints:
        errors.append("endpoints must be a non-empty list")
    for i, ep in enumerate(endpoints if isinstance(endpoints, list) else []):
        if not isinstance(ep, dict) or not ep.get("path"):
            errors.append(f"endpoints[{i}] must include a path")
            continue
        if str(ep.get("method", "GET")).upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            errors.append(f"endpoints[{i}].method is unsupported")
        pagination = ep.get("pagination") or {"type": "none"}
        if not isinstance(pagination, dict) or pagination.get("type", "none") not in {"none", "page", "offset", "cursor", "next_link"}:
            errors.append(f"endpoints[{i}].pagination.type is unsupported")
        if ep.get("headers") is not None and not isinstance(ep.get("headers"), dict):
            errors.append(f"endpoints[{i}].headers must be a JSON object")
        if ep.get("body") is not None and not isinstance(ep.get("body"), (dict, list)):
            errors.append(f"endpoints[{i}].body must be a JSON object or array")
    base = config.get("base_url")
    if base:
        try:
            parsed = urlparse(base)
            if parsed.scheme != "https" and not (settings.app_env == "development" and parsed.scheme == "http"):
                errors.append("base_url must use HTTPS (HTTP is allowed only in development)")
            if not parsed.hostname:
                errors.append("base_url must be a valid absolute URL")
            if parsed.username or parsed.password:
                errors.append("Do not put credentials in base_url")
        except Exception:
            errors.append("base_url is invalid")
    return errors


def _check_target(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise IntegrationError("Only absolute HTTP/HTTPS URLs are supported")
    if settings.allow_private_targets:
        return
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise IntegrationError("Target resolves to a private, loopback or reserved IP; blocked by SSRF protection")
    except socket.gaierror:
        raise IntegrationError("Hostname could not be resolved")


def build_headers(auth: dict):
    typ = auth.get("type", "none")
    headers = {}
    if typ == "bearer":
        headers["Authorization"] = f"Bearer {auth.get('token', '')}"
    elif typ == "api_key":
        header_name = auth.get("header", "X-API-Key")
        key = auth.get("key", "")
        if header_name.lower() == "authorization" and not key.startswith("ApiKey "):
            key = f"ApiKey {key}"
        headers[header_name] = key
    elif typ == "oauth2_client_credentials":
        token = auth.get("access_token")
        if not token:
            raise IntegrationError("OAuth2 client credentials require an access_token; token acquisition must be configured for this vendor")
        headers["Authorization"] = f"Bearer {token}"
    elif typ == "basic":
        pass
    # Explicit auth headers are supported for vendor-specific schemes.
    headers.update(auth.get("headers", {}))
    return headers



async def request_endpoint(
    base_url: str,
    endpoint: dict,
    auth: dict,
    timeout: float = 30,
    params_override: dict | None = None
):
    url = base_url.rstrip("/") + "/" + endpoint.get("path", "").lstrip("/")
    _check_target(url)

    headers = build_headers(auth)

    # Add endpoint-specific headers
    headers.update(endpoint.get("headers") or {})

    params = dict(endpoint.get("params", {}))
    params.update(params_override or {})

    request_body = endpoint.get("body")

    request_options = {
        "headers": headers,
        "timeout": timeout,
        "follow_redirects": False
    }

    # Basic authentication
    if auth.get("type") == "basic":
        request_options["auth"] = (
            auth.get("username", ""),
            auth.get("password", "")
        )

    if params:
        request_options["params"] = params

    try:
        async with httpx.AsyncClient(**request_options) as client:
            response = await client.request(
                method=endpoint.get("method", "GET").upper(),
                url=url,
                json=request_body
            )

    except httpx.TimeoutException:
        return {
            "ok": False,
            "http_status": None,
            "message": "Vendor API request timed out",
            "url": url,
            "body": "",
            "headers": {}
        }

    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "http_status": None,
            "message": f"HTTP client error: {type(exc).__name__}",
            "url": url,
            "body": "",
            "headers": {}
        }

    return {
        "ok": response.is_success,
        "http_status": response.status_code,
        "message": (
            "Connection successful"
            if response.is_success
            else f"Vendor API returned HTTP {response.status_code}: {response.text[:500]}"
        ),
        "url": str(response.url),
        "body": response.text[:100000],
        "headers": dict(response.headers)
    }

def extract_items(payload: Any, response_path: str | None = None):
    value = payload
    if response_path:
        for part in response_path.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = None
                break
    elif isinstance(value, dict):
        for key in ("data", "results", "items", "alerts", "events", "findings"):
            if isinstance(value.get(key), list):
                value = value[key]
                break
    if isinstance(value, dict):
        return [value]
    return value if isinstance(value, list) else []


async def fetch_all(base_url: str, endpoint: dict, auth: dict, checkpoint: str | None = None, max_pages: int = 20):
    """Fetch bounded pages. Pagination settings are explicit; no guessed vendor paths."""
    pagination = endpoint.get("pagination", {"type": "none"}) or {"type": "none"}
    typ = pagination.get("type", "none")
    page_size = int(pagination.get("page_size", 100))
    page = int(pagination.get("start_page", 1))
    offset = int(pagination.get("start_offset", 0))
    cursor = checkpoint
    collected, last_checkpoint, pages, status = [], checkpoint, 0, None
    for _ in range(max_pages):
        override = {}
        if typ == "page":
            override[pagination.get("page_param", "page")] = page
            override[pagination.get("page_size_param", "page_size")] = page_size
        elif typ == "offset":
            override[pagination.get("offset_param", "offset")] = offset
            override[pagination.get("limit_param", "limit")] = page_size
        elif typ == "cursor" and cursor:
            override[pagination.get("cursor_param", "cursor")] = cursor
        inc = endpoint.get("incremental") or {}
        if checkpoint and inc.get("param"):
            override[inc["param"]] = checkpoint
        result = await request_endpoint(base_url, endpoint, auth, params_override=override)
        status = result["http_status"]
        if not result["ok"]:
            raise IntegrationError(result["message"])
        import json
        try:
            payload = json.loads(result["body"]) if result["body"] else []
        except ValueError:
            raise IntegrationError("Vendor response was not valid JSON")
        items = extract_items(payload, endpoint.get("response_path"))
        collected.extend(items)
        pages += 1
        if typ == "page":
            has_more = payload.get(pagination.get("has_more_path", "has_more"), False) if isinstance(payload, dict) else len(items) >= page_size
            if has_more is False or (not has_more and len(items) < page_size):
                break
            page += 1
        elif typ == "offset":
            if len(items) < page_size:
                break
            offset += len(items)
        elif typ == "cursor":
            next_value = payload
            for part in pagination.get("next_cursor_path", "next_cursor").split("."):
                next_value = next_value.get(part) if isinstance(next_value, dict) else None
            if not next_value:
                break
            cursor = str(next_value)
            last_checkpoint = cursor
        elif typ == "next_link":
            link = payload
            for part in pagination.get("next_link_path", "next").split("."):
                link = link.get(part) if isinstance(link, dict) else None
            if not link:
                break
            candidate = urljoin(base_url.rstrip("/") + "/", str(link))
            a, b = urlparse(candidate), urlparse(base_url)
            if (a.scheme, a.hostname, a.port) != (b.scheme, b.hostname, b.port):
                raise IntegrationError("Pagination next link changed origin; blocked")
            endpoint = dict(endpoint)
            endpoint["path"] = candidate[len(base_url.rstrip("/")):].lstrip("/")
        else:
            break
    else:
        if typ != "none":
            raise IntegrationError(f"Pagination exceeded max_pages={max_pages}; increase the configured limit if appropriate")
    return {"items": collected, "pages": pages, "http_status": status, "checkpoint": last_checkpoint}
