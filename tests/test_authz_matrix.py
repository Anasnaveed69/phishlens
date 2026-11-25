"""Authorization matrix: every protected API route x every role.

The expected result is derived from the route's declared permission and the PERMISSIONS table
(app/security/deps.py), which is the same table the README documents. A route that a role lacks the
permission for must answer 403 FORBIDDEN *before* touching its body; a route the role may use must
never answer 401/403. A new route without a permission dependency fails test_every_api_route_is_protected.
"""
from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

from app.main import app
from app.security.deps import PERMISSIONS

from .conftest import login

PUBLIC = {("POST", "/api/auth/login"), ("GET", "/api/health")}
SESSION_ONLY = {("POST", "/api/auth/logout"), ("GET", "/api/auth/me"), ("POST", "/api/auth/password")}
DUMMY_ID = "00000000-0000-0000-0000-000000000000"


def _permission_of(route: APIRoute) -> str | None:
    for dep in route.dependant.dependencies:
        fn = dep.call
        if fn.__name__ == "_dep" and fn.__closure__:
            for cell in fn.__closure__:
                if isinstance(cell.cell_contents, str):
                    return cell.cell_contents
    return None


def _api_routes(routes):
    """Flatten app routes; newer FastAPI versions wrap included routers lazily."""
    for r in routes:
        if isinstance(r, APIRoute):
            yield r
        elif hasattr(r, "original_router"):
            yield from _api_routes(r.original_router.routes)


ROUTES = sorted({(m, r.path, _permission_of(r)) for r in _api_routes(app.routes)
                 if r.path.startswith("/api/") for m in r.methods})
assert len(ROUTES) >= 20, f"route discovery found only {len(ROUTES)} routes"


def test_every_api_route_is_protected():
    unprotected = [(m, p) for m, p, perm in ROUTES if perm is None and (m, p) not in PUBLIC | SESSION_ONLY]
    assert not unprotected, f"routes without a permission check: {unprotected}"


def test_documented_role_table_matches_code():
    """README 'Roles' table: viewer < analyst < admin, admin-only = config/users/audit/model."""
    assert PERMISSIONS["viewer"] < PERMISSIONS["analyst"] < PERMISSIONS["admin"]
    assert PERMISSIONS["admin"] - PERMISSIONS["analyst"] == {"config:read", "config:write", "user:manage", "audit:read"}
    assert PERMISSIONS["viewer"] == {"result:read"}


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
@pytest.mark.parametrize("method,path,perm", [r for r in ROUTES if r[2]], ids=lambda v: str(v))
def test_role_matrix(client, role, method, path, perm):
    headers = login(client, role)
    url = path.replace("{sample_id}", DUMMY_ID).replace("{analysis_id}", DUMMY_ID).replace("{user_id}", DUMMY_ID)
    r = client.request(method, url, headers=headers, json={} if method in {"PUT", "PATCH", "POST"} else None)
    if perm in PERMISSIONS[role]:
        assert r.status_code not in (401, 403), f"{role} should be allowed {method} {path}: {r.status_code} {r.text}"
    else:
        assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN", \
            f"{role} must be denied {method} {path}, got {r.status_code}"


@pytest.mark.parametrize("method,path,perm", [r for r in ROUTES if r[2]], ids=lambda v: str(v))
def test_anonymous_is_rejected_everywhere(client, method, path, perm):
    client.cookies.clear()
    url = path.replace("{sample_id}", DUMMY_ID).replace("{analysis_id}", DUMMY_ID).replace("{user_id}", DUMMY_ID)
    r = client.request(method, url)
    assert r.status_code == 401 and r.json()["error"]["code"] == "AUTH_REQUIRED"


@pytest.mark.parametrize("method,path,perm", [r for r in ROUTES if r[0] in {"POST", "PUT", "PATCH", "DELETE"}
                                              and (r[2] or (r[0], r[1]) in SESSION_ONLY)], ids=lambda v: str(v))
def test_csrf_required_on_every_state_changing_route(client, method, path, perm):
    login(client, "admin")  # logged in, but no X-CSRF-Token header
    url = path.replace("{sample_id}", DUMMY_ID).replace("{analysis_id}", DUMMY_ID).replace("{user_id}", DUMMY_ID)
    r = client.request(method, url, json={})
    assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"
