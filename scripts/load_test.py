"""Load / concurrency test against a running server (not part of pytest; run manually).

    PHISHLENS_ANALYZE_RATE=100000 PHISHLENS_LOGIN_RATE=1000 uvicorn app.main:app --port 8000
    python scripts/load_test.py --base http://127.0.0.1:8000 --user analyst --password ... --admin-password ...

Simulates N concurrent analysts (upload+analyze, history, detail, export) for D seconds, then verifies
the audit chain as admin. Prints throughput, latency percentiles and error counts.
"""
from __future__ import annotations

import argparse
import random
import statistics
import threading
import time
from collections import Counter
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
PAGES = list((ROOT / "fixtures" / "tests").glob("*.html"))


def session(base: str, user: str, pw: str) -> tuple[httpx.Client, dict]:
    c = httpx.Client(base_url=base, timeout=30)
    r = c.post("/api/auth/login", json={"username": user, "password": pw})
    r.raise_for_status()
    return c, {"X-CSRF-Token": r.json()["csrf_token"]}


def worker(base, user, pw, until, lat, codes, lock, seed):
    rnd = random.Random(seed)
    c, h = session(base, user, pw)
    ids = []
    while time.time() < until:
        op = rnd.choices(["analyze", "list", "detail", "export"], [3, 3, 3, 1])[0]
        t0 = time.perf_counter()
        if op == "analyze":
            page = rnd.choice(PAGES)
            # unique bytes so every upload is a real new analysis, not only a duplicate hit
            body = page.read_bytes() + f"<!-- {seed}-{time.time_ns()} -->".encode()
            r = c.post("/api/samples", headers=h, files={"file": (page.name, body, "text/html")},
                       data={"source_url": "https://load.example.com/login"})
            if r.status_code == 200:
                ids.append(r.json()["analysis"]["id"])
        elif op == "list":
            r = c.get("/api/analyses", params={"limit": 50})
        elif op == "detail" and ids:
            r = c.get(f"/api/analyses/{rnd.choice(ids)}")
        elif op == "export" and ids:
            r = c.get(f"/api/analyses/{rnd.choice(ids)}/export", params={"format": "json"})
        else:
            continue
        dt = (time.perf_counter() - t0) * 1000
        with lock:
            lat.setdefault(op, []).append(dt)
            codes[(op, r.status_code)] += 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--user", default="analyst")
    ap.add_argument("--password", required=True)
    ap.add_argument("--admin-password", required=True)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--seconds", type=int, default=30)
    a = ap.parse_args()
    lat: dict[str, list[float]] = {}
    codes: Counter = Counter()
    lock = threading.Lock()
    until = time.time() + a.seconds
    ts = [threading.Thread(target=worker, args=(a.base, a.user, a.password, until, lat, codes, lock, i))
          for i in range(a.workers)]
    t0 = time.time()
    [t.start() for t in ts]
    [t.join() for t in ts]
    wall = time.time() - t0
    total = sum(codes.values())
    print(f"{a.workers} concurrent users, {wall:.1f} s, {total} requests, {total / wall:.1f} req/s")
    for op, xs in sorted(lat.items()):
        xs.sort()
        print(f"  {op:8s} n={len(xs):5d}  median={statistics.median(xs):7.1f} ms  p95={xs[int(.95 * (len(xs) - 1))]:7.1f} ms  max={xs[-1]:7.1f} ms")
    print("  status codes:", dict(sorted(codes.items())))
    c, _ = session(a.base, "admin", a.admin_password)
    print("  audit chain after load:", c.get("/api/admin/audit/verify").json())


if __name__ == "__main__":
    main()
