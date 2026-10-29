"""Build APAC Cyber Insight.

Pulls the latest Cyber Threat Brief and APAC Cyber Policy Tracker editions,
adds industry and customer news, scores each country, and writes
docs/data.json plus a small daily history file. The page in docs/index.html
renders everything from data.json.

Run:  python build.py
"""

from __future__ import annotations

import html
import json
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import yaml

ROOT = Path(__file__).parent
DOCS = ROOT / "docs"
HISTORY = DOCS / "history"
MYT = timezone(timedelta(hours=8))
UA = "apac-cyber-insight/1.0 (+https://github.com/djrufio21/apac-cyber-insight)"

failed: list[str] = []


# ---------- helpers ----------

def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def parse_time(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def clean(text: str, limit: int = 260) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = html.unescape(re.sub(r"\s+", " ", text)).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def google_news(query: str, days: int) -> str:
    q = urllib.parse.quote_plus(f"{query} when:{days}d")
    return f"https://news.google.com/rss/search?q={q}&hl=en-SG&gl=SG&ceid=SG:en"


def read_feed(name: str, url: str, hours_back: int) -> list[dict]:
    feed = feedparser.parse(url, agent=UA)
    if feed.bozo and not feed.entries:
        failed.append(name)
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    out = []
    for e in feed.entries:
        t = e.get("published_parsed") or e.get("updated_parsed")
        published = datetime(*t[:6], tzinfo=timezone.utc) if t else None
        if published and published < cutoff:
            continue
        title = clean(e.get("title", ""), 300)
        source = (e.get("source") or {}).get("title") or name
        # Google News appends " - Source" to every headline
        if source and title.endswith(f" - {source}"):
            title = title[: -len(source) - 3]
        out.append({
            "title": title,
            "link": e.get("link", ""),
            "source": source,
            "published": published.isoformat() if published else None,
            "summary": "" if "news.google.com" in url else clean(e.get("summary", "")),
        })
    return out


def dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for it in items:
        key = re.sub(r"[^a-z0-9]", "", it["title"].lower())[:80]
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def newest_first(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda s: s.get("published") or "", reverse=True)


# ---------- build ----------

def main() -> int:
    cfg = yaml.safe_load((ROOT / "sources.yml").read_text(encoding="utf-8"))
    st = cfg["settings"]
    now = datetime.now(timezone.utc)
    today = now.astimezone(MYT).date()

    countries = cfg["countries"]
    by_name = {c["name"].lower(): c["code"] for c in countries}
    patterns = {c["code"]: re.compile(c["match"], re.I) for c in countries}
    cyber_re = re.compile(cfg["cyber_terms"], re.I)
    apac_re = re.compile(cfg["apac_terms"], re.I)

    def tag_countries(text: str, named: list[str] | None = None) -> list[str]:
        codes = {by_name[n.lower()] for n in (named or []) if n.lower() in by_name}
        codes |= {code for code, rx in patterns.items() if rx.search(text)}
        return sorted(codes)

    lenses: dict[str, dict] = {}

    # Threat lens: from cyber-threat-brief
    threat_raw = {}
    try:
        threat_raw = fetch_json(cfg["upstream"]["threat"])
    except Exception as exc:  # noqa: BLE001
        failed.append(f"Cyber Threat Brief ({exc.__class__.__name__})")
    threat_sections = []
    for sec in threat_raw.get("sections", []):
        stories = []
        for s in sec.get("stories", []):
            text = f"{s.get('title','')} {s.get('subtitle','')} {s.get('summary','')}"
            stories.append({
                "title": s.get("title", ""),
                "link": s.get("link", ""),
                "source": s.get("source", ""),
                "published": s.get("published"),
                "summary": clean(s.get("subtitle") or s.get("summary", "")),
                "extra": s.get("extra", ""),
                "tags": s.get("tags", []),
                "countries": tag_countries(text),
            })
        threat_sections.append({"name": sec["name"], "stories": stories})
    lenses["threat"] = {"sections": threat_sections, "site": cfg["upstream"]["threat_site"]}

    # Compliance lens: from apac-cyber-policy-tracker
    policy_raw = {}
    try:
        policy_raw = fetch_json(cfg["upstream"]["policy"])
    except Exception as exc:  # noqa: BLE001
        failed.append(f"APAC Cyber Policy Tracker ({exc.__class__.__name__})")
    policy_sections = []
    for sec in policy_raw.get("sections", []):
        stories = []
        for s in sec.get("stories", []):
            stories.append({
                "title": s.get("title", ""),
                "link": s.get("link", ""),
                "source": s.get("source", ""),
                "published": s.get("published"),
                "summary": clean(s.get("summary", "")),
                "tags": s.get("tags", []),
                "closes": s.get("closes"),
                "countries": tag_countries(s.get("title", ""), s.get("countries")),
            })
        policy_sections.append({"name": sec["name"], "stories": stories})
    lenses["compliance"] = {
        "sections": policy_sections,
        "closing_soon": policy_raw.get("closing_soon", []),
        "site": cfg["upstream"]["policy_site"],
    }

    # Industry lens: one Google News search per sector
    ind = cfg["industry"]
    days = max(1, ind["hours_back"] // 24)
    industry_sections = []
    for sector in ind["sectors"]:
        items = read_feed(f"Industry: {sector['name']}", google_news(sector["query"], days), ind["hours_back"])
        items = [i for i in items if cyber_re.search(i["title"]) and apac_re.search(i["title"])]
        items = newest_first(dedupe(items))[: ind["max_items"]]
        for i in items:
            i["tags"] = [sector["name"]]
            i["countries"] = tag_countries(i["title"])
        industry_sections.append({"name": sector["name"], "stories": items})
    lenses["industry"] = {"sections": industry_sections}

    # Customer lens: watchlist names, searched in batches of six
    cus = cfg["customer"]
    days = max(1, cus["hours_back"] // 24)
    watch = cus["watchlist"]
    found: list[dict] = []
    for start in range(0, len(watch), 6):
        batch = watch[start:start + 6]
        names = " OR ".join(f'"{w["name"]}"' for w in batch)
        query = f"({names}) (cybersecurity OR cyber OR breach OR outage OR hack OR scam OR data OR security)"
        found += read_feed(f"Customer watchlist {start // 6 + 1}", google_news(query, days), cus["hours_back"])
    by_account: dict[str, list[dict]] = {}
    for item in newest_first(dedupe(found)):
        if not cyber_re.search(item["title"]):
            continue
        for w in watch:
            short = w["name"].split()[0] if w["name"] in ("AIS Thailand", "True Corporation") else w["name"]
            if re.search(rf"\b{re.escape(short)}\b", item["title"], re.I):
                item = dict(item, tags=[w["name"]], countries=sorted(set(tag_countries(item["title"])) | {w["country"]}))
                by_account.setdefault(w["name"], []).append(item)
                break
    customer_stories = newest_first([i for v in by_account.values() for i in v])[: cus["max_items"]]
    lenses["customer"] = {
        "sections": [{"name": "Watchlist", "stories": customer_stories}],
        "watchlist": [{"name": w["name"], "country": w["country"], "hits": len(by_account.get(w["name"], []))} for w in watch],
    }

    # ---------- history and country index ----------

    HISTORY.mkdir(parents=True, exist_ok=True)
    kev = next((s for s in threat_sections if s["name"].lower().startswith("actively")), {"stories": []})
    today_items = [
        {"lens": lens, "link": s["link"], "countries": s["countries"]}
        for lens, data in lenses.items()
        for sec in data["sections"]
        for s in sec["stories"]
        if s["countries"] and s["link"]
    ]
    today_record = {
        "date": today.isoformat(),
        "kev": len(kev["stories"]),
        "closing": len(lenses["compliance"]["closing_soon"]),
        "items": today_items,
    }
    (HISTORY / f"{today}.json").write_text(json.dumps(today_record, separators=(",", ":")), encoding="utf-8")

    def load_day(d):
        p = HISTORY / f"{d}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    window = st["window_days"]

    def window_items(end):
        seen, items, days_found = set(), [], 0
        for n in range(window):
            rec = load_day(end - timedelta(days=n))
            if not rec:
                continue
            days_found += 1
            for it in rec["items"]:
                key = (it["lens"], it["link"])
                if key not in seen:
                    seen.add(key)
                    items.append(it)
        return items, days_found

    weights = cfg["index_weights"]

    def score(items):
        counts = {c["code"]: {k: 0 for k in weights} for c in countries}
        for it in items:
            for code in it["countries"]:
                if code in counts and it["lens"] in weights:
                    counts[code][it["lens"]] += 1
        peak = {k: max(1, max(c[k] for c in counts.values())) for k in weights}
        scores = {code: round(100 * sum(weights[k] * c[k] / peak[k] for k in weights)) for code, c in counts.items()}
        return counts, scores

    cur_items, days_found = window_items(today)
    prev_items, prev_days = window_items(today - timedelta(days=window))
    counts, scores = score(cur_items)
    _, prev_scores = score(prev_items) if prev_days else ({}, {})

    def band(v):
        return "High" if v >= 75 else "Elevated" if v >= 50 else "Active" if v >= 25 else "Quiet"

    country_rows = []
    for c in countries:
        code = c["code"]
        row = {"code": code, "name": c["name"], "score": scores[code], "band": band(scores[code]), **counts[code]}
        row["total"] = sum(counts[code].values())
        row["delta"] = scores[code] - prev_scores[code] if prev_days else None
        country_rows.append(row)
    country_rows.sort(key=lambda r: (-r["score"], r["name"]))

    # ---------- headline numbers ----------

    def lens_count(items, lens):
        return sum(1 for i in items if i["lens"] == lens)

    yesterday = load_day(today - timedelta(days=1))
    kpis = [
        {"label": "Policy and regulatory updates", "value": lens_count(cur_items, "compliance"),
         "delta": lens_count(cur_items, "compliance") - lens_count(prev_items, "compliance") if prev_days else None,
         "note": f"last {window} days"},
        {"label": "Actively exploited vulnerabilities", "value": today_record["kev"],
         "delta": today_record["kev"] - yesterday["kev"] if yesterday else None, "note": "added to CISA KEV, 7 days"},
        {"label": "APAC threat stories", "value": lens_count(cur_items, "threat"),
         "delta": lens_count(cur_items, "threat") - lens_count(prev_items, "threat") if prev_days else None,
         "note": f"naming an APAC country, last {window} days"},
        {"label": "Consultations closing soon", "value": today_record["closing"], "delta": None,
         "note": "open for comment"},
    ]

    # ---------- top stories: a mix across the four lenses ----------

    def pool(lens, prefer=None):
        secs = lenses[lens]["sections"]
        if prefer:
            secs = sorted(secs, key=lambda s: s["name"] != prefer)
        out = []
        for sec in secs:
            for s in sec["stories"]:
                if s["countries"]:
                    out.append(dict(s, lens=lens, section=sec["name"]))
        return out

    plan = [("threat", 2, "APAC Watch"), ("compliance", 2, None), ("industry", 1, None), ("customer", 1, None)]
    top, used = [], set()
    for lens, n, prefer in plan:
        for s in pool(lens, prefer)[:n]:
            top.append(s)
            used.add(s["link"])
    for lens, _, prefer in plan:  # fill any gaps
        for s in pool(lens, prefer):
            if len(top) >= 6:
                break
            if s["link"] not in used:
                top.append(s)
                used.add(s["link"])

    # ---------- write ----------

    iso = today.isocalendar()
    data = {
        "generated": now.isoformat(timespec="seconds"),
        "date": today.isoformat(),
        "weekday": today.strftime("%A"),
        "week": iso.week,
        "title": st["title"],
        "tagline": st["tagline"],
        "window_days": window,
        "history_days": days_found,
        "weights": weights,
        "kpis": kpis,
        "countries": country_rows,
        "top": top[:6],
        "lenses": lenses,
        "failed": failed,
    }
    (DOCS / "data.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")

    # prune old history
    cutoff = today - timedelta(days=st["keep_days"])
    for p in HISTORY.glob("*.json"):
        try:
            if datetime.fromisoformat(p.stem).date() < cutoff:
                p.unlink()
        except ValueError:
            pass

    total = sum(len(s["stories"]) for d in lenses.values() for s in d["sections"])
    print(f"Built {today}: {total} stories, {len(top)} top stories, failed: {failed or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
