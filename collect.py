"""AI Breakpoint Report - daily collector.

Reads every advisory GitHub added to its Advisory Database on one day (no
100-item API limit: it reads the database's own Git repository), keeps the ones
rated CVSS 8.0+, flags the likely AI ones and removes duplicates. Writes
daily/<date>.json for the Make scenario to pick up.

Usage: python collect.py --db <advisory-database checkout> [--date YYYY-MM-DD]
"""
import argparse, csv, datetime as dt, glob, json, os, re, sys, urllib.request

from cvss import CVSS3, CVSS4

HERE = os.path.dirname(os.path.abspath(__file__))

BRAND = re.compile(r"(Copilot|Gemini|Vertex AI|Bedrock|SageMaker|Amazon Q\b|Azure (AI|Machine Learning|OpenAI)|"
    r"Triton Inference|TensorRT|\bNeMo\b|\bNIM\b|AIStore|ChatGPT|OpenAI|Anthropic|\bClaude\b|\bGrok\b|\bxAI\b|"
    r"\bLlama\b|Mistral|DeepSeek|Agentforce|Einstein|Now Assist|watsonx|\bJoule\b|SAP AI Core|Generative AI Hub|"
    r"Cortex AI|Mosaic AI|Databricks|Hugging ?Face|\bCursor\b|Charlotte AI|Prisma AIRS|Auth0 for AI|"
    r"OCI Generative AI)")
GENERIC = re.compile(r"(\bLLMs?\b|language model|prompt injection|\bAI[- ]agents?\b|\bagentic\b|Model Context Protocol|"
    r"\bMCP\b|machine learning|\bML model|inference (server|engine|process)|generative AI|\bGenAI\b|\bchatbot|"
    r"\bembedding|vector (store|database)|\bRAG\b|text[- ]to[- ](image|speech|SQL)|neural|\bGPT\b|diffusion model|"
    r"deep learning|\bAI\b)", re.I)
STOP = {"cursor", "transformers", "feast", "keras", "onnx", "ray", "agno", "cline", "engram", "knowns", "grackle",
        "praktor", "aegra", "kozou", "boxlite", "omnigent", "network-ai", "mcp sdks", "langchain", "hermes", "obot",
        "verba", "dspy", "instructor", "guidance", "outlines", "autogen", "memory", "chroma", "server", "camel",
        "adapters", "memos", "inspector", "feishu", "headroom", "new api"}
CLASSIC = {"CWE-22", "CWE-78", "CWE-77", "CWE-94", "CWE-95", "CWE-502", "CWE-306", "CWE-862", "CWE-918", "CWE-89",
           "CWE-287", "CWE-863", "CWE-79"}


def load_registry():
    reg = list(csv.DictReader(open(os.path.join(HERE, "registry.csv"), encoding="utf-8")))
    names, pkgs, repos = {}, {}, {}
    for r in reg:
        base = re.sub(r"\s*\(.*\)", "", r["product"]).strip()
        if len(base) >= 4 and base.lower() not in STOP:
            names[base.lower()] = r
        for p in (r.get("packages") or "").split(";"):
            p = p.strip().lower()
            if p:
                pkgs[p] = r
                short = p.split("/")[-1]
                if len(short) >= 5 and short not in STOP:
                    names.setdefault(short, r)
        for al in (r.get("aliases") or "").split(";"):
            if al.strip():
                names[al.strip().lower()] = r
        for k in (r.get("repos") or "").split(";"):
            if k:
                repos[k.lower()] = r
    slugs = {re.sub(r"[^a-z0-9]", "", n): r for n, r in names.items() if len(re.sub(r"[^a-z0-9]", "", n)) >= 6}
    rx = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True)) + r")(?![\w-])", re.I)
    return names, pkgs, repos, rx, slugs


def score_of(d):
    v3 = v4 = None
    vec = ""
    for s in d.get("severity", []):
        try:
            if s["type"] == "CVSS_V4":
                v4 = float(CVSS4(s["score"]).base_score); vec = s["score"]
            elif s["type"] == "CVSS_V3":
                v3 = float(CVSS3(s["score"]).scores()[0]); vec = vec or s["score"]
        except Exception:
            pass
    if v4 is not None:
        return v4, "4.0", vec
    return v3, ("3.x" if v3 is not None else ""), vec


def gh_api(path):
    req = urllib.request.Request("https://api.github.com" + path, headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SPB-AI-Breakpoint"})
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", "Bearer " + tok)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except Exception as e:
        print("API call failed", path, e, file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--date", default=(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).strftime("%Y-%m-%d"))
    ap.add_argument("--out", default=os.path.join(HERE, "daily"))
    ap.add_argument("--no-api", action="store_true")
    a = ap.parse_args()
    day = dt.date.fromisoformat(a.date)
    names, pkgs, repos, name_rx, slugs = load_registry()

    # GitHub files advisories in year/month folders; scan the day's month and the one before.
    months = {(day.year, day.month), ((day.replace(day=1) - dt.timedelta(days=1)).year,
                                       (day.replace(day=1) - dt.timedelta(days=1)).month)}
    files = []
    for kind in ("github-reviewed", "unreviewed"):
        for y, m in months:
            files += glob.glob(os.path.join(a.db, "advisories", kind, str(y), "%02d" % m, "*", "*.json"))
    reviewed_ids = {os.path.basename(f)[:-5] for f in glob.glob(os.path.join(a.db, "advisories", "github-reviewed", "*", "*", "*", "*.json"))}

    scanned = severe = 0
    cands = []
    for f in files:
        d = json.load(open(f, encoding="utf-8"))
        if d.get("withdrawn") or d["published"][:10] != a.date:
            continue
        scanned += 1
        score, ver, vec = score_of(d)
        if score is None or score < 8.0:
            continue
        severe += 1
        source = "GitHub-reviewed" if "/github-reviewed/" in f.replace("\\", "/") else "GitHub-unreviewed (from NVD)"
        aff = d.get("affected", [])
        packages = sorted({x.get("package", {}).get("name", "") for x in aff} - {""})
        ecos = sorted({x.get("package", {}).get("ecosystem", "") for x in aff} - {""})
        refs = [r["url"] for r in d.get("references", [])]
        text = " ".join([d.get("summary", ""), d.get("details", ""), " ".join(packages)])
        cwe = d.get("database_specific", {}).get("cwe_ids", [])

        # Why it might be AI (any one is enough to send it to Claude)
        why, reg = [], None
        for p in packages:
            if p.lower() in pkgs:
                reg = pkgs[p.lower()]; why.append("registry package")
                break
        if reg is None:
            m = name_rx.search(text)
            if m:
                reg = names[m.group(1).lower()]; why.append("registry name: " + m.group(1))
        if reg is None:
            for u in refs:
                m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", u)
                if m and (m.group(1) + "/" + m.group(2)).lower().removesuffix(".git") in repos:
                    reg = repos[(m.group(1) + "/" + m.group(2)).lower().removesuffix(".git")]; why.append("registry repo link")
                    break
        if reg is None:
            flat = re.sub(r"[^a-z0-9]", "", " ".join(u for u in refs if "nvd.nist.gov" not in u).lower())
            hit = next((k for k in slugs if k in flat), None)
            if hit:
                reg = slugs[hit]; why.append("registry name in link")
        if BRAND.search(text): why.append("brand term")
        if GENERIC.search(text): why.append("AI term")
        if "CWE-1427" in cwe: why.append("CWE-1427")
        if not why:
            continue

        own = d["id"]
        dup = next((g for u in refs for g in re.findall(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", u)
                    if g != own and g in reviewed_ids), "")
        cves = [x for x in d.get("aliases", []) if x.startswith("CVE-")]
        fixed = sorted({e["fixed"] for x in aff for r in x.get("ranges", []) for e in r.get("events", []) if "fixed" in e})
        av = re.search(r"AV:([NALP])", vec); pr = re.search(r"PR:([NLH])", vec)
        c = dict(
            ghsa=own, cve=";".join(cves), published=a.date,
            week_start=(day - dt.timedelta(days=day.weekday())).isoformat(),
            score=score, cvss_version=ver, source=source,
            package=";".join(packages), ecosystem=";".join(ecos),
            summary=(d.get("summary") or d.get("details", ""))[:300].replace("\n", " "),
            description=d.get("details", "")[:600].replace("\n", " "),
            refs=" ".join(refs[:12]), link="https://github.com/advisories/" + own,
            match=", ".join(why),
            registry_product=reg["product"] if reg else "", registry_maker=reg["maker"] if reg else "",
            registry_purpose=reg["purpose"] if reg else "", brand25=(reg.get("brand25") or "") if reg else "",
            maker_type=reg["maker_type"] if reg else "",
            duplicate_of=dup,
            patch_available=("Yes" if fixed else "No") if source == "GitHub-reviewed" else ("Yes" if fixed else "Unknown"),
            fixed_version=", ".join(fixed),
            vulnerable_versions="; ".join(
                " ".join(("from " + e["introduced"]) if "introduced" in e else ("before " + e["fixed"]) if "fixed" in e
                         else ("through " + e["last_affected"]) if "last_affected" in e else "" for e in r.get("events", []))
                for x in aff for r in x.get("ranges", [])),
            attack_vector=av.group(1) if av else "", login_required=pr.group(1) if pr else "",
            cwe=";".join(cwe), classic_bug="Yes" if set(cwe) & CLASSIC else "No",
            vendor_link=next((u for u in refs if "nvd.nist.gov" not in u and "/advisories/GHSA" not in u), ""),
            late_filing="Yes" if cves and not cves[0].startswith("CVE-%d" % day.year) else "",
            epss_percentage="", epss_percentile="", credits="",
        )
        cands.append(c)

    # Enrich from GitHub's API: EPSS, credits, and a check for a reviewed advisory with the same CVE.
    if not a.no_api:
        for c in cands:
            j = gh_api("/advisories/" + c["ghsa"])
            if j:
                ep = j.get("epss") or {}
                if isinstance(ep, list):  # GitHub returns one object; accept a list too
                    ep = ep[0] if ep else {}
                if isinstance(ep, dict):
                    c["epss_percentage"] = ep.get("percentage", "") or ""
                    c["epss_percentile"] = ep.get("percentile", "") or ""
                c["credits"] = ", ".join(((x or {}).get("user") or {}).get("login", "")
                                         for x in (j.get("credits") or []) if isinstance(x, dict))
            if not c["duplicate_of"] and c["source"] != "GitHub-reviewed" and c["cve"]:
                r = gh_api("/advisories?type=reviewed&cve_id=" + c["cve"].split(";")[0])
                if r:
                    other = [x["ghsa_id"] for x in r if x.get("ghsa_id") != c["ghsa"]]
                    if other:
                        c["duplicate_of"] = other[0]

    cands.sort(key=lambda c: -c["score"])
    lines = []
    for i, c in enumerate(cands, 1):
        lines.append(f"{i}. GHSA: {c['ghsa']} ;; CVE: {c['cve']} ;; SCORE: {c['score']} ;; SOURCE: {c['source']} ;; "
                     f"PACKAGES: {c['package']} ;; REGISTRY MATCH: {c['registry_product'] or 'none'} ;; "
                     f"WHY FLAGGED: {c['match']} ;; SUMMARY: {c['summary']} ;; DESCRIPTION: {c['description']} ;; "
                     f"REFS: {c['refs']}")
    out = dict(date=a.date, generated_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
               scanned=scanned, severe=severe, candidate_count=len(cands),
               candidates_text="\n".join(lines) if lines else "NONE", candidates=cands)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, a.date + ".json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)
    print(f"{a.date}: {scanned} advisories, {severe} rated 8.0+, {len(cands)} AI candidates")


if __name__ == "__main__":
    main()
