
from __future__ import annotations

import json
import shutil
import time
import zipfile
from itertools import zip_longest
from pathlib import Path
from typing import Any, Iterable, Optional

import pandas as pd

DEFAULT_GITHUB_REPORT_SEARCHES = [
    "GitHub: Secrets Reachable by User",
    "GitHub: Repos Vulnerable to Workflow Secret Exfiltration",
    "GitHub: Branch Protection - No Code Owner Reviews",
    "GitHub: Members Can Change Repository Visibility",
    "GitHub: Secret Scanning Push Protection Disabled",
]



def _flatten_cell_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return value


def bhe_graph_response_to_df(raw: Any) -> pd.DataFrame:
    if raw is None:
        return pd.DataFrame()

    data = raw.get("data") if isinstance(raw, dict) else raw
    if not isinstance(data, dict):
        if isinstance(data, list):
            return pd.DataFrame(data)
        return pd.DataFrame([{"raw": raw}])

    rows = []

    for node_id, node in (data.get("nodes", {}) or {}).items():
        if not isinstance(node, dict):
            rows.append({"result_type": "node", "id": node_id, "raw": _flatten_cell_value(node)})
            continue

        row = {
            "result_type": "node",
            "id": node_id,
            "label": node.get("label"),
            "kind": node.get("kind"),
            "kinds": ",".join(node.get("kinds", [])) if isinstance(node.get("kinds"), list) else node.get("kinds"),
            "objectId": node.get("objectId"),
            "isTierZero": node.get("isTierZero"),
            "isOwnedObject": node.get("isOwnedObject"),
            "lastSeen": node.get("lastSeen"),
        }
        for k, v in node.items():
            if k not in row:
                row[k] = _flatten_cell_value(v)
        rows.append(row)

    for idx, edge in enumerate(data.get("edges", []) or []):
        row = {"result_type": "edge", "edge_index": idx}
        if isinstance(edge, dict):
            for k, v in edge.items():
                row[k] = _flatten_cell_value(v)
        else:
            row["edge"] = _flatten_cell_value(edge)
        rows.append(row)

    literals = data.get("literals", []) or []
    if literals:
        literal_columns = []
        for lit in literals:
            if isinstance(lit, dict):
                if isinstance(lit.get("values"), list):
                    literal_columns.append(lit["values"])
                elif isinstance(lit.get("value"), list):
                    literal_columns.append(lit["value"])
                elif "value" in lit:
                    literal_columns.append([lit["value"]])
                else:
                    literal_columns.append([lit])
            else:
                literal_columns.append([lit])

        if len(literal_columns) > 1:
            for literal_row in zip_longest(*literal_columns, fillvalue=None):
                rows.append({
                    "result_type": "literal",
                    **{f"col_{i+1}": _flatten_cell_value(v) for i, v in enumerate(literal_row)}
                })
        else:
            for v in literal_columns[0]:
                rows.append({"result_type": "literal", "value": _flatten_cell_value(v)})

    return pd.DataFrame(rows)


def run_bhe_graph_query(bh: Any, query: str) -> pd.DataFrame:
    if hasattr(bh, "raw"):
        return bhe_graph_response_to_df(bh.raw(query))
    if hasattr(bh, "run"):
        result = bh.run(query)
        if isinstance(result, pd.DataFrame):
            return result
        return bhe_graph_response_to_df(result)
    raise TypeError("The bh object must expose either bh.raw(query) or bh.run(query).")


def _load_json_lenient(path: Path) -> Any:
    raw = path.read_bytes()
    if not raw.strip():
        raise ValueError("empty file")
    text = raw.decode("utf-8-sig", errors="replace").strip()
    return json.loads(text)


def _extract_saved_search_query(obj: Any) -> str:
    candidates = []

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                lk = str(k).lower()
                if lk in {"query", "cypher", "statement"} and isinstance(v, str):
                    candidates.append((str(k), v))
                elif isinstance(v, str) and ("match " in v.lower() or "return " in v.lower()):
                    candidates.append((str(k), v))
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(obj)

    if not candidates:
        return ""

    candidates = sorted(
        candidates,
        key=lambda kv: (0 if kv[0].lower() in {"query", "cypher", "statement"} else 1, -len(kv[1]))
    )
    return candidates[0][1]


def _extract_saved_search_name(obj: Any, fallback: str) -> str:
    if isinstance(obj, dict):
        for key in ["name", "title", "display_name", "displayName", "label"]:
            if isinstance(obj.get(key), str):
                return obj[key]
    return fallback


def _extract_saved_search_description(obj: Any) -> str:
    if isinstance(obj, dict):
        for key in ["description", "summary"]:
            if isinstance(obj.get(key), str):
                return obj[key]
    return ""


def github_report_theme(name: str, description: str, query: str) -> str:
    text = " ".join([str(name), str(description), str(query)]).lower()
    if any(k in text for k in ["secret", "repo secret", "repository secret", "exfiltration"]):
        return "GitHub Secrets Exposure"
    if any(k in text for k in ["workflow", "actions", "pull request", "pr"]):
        return "GitHub Workflow Risk"
    if any(k in text for k in ["branch", "bypass", "protection"]):
        return "GitHub Branch Protection Risk"
    if any(k in text for k in ["owner", "admin", "administrator", "permission", "write", "maintain"]):
        return "GitHub Administrative Risk"
    if any(k in text for k in ["repository", "repo"]):
        return "GitHub Repository Risk"
    return "GitHub OpenGraph"


def github_candidate_score(name: str, description: str, query: str) -> int:
    text = " ".join([str(name), str(description), str(query)]).lower()
    score = 0
    for kw in ["github", "repository", "repo", "organization", "team", "owner", "admin", "secret", "workflow", "actions", "branch", "bypass", "protection", "write", "maintain"]:
        if kw in text:
            score += 1
    if "match " in text and "return " in text:
        score += 3
    for kw in ["secret", "workflow", "bypass", "admin", "owner", "branch protection", "actions_allowed_actions"]:
        if kw in text:
            score += 2
    return score


def load_github_saved_search_catalog(saved_search_zip: str | Path, work_dir: str | Path = "_github_saved_searches_plugin_tmp") -> tuple[pd.DataFrame, pd.DataFrame]:
    saved_search_zip = Path(saved_search_zip)
    work_dir = Path(work_dir)

    if not saved_search_zip.exists():
        raise FileNotFoundError(f"Missing GitHub saved-search ZIP: {saved_search_zip}")

    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(saved_search_zip, "r") as z:
        z.extractall(work_dir)

    records = []
    invalid_rows = []

    for path in sorted(work_dir.rglob("*.json")):
        if any(part.startswith(".") for part in path.parts):
            continue
        try:
            data = _load_json_lenient(path)
        except Exception as e:
            invalid_rows.append({"file": str(path.relative_to(work_dir)), "error": f"{type(e).__name__}: {e}", "size_bytes": path.stat().st_size})
            continue

        items = data if isinstance(data, list) else [data]
        for idx, item in enumerate(items):
            query = _extract_saved_search_query(item)
            name = _extract_saved_search_name(item, path.stem if len(items) == 1 else f"{path.stem}_{idx+1}")
            desc = _extract_saved_search_description(item)
            records.append({
                "file": str(path.relative_to(work_dir)),
                "name": name,
                "description": desc,
                "query": query,
                "has_query": bool(query),
                "report_theme": github_report_theme(name, desc, query),
                "candidate_score": github_candidate_score(name, desc, query),
            })

    catalog = pd.DataFrame(records)
    if catalog.empty:
        catalog = pd.DataFrame(columns=["file", "name", "description", "query", "has_query", "report_theme", "candidate_score"])

    catalog = catalog.sort_values(["candidate_score", "has_query", "report_theme", "name"], ascending=[False, False, True, True]).reset_index(drop=True)

    invalid = pd.DataFrame(invalid_rows)
    if invalid.empty:
        invalid = pd.DataFrame(columns=["file", "error", "size_bytes"])

    return catalog, invalid


def _row_display_name(row: pd.Series) -> str:
    for col in ["label", "name", "displayName", "login", "objectId", "id"]:
        if col in row and pd.notna(row[col]) and str(row[col]).strip():
            return str(row[col])
    return ""


def _row_target(row: pd.Series) -> str:
    for col in ["kind", "kinds", "target", "target_label", "target_kind"]:
        if col in row and pd.notna(row[col]) and str(row[col]).strip():
            return str(row[col])
    return ""


def _recommendation(theme: str) -> str:
    if theme == "GitHub Secrets Exposure":
        return "Review affected GitHub secrets and reduce unnecessary access paths to repositories, workflows, and users that can reach them."
    if theme == "GitHub Workflow Risk":
        return "Review GitHub Actions policy, workflow permissions, and repository workflow controls."
    if theme == "GitHub Branch Protection Risk":
        return "Review branch protection rules and remove permissions that allow bypassing or weakening protection controls."
    if theme == "GitHub Administrative Risk":
        return "Review GitHub organization, team, and repository administration assignments and reduce standing privileged access."
    if theme == "GitHub Repository Risk":
        return "Review repository permissions and restrict access to least privilege."
    return "Review the affected GitHub OpenGraph object and reduce unnecessary standing access or risky configuration."


def _why(theme: str) -> str:
    if theme == "GitHub Secrets Exposure":
        return "GitHub secrets can become a high-impact identity path when users, workflows, or repositories can reach sensitive deployment credentials."
    if theme == "GitHub Workflow Risk":
        return "GitHub workflows can affect build, deployment, and automation paths that may influence production systems."
    if theme == "GitHub Branch Protection Risk":
        return "Branch protection weaknesses can allow code or workflow changes to bypass expected review and control gates."
    if theme == "GitHub Administrative Risk":
        return "GitHub administrative access can affect repositories, organization policy, workflows, and secrets."
    if theme == "GitHub Repository Risk":
        return "Repository access can affect source code, pull requests, workflows, and development secrets."
    return "GitHub OpenGraph data extends identity risk into developer-platform access and software supply chain control points."


def _graph_rows_to_report_rows(df: pd.DataFrame, search_name: str, theme: str, evidence_source: str, max_rows: int) -> list[dict[str, Any]]:
    rows = []
    for _, result in df.head(max_rows).iterrows():
        rows.append({
            "Evidence Source": evidence_source,
            "Source": _row_display_name(result),
            "Finding": search_name,
            "Target": _row_target(result),
            "Why It Matters": _why(theme),
            "Risk": theme,
            "Recommendation": _recommendation(theme),
            "GitHub Search": search_name,
            "Result Type": result.get("result_type", ""),
            "Raw Details": json.dumps(result.dropna().to_dict(), default=str),
        })
    return rows


def run_github_opengraph_plugin(
    bh: Any,
    saved_search_zip: str | Path = "Archive.zip",
    max_queries: int = 10,
    min_score: int = 6,
    max_rows_per_search: int = 25,
    selected_names: Optional[Iterable[str]] = None,
    include_control_query: bool = True,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    catalog, invalid = load_github_saved_search_catalog(saved_search_zip)

    if selected_names:
        selected = catalog[catalog["name"].isin(list(selected_names))].copy()
    else:
        selected = catalog[(catalog["has_query"]) & (catalog["candidate_score"] >= min_score)].head(max_queries).copy()

    evidence_rows = []
    status_rows = []

    if include_control_query:
        control_name = "CONTROL: GitHub All Actions Allowed"
        control_theme = "GitHub Workflow Risk"
        control_query = """
MATCH (org:GH_Organization {actions_allowed_actions: 'all'})
RETURN org
LIMIT 1000
"""
        start = time.time()
        try:
            control_df = run_bhe_graph_query(bh, control_query)
            elapsed = round(time.time() - start, 2)
            status_rows.append({"name": control_name, "report_theme": control_theme, "ok": True, "rows": len(control_df), "elapsed_seconds": elapsed, "error": "", "query": control_query})
            evidence_rows.extend(_graph_rows_to_report_rows(control_df, "All GitHub Actions Allowed", control_theme, "GitHub OpenGraph Control Query", max_rows_per_search))
        except Exception as e:
            elapsed = round(time.time() - start, 2)
            status_rows.append({"name": control_name, "report_theme": control_theme, "ok": False, "rows": 0, "elapsed_seconds": elapsed, "error": f"{type(e).__name__}: {e}", "query": control_query})

    for _, saved_search in selected.iterrows():
        name = str(saved_search["name"])
        theme = str(saved_search["report_theme"])
        query = str(saved_search["query"])
        start = time.time()
        try:
            df = run_bhe_graph_query(bh, query)
            elapsed = round(time.time() - start, 2)
            status_rows.append({"name": name, "report_theme": theme, "ok": True, "rows": len(df), "elapsed_seconds": elapsed, "error": "", "query": query})
            evidence_rows.extend(_graph_rows_to_report_rows(df, name, theme, f"GitHub Saved Search: {name}", max_rows_per_search))
        except Exception as e:
            elapsed = round(time.time() - start, 2)
            status_rows.append({"name": name, "report_theme": theme, "ok": False, "rows": 0, "elapsed_seconds": elapsed, "error": f"{type(e).__name__}: {e}", "query": query})

    return pd.DataFrame(evidence_rows), pd.DataFrame(status_rows)


def export_github_opengraph_plugin_results(evidence_df: pd.DataFrame, status_df: pd.DataFrame, output_path: str | Path = "github_opengraph_plugin_results.xlsx") -> Path:
    output_path = Path(output_path)
    with pd.ExcelWriter(output_path) as writer:
        evidence_df.to_excel(writer, sheet_name="Report Evidence", index=False)
        status_df.to_excel(writer, sheet_name="Run Status", index=False)
        if not evidence_df.empty and "Risk" in evidence_df.columns:
            summary = evidence_df.groupby(["Risk", "GitHub Search"]).size().reset_index(name="Rows").sort_values(["Risk", "Rows"], ascending=[True, False])
            summary.to_excel(writer, sheet_name="Summary", index=False)
    return output_path


def run_curated_github_opengraph_plugin(
    bh: Any,
    saved_search_zip: str | Path = "Archive.zip",
    max_rows_per_search: int = 25,
    selected_names: Optional[Iterable[str]] = None,
    include_control_query: bool = True,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    names = list(selected_names) if selected_names else DEFAULT_GITHUB_REPORT_SEARCHES
    return run_github_opengraph_plugin(
        bh=bh,
        saved_search_zip=saved_search_zip,
        max_queries=len(names),
        min_score=0,
        max_rows_per_search=max_rows_per_search,
        selected_names=names,
        include_control_query=include_control_query,
    )


def collect_extension(bh, config):
    evidence_df, status_df = run_curated_github_opengraph_plugin(
        bh=bh,
        saved_search_zip=config.get("saved_search_zip", "searches/GitHub_searches.zip"),
        max_rows_per_search=int(config.get("max_rows_per_search", 25)),
        selected_names=config.get("selected_searches") or None,
        include_control_query=bool(config.get("include_control_query", True)),
    )
    technical_df = evidence_df.copy()
    customer_cols = [c for c in ["Evidence Source","Source","Finding","Target","Why It Matters","Risk","Recommendation"] if c in evidence_df.columns]
    evidence_df = evidence_df[customer_cols].copy() if customer_cols else evidence_df.copy()
    return evidence_df, status_df, technical_df
