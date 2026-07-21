from __future__ import annotations

import json
import shutil
import time
import zipfile
from itertools import zip_longest
from pathlib import Path
from typing import Any, Iterable, Optional

import pandas as pd

PLATFORM = "Okta"
DEFAULT_CURATED_SEARCHES = ['Okta: Read Client Secrets of Privileged Applications', 'Okta: Unrotated Active Access Keys on Privileged Apps', 'Okta: Password and MFA Permissions', 'Okta: Privileged Users without MFA (Direct)', 'Okta: Privileged Users without MFA (Indirect)', 'Okta: Synced Principals with Privileged Access (Direct) - Hybrid Edges', 'Okta: Synced Principals with Privileged Access (Indirect) - Hybrid Edges', 'Okta: Principals with Admin Console Access']


def _flatten(value: Any) -> Any:
    return json.dumps(value, default=str) if isinstance(value, (dict, list)) else value


def bhe_graph_response_to_df(raw: Any) -> pd.DataFrame:
    if raw is None:
        return pd.DataFrame()

    data = raw.get("data") if isinstance(raw, dict) else raw
    if not isinstance(data, dict):
        return pd.DataFrame(data if isinstance(data, list) else [{"raw": raw}])

    rows = []

    for node_id, node in (data.get("nodes", {}) or {}).items():
        row = {"result_type": "node", "id": node_id}
        if isinstance(node, dict):
            row.update({
                "label": node.get("label"),
                "kind": node.get("kind"),
                "kinds": ",".join(node.get("kinds", [])) if isinstance(node.get("kinds"), list) else node.get("kinds"),
                "objectId": node.get("objectId"),
                "isTierZero": node.get("isTierZero"),
                "isOwnedObject": node.get("isOwnedObject"),
                "lastSeen": node.get("lastSeen"),
            })
            for key, value in node.items():
                if key not in row:
                    row[key] = _flatten(value)
        else:
            row["raw"] = _flatten(node)
        rows.append(row)

    for idx, edge in enumerate(data.get("edges", []) or []):
        row = {"result_type": "edge", "edge_index": idx}
        if isinstance(edge, dict):
            for key, value in edge.items():
                row[key] = _flatten(value)
        else:
            row["edge"] = _flatten(edge)
        rows.append(row)

    literals = data.get("literals", []) or []
    if literals:
        columns = []
        for literal in literals:
            if isinstance(literal, dict):
                if isinstance(literal.get("values"), list):
                    columns.append(literal["values"])
                elif isinstance(literal.get("value"), list):
                    columns.append(literal["value"])
                elif "value" in literal:
                    columns.append([literal["value"]])
                else:
                    columns.append([literal])
            else:
                columns.append([literal])

        if len(columns) > 1:
            for values in zip_longest(*columns, fillvalue=None):
                rows.append({"result_type": "literal", **{f"col_{i+1}": _flatten(v) for i, v in enumerate(values)}})
        else:
            for value in columns[0]:
                rows.append({"result_type": "literal", "value": _flatten(value)})

    return pd.DataFrame(rows)


def run_bhe_graph_query(bh: Any, query: str) -> pd.DataFrame:
    if hasattr(bh, "raw"):
        return bhe_graph_response_to_df(bh.raw(query))
    result = bh.run(query)
    return result if isinstance(result, pd.DataFrame) else bhe_graph_response_to_df(result)


def _load_json(path: Path) -> Any:
    raw = path.read_bytes()
    if not raw.strip():
        raise ValueError("empty file")
    return json.loads(raw.decode("utf-8-sig", errors="replace").strip())


def _extract_query(obj: Any) -> str:
    candidates = []

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                lowered = str(key).lower()
                if isinstance(child, str) and lowered in {"query", "cypher", "statement"}:
                    candidates.append((0, child))
                elif isinstance(child, str) and ("match " in child.lower() or "return " in child.lower()):
                    candidates.append((1, child))
                else:
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(obj)
    if not candidates:
        return ""
    return sorted(candidates, key=lambda item: (item[0], -len(item[1])))[0][1]


def _extract_name(obj: Any, fallback: str) -> str:
    if isinstance(obj, dict):
        for key in ["name", "title", "display_name", "displayName", "label"]:
            if isinstance(obj.get(key), str):
                return obj[key]
    return fallback


def _extract_description(obj: Any) -> str:
    if isinstance(obj, dict):
        for key in ["description", "summary"]:
            if isinstance(obj.get(key), str):
                return obj[key]
    return ""


def load_catalog(saved_search_zip: str | Path, work_dir: str | Path) -> pd.DataFrame:
    saved_search_zip = Path(saved_search_zip)
    work_dir = Path(work_dir)

    if not saved_search_zip.exists():
        raise FileNotFoundError(f"Missing saved-search ZIP: {saved_search_zip}")

    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(saved_search_zip) as archive:
        archive.extractall(work_dir)

    records = []

    for path in sorted(work_dir.rglob("*.json")):
        if any(part.startswith(".") for part in path.parts):
            continue

        try:
            data = _load_json(path)
        except Exception:
            continue

        items = data if isinstance(data, list) else [data]
        for item in items:
            query = _extract_query(item)
            name = _extract_name(item, path.stem)
            description = _extract_description(item)
            records.append({
                "file": str(path.relative_to(work_dir)),
                "name": name,
                "description": description,
                "query": query,
                "has_query": bool(query),
            })

    return pd.DataFrame(records)


def _first_value(row: pd.Series, candidates: list[str]) -> str:
    for column in candidates:
        if column in row and pd.notna(row[column]) and str(row[column]).strip():
            return str(row[column])
    return ""


def _principal(row: pd.Series) -> str:
    return _first_value(row, ["label", "name", "displayName", "username", "login", "objectId", "id"])


def _object_type(row: pd.Series) -> str:
    return _first_value(row, ["kind", "kinds", "primarykind", "result_type"])


def _relationship(row: pd.Series) -> str:
    return _first_value(row, ["kind", "relationship_type", "edge_type", "type", "label"])


def _target(row: pd.Series) -> str:
    return _first_value(row, ["target", "target_label", "target_name", "target_kind", "objectId"])


THEME_BY_SEARCH = {'Okta: Read Client Secrets of Privileged Applications': 'Okta Credential Exposure', 'Okta: Unrotated Active Access Keys on Privileged Apps': 'Okta Credential Exposure', 'Okta: Password and MFA Permissions': 'Okta Administrative Risk', 'Okta: Privileged Users without MFA (Direct)': 'Okta Authentication Policy Risk', 'Okta: Privileged Users without MFA (Indirect)': 'Okta Authentication Policy Risk', 'Okta: Synced Principals with Privileged Access (Direct) - Hybrid Edges': 'Okta Hybrid Identity Risk', 'Okta: Synced Principals with Privileged Access (Indirect) - Hybrid Edges': 'Okta Hybrid Identity Risk', 'Okta: Principals with Admin Console Access': 'Okta Administrative Risk'}
WHY_BY_THEME = {'Okta Credential Exposure': 'Okta client secrets and access keys can create high-impact paths into privileged applications and identity administration.', 'Okta Administrative Risk': 'Okta administrative permissions can affect passwords, MFA factors, application access, and tenant-wide identity controls.', 'Okta Authentication Policy Risk': 'Privileged users without MFA have a higher likelihood of account takeover leading to administrative control.', 'Okta Hybrid Identity Risk': 'Synced or integrated principals with privileged Okta access can extend compromise between on-premises identity and the Okta control plane.'}
RECOMMENDATION_BY_THEME = {'Okta Credential Exposure': 'Rotate stale credentials and restrict access to client secrets and privileged application keys.', 'Okta Administrative Risk': 'Review administrative permissions and reduce standing access to password, MFA, application, and tenant controls.', 'Okta Authentication Policy Risk': 'Require phishing-resistant MFA for all privileged Okta users and indirect administrative paths.', 'Okta Hybrid Identity Risk': 'Review synced principals, agents, and hybrid relationships that lead to privileged Okta access.'}


def _theme(search_name: str) -> str:
    return THEME_BY_SEARCH.get(search_name, f"Okta Identity Risk")


def run_curated_okta_plugin(
    bh: Any,
    saved_search_zip: str | Path = "Okta_searches.zip",
    selected_names: Optional[Iterable[str]] = None,
    max_rows_per_search: int = 25,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Returns:
      evidence_df  - clean customer/report-facing rows
      status_df    - query success/failure and counts
      technical_df - raw parsed graph rows for technical export only

    If the platform is not present, successful queries return zero rows and
    evidence_df remains empty. Query failures stay isolated in status_df.
    """
    catalog = load_catalog(saved_search_zip, "_okta_curated_saved_searches_tmp")
    names = list(selected_names) if selected_names else DEFAULT_CURATED_SEARCHES
    selected = catalog[catalog["name"].isin(names)].copy()

    evidence_rows = []
    status_rows = []
    technical_rows = []

    for _, saved in selected.iterrows():
        name = str(saved["name"])
        query = str(saved["query"])
        theme = _theme(name)
        start = time.time()

        try:
            graph_df = run_bhe_graph_query(bh, query)
            elapsed = round(time.time() - start, 2)

            status_rows.append({
                "Search": name,
                "Risk Theme": theme,
                "Succeeded": True,
                "Rows": len(graph_df),
                "Elapsed Seconds": elapsed,
                "Error": "",
            })

            for _, row in graph_df.iterrows():
                raw = row.dropna().to_dict()
                technical_rows.append({
                    "Platform": PLATFORM,
                    "Search": name,
                    "Risk Theme": theme,
                    **{str(k): _flatten(v) for k, v in raw.items()},
                })

            for _, row in graph_df.head(max_rows_per_search).iterrows():
                evidence_rows.append({
                    "Platform": PLATFORM,
                    "Risk Theme": theme,
                    "Finding": name,
                    "Principal / Object": _principal(row),
                    "Relationship": _relationship(row),
                    "Target / Scope": _target(row),
                    "Object Type": _object_type(row),
                    "Why It Matters": WHY_BY_THEME.get(theme, f"Okta relationships may create identity or administrative attack paths."),
                    "Recommendation": RECOMMENDATION_BY_THEME.get(theme, f"Review Okta access and administration for least privilege."),
                })

        except Exception as error:
            status_rows.append({
                "Search": name,
                "Risk Theme": theme,
                "Succeeded": False,
                "Rows": 0,
                "Elapsed Seconds": round(time.time() - start, 2),
                "Error": f"{type(error).__name__}: {error}",
            })

    evidence_df = pd.DataFrame(evidence_rows)
    if not evidence_df.empty:
        evidence_df = evidence_df.drop_duplicates().reset_index(drop=True)

    return evidence_df, pd.DataFrame(status_rows), pd.DataFrame(technical_rows)


def export_curated_okta_results(
    evidence_df: pd.DataFrame,
    status_df: pd.DataFrame,
    technical_df: pd.DataFrame,
    output_path: str | Path = "okta_opengraph_curated_results.xlsx",
) -> Path:
    output_path = Path(output_path)

    with pd.ExcelWriter(output_path) as writer:
        evidence_df.to_excel(writer, sheet_name="Report Evidence", index=False)
        status_df.to_excel(writer, sheet_name="Run Status", index=False)
        technical_df.to_excel(writer, sheet_name="Technical Raw", index=False)

        if not evidence_df.empty:
            summary = (
                evidence_df.groupby(["Risk Theme", "Finding"])
                .size()
                .reset_index(name="Evidence Rows")
                .sort_values(["Risk Theme", "Evidence Rows"], ascending=[True, False])
            )
            summary.to_excel(writer, sheet_name="Summary", index=False)

    return output_path


def collect_extension(bh, config):
    return run_curated_okta_plugin(
        bh=bh,
        saved_search_zip=config.get("saved_search_zip", "searches/Okta_searches.zip"),
        selected_names=config.get("selected_searches") or None,
        max_rows_per_search=int(config.get("max_rows_per_search", 25)),
    )
