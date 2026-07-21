from __future__ import annotations
from dataclasses import dataclass
from typing import Any
import pandas as pd

VALID_STATUSES = {"Collected", "No Evidence", "Not Present", "Disabled", "Collection Issue"}

@dataclass
class ExtensionResult:
    evidence_df: pd.DataFrame
    status_df: pd.DataFrame
    technical_df: pd.DataFrame
    coverage_status: str
    finding_count: int
    collection_note: str = ""

    def __post_init__(self):
        if self.coverage_status not in VALID_STATUSES:
            raise ValueError(f"Invalid extension coverage status: {self.coverage_status}")


def infer_coverage_status(enabled: bool, evidence_df: pd.DataFrame, status_df: pd.DataFrame) -> tuple[str, str]:
    if not enabled:
        return "Disabled", ""
    if status_df is None or status_df.empty:
        return "Not Present", "No saved searches were executed or the platform was not detected."

    ok_col = "Succeeded" if "Succeeded" in status_df.columns else ("ok" if "ok" in status_df.columns else None)
    rows_col = "Rows" if "Rows" in status_df.columns else ("rows" if "rows" in status_df.columns else None)
    error_col = "Error" if "Error" in status_df.columns else ("error" if "error" in status_df.columns else None)

    successes = int(status_df[ok_col].fillna(False).astype(bool).sum()) if ok_col else 0
    failures = len(status_df) - successes if ok_col else 0
    returned_rows = int(pd.to_numeric(status_df[rows_col], errors="coerce").fillna(0).sum()) if rows_col else len(evidence_df)

    if successes == 0 and failures > 0:
        details = "; ".join(status_df[error_col].dropna().astype(str).head(3)) if error_col else "All extension queries failed."
        return "Collection Issue", details
    if returned_rows == 0 or evidence_df is None or evidence_df.empty:
        if failures > 0:
            return "No Evidence", f"No evidence returned; {failures} query failure(s) were isolated."
        return "No Evidence", "Queries completed but returned no evidence."
    if failures > 0:
        return "Collected", f"Evidence collected; {failures} query failure(s) were isolated."
    return "Collected", ""
