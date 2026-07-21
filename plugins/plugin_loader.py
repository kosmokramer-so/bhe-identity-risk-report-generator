from __future__ import annotations
import importlib.util
from pathlib import Path
from typing import Any
import pandas as pd
from plugin_base import ExtensionResult, infer_coverage_status

class ExtensionManager:
    def __init__(self, project_root: str | Path, extension_configs: list[dict]):
        self.project_root = Path(project_root)
        self.extension_configs = extension_configs
        self._modules = {}
        self._results = {}

    def _resolve(self, value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else self.project_root / path

    def load_module(self, extension_id: str):
        if extension_id in self._modules:
            return self._modules[extension_id]
        cfg = next(x for x in self.extension_configs if x['id'] == extension_id)
        module_path = self._resolve(cfg['module'])
        if not module_path.exists():
            raise FileNotFoundError(f"Missing extension module: {module_path}")
        spec = importlib.util.spec_from_file_location(f"bhe_extension_{extension_id}", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self._modules[extension_id] = module
        return module

    def collect(self, extension_id: str, bh: Any) -> ExtensionResult:
        if extension_id in self._results:
            return self._results[extension_id]
        cfg = next(x for x in self.extension_configs if x['id'] == extension_id)
        if not cfg.get('enabled', True):
            result = ExtensionResult(pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), 'Disabled', 0)
            self._results[extension_id] = result
            return result
        try:
            module = self.load_module(extension_id)
            payload = dict(cfg)
            if payload.get('saved_search_zip'):
                payload['saved_search_zip'] = str(self._resolve(payload['saved_search_zip']))
            evidence_df, status_df, technical_df = module.collect_extension(bh=bh, config=payload)
            coverage_status, note = infer_coverage_status(True, evidence_df, status_df)
            result = ExtensionResult(evidence_df, status_df, technical_df, coverage_status, len(evidence_df), note)
        except Exception as exc:
            result = ExtensionResult(
                pd.DataFrame(),
                pd.DataFrame([{'Succeeded': False, 'Rows': 0, 'Error': f'{type(exc).__name__}: {exc}'}]),
                pd.DataFrame(),
                'Collection Issue', 0,
                f'{type(exc).__name__}: {exc}',
            )
        self._results[extension_id] = result
        return result

    def coverage_dataframe(self) -> pd.DataFrame:
        rows=[]
        for cfg in self.extension_configs:
            result=self._results.get(cfg['id'])
            if result is None:
                status='Disabled' if not cfg.get('enabled', True) else 'Not Collected'
                count=0; note=''
            else:
                status=result.coverage_status; count=result.finding_count; note=result.collection_note
            rows.append({'Platform': cfg.get('platform', cfg['id'].title()), 'Status': status, 'Findings': count, 'Notes': note})
        return pd.DataFrame(rows)
