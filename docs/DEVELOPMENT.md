# Development and Maintenance

The root notebook is the canonical application entry point. Build changes should be made directly in `Identity_Risk_Report_PDF_v1_5_FINAL.ipynb` and validated by running the notebook against a BloodHound Enterprise tenant.

## Baseline rules

- PDF is the primary report deliverable.
- The XLSX evidence workbook is the authoritative technical validation artifact.
- Preserve validated report calculations and representative-evidence logic.
- Keep customer branding optional and configuration-driven.
- Do not add generated reports, credentials, experimental notebooks, operating-system metadata, or temporary test artifacts to the baseline package.
- Rebuild `MANIFEST.json` and `SHA256SUMS.txt` after package changes.
