# BloodHound Enterprise Identity Risk Report — PDF Edition

Production package for **Version 2.0 FINAL**.

## Package entry point

`Identity_Risk_Report_PDF_v1_5_FINAL.ipynb` is the canonical production notebook. It generates:

- The executive PDF Identity Risk Report.
- The supporting technical Evidence Workbook (XLSX).

## Setup

1. Install the packages in `requirements.txt`.
2. Edit `config/bhe_report_config.json` with the BloodHound Enterprise tenant URL and API credentials.
3. Set the customer name and optional customer-logo fields.
4. Run the notebook from top to bottom.

Customer logos and cover images are optional. Blank branding fields use the embedded/default report artwork. Generated artifacts are written to `output/`.

## Release baseline

Version **2.0 FINAL** is the frozen production baseline for the PDF Edition. It includes the finalized Executive Dashboard, Identity Risk Themes, connected-platform reporting, Privilege Zone Intelligence summary reporting, and Evidence Workbook generation.

Internal build lineage: **v1.5.44+**.
