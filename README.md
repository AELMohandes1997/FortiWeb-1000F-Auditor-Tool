# FortiWeb-1000F-Auditor-Tool
FortiWeb 1000F WAF Auditor 2026 


# Default Command :
python3 fortiweb_audit.py your_fortiweb.conf

# CSV Format: 
python3 fortiweb_audit.py your_fortiweb.conf --output findings.csv --format csv

# Filter to failures only
python3 fortiweb_audit.py fortiweb.conf --failed-only

# Only CRITICAL and HIGH severity
python3 fortiweb_audit.py fortiweb.conf --severity CRITICAL HIGH

# Quick terminal output
python3 fortiweb_audit.py fortiweb.conf --format text
