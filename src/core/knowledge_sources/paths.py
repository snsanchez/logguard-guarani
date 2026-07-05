from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).resolve().parents[3] / "knowledge"
METADATA_FILE = KNOWLEDGE_DIR / "metadata.json"
PLAYBOOKS_DIR = KNOWLEDGE_DIR / "playbooks"
REFERENCES_DIR = KNOWLEDGE_DIR / "references"
MITRE_DIR = KNOWLEDGE_DIR / "mitre"
CVES_DIR = KNOWLEDGE_DIR / "cves"
REQUIRED_SUBDIRS = [PLAYBOOKS_DIR, REFERENCES_DIR, MITRE_DIR, CVES_DIR]
REQUIRED_METADATA_KEYS = ["version", "last_updated", "sources"]
CVE_CACHE_FILE = CVES_DIR / "cve_cache.json"
KEV_CACHE_FILE = CVES_DIR / "kev.json"
MITRE_MAPPINGS_FILE = MITRE_DIR / "attack_mappings.json"
