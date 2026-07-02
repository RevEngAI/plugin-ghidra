import argparse
import json
import sys
from pathlib import Path

PLUGIN = "ghidra"

ACTIONS = {
    "AnalysisManagementPlugin: Create new": ("analyse_binary", "yes"),
    "AnalysisManagementPlugin: Attach to existing": ("apply_existing_analysis", "yes"),
    "AnalysisManagementPlugin: Check status": ("check_analysis_status", "yes"),
    "AnalysisLogComponent": ("view_analysis_logs", "yes"),
    "BinarySimilarityPlugin: Match function": ("rename_from_similar_function", "yes"),
    "BinarySimilarityPlugin: AI Decompilation": ("function_decompilation", "yes"),
    "AssemblyDiffPanel": ("function_asm_diffing", "yes"),
}

EXTRA = {
    "binary_upload": {"status": "yes"},
    "fs_collection_filter": {"status": "yes"},
    "fs_binary_filter": {"status": "yes"},
    "fs_debug_filter": {"status": "yes"},
    "fs_nns_filter": {"status": "partial"},
    "fs_similarity_filter": {"status": "yes"},
    "upload_function_names": {"status": "yes"},
    "data_types_sync": {"status": "yes"},
    "comment_sync": {"status": "partial"},
    "search": {"status": "yes"},
    "ai_decompilation_summary": {"status": "yes"},
    "disable_private_analyses": {
        "status": "yes",
        "note": "Disables private analyses creations for the Enthusiast Tier",
    },
}

MANIFEST_PATH = Path(__file__).resolve().parent.parent / ".revengai" / "features.json"


def build_manifest():
    features = {}
    for _action, (feature_id, status) in ACTIONS.items():
        features.setdefault(feature_id, {"status": status})
    for feature_id, entry in EXTRA.items():
        features.setdefault(feature_id, dict(entry))
    return {"schema_version": 1, "plugin": PLUGIN, "features": features}


def serialize():
    return json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    content = serialize()
    if args.check:
        current = MANIFEST_PATH.read_text() if MANIFEST_PATH.exists() else ""
        if current != content:
            print(
                "features.json is out of date; run: python scripts/emit_features.py",
                file=sys.stderr,
            )
            return 1
        print("features.json is up to date.")
        return 0

    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(content)
    print(f"wrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
