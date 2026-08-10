#!/usr/bin/env python3
import os
import yaml
from pathlib import Path
from datetime import datetime

# Adjust path to find investigations relative to this script
BASE_DIR = Path(__file__).resolve().parent / "active_investigations"

def load_beads(case_dir: Path):
    beads = []
    for f in case_dir.glob("*.yaml"):
        # Basic check to see if it's a bead
        if f.name.startswith("bead-"):
            try:
                with open(f, 'r') as stream:
                    data = yaml.safe_load(stream)
                    beads.append(data)
            except Exception as e:
                print(f"Error loading {f}: {e}")
    return beads

def print_case_summary(case_id: str, beads: list):
    print(f"\n{'='*60}")
    print(f"CASE: {case_id}")
    print(f"{'='*60}")

    if not beads:
        print("No active tasks (Beads) found.")
        return

    # Sort by ID
    beads.sort(key=lambda x: x.get('id', ''))

    # Header
    print(f"{'ID':<15} | {'STATUS':<12} | {'ASSIGNED TO':<20} | {'DESCRIPTION'}")
    print(f"{'-'*15}-+-{'-'*12}-+-{'-'*20}-+-{'-'*20}")

    for b in beads:
        bid = b.get('id', 'Unknown')
        status = b.get('status', 'Unknown')
        assigned = b.get('assigned_to', 'Unassigned')
        desc = b.get('description', '')
        # Truncate desc
        if len(desc) > 50:
            desc = desc[:47] + "..."

        print(f"{bid:<15} | {status:<12} | {assigned:<20} | {desc}")
    print(f"{'-'*60}")

def main():
    if not BASE_DIR.exists():
        print(f"No active investigations directory found at {BASE_DIR}")
        return

    cases = [d for d in BASE_DIR.iterdir() if d.is_dir()]

    if not cases:
        print("No active investigations found.")
        return

    print(f"Gas Town Dashboard - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Found {len(cases)} active investigations.")

    for case_dir in cases:
        beads = load_beads(case_dir)
        print_case_summary(case_dir.name, beads)

if __name__ == "__main__":
    main()
