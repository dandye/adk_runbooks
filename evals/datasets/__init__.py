"""
Datasets package for declarative evaluation test cases.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

DATASETS_DIR = Path(__file__).resolve().parent


def get_dataset_path(dataset_name: str) -> Path:
    """Retrieve absolute file path for a dataset JSON file."""
    if not dataset_name.endswith(".json"):
        dataset_name = f"{dataset_name}.json"
    return DATASETS_DIR / dataset_name


def load_dataset(dataset_name: str) -> List[Dict[str, Any]]:
    """Load and parse a JSON test dataset by name."""
    path = get_dataset_path(dataset_name)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found at '{path}'.")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"Dataset in '{path}' must be a JSON array of test cases.")
    return data
