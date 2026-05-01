"""
Utility functions for working with JSON data.

Currently provides a function to flatten nested JSON objects into
a single‑level dictionary using dot notation.  This makes it easy to
store and process heterogeneous alert structures in a tabular form.
"""

from typing import Any, Dict


def flatten_json(data: Dict[str, Any], parent_key: str = '') -> Dict[str, Any]:
    """Flatten a nested JSON-like dictionary.

    Parameters
    ----------
    data : Dict[str, Any]
        The dictionary to flatten.
    parent_key : str
        The base key to prepend to nested keys.  Used recursively.

    Returns
    -------
    Dict[str, Any]
        A new dictionary with no nested structures.  Nested keys are
        concatenated with dots.
    """
    items: Dict[str, Any] = {}
    for key, value in data.items():
        new_key = f"{parent_key}.{key}" if parent_key else key
        if isinstance(value, dict):
            items.update(flatten_json(value, new_key))
        else:
            items[new_key] = value
    return items


__all__ = ['flatten_json']