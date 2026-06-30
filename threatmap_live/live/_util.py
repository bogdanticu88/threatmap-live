"""
Helpers for reading values out of live cloud-CLI JSON.

`az` (and `aws`) output is inconsistent: some commands expose fields at the top
level in camelCase (e.g. `allowBlobPublicAccess`), others nest them under a
`properties` object (the raw ARM shape). These helpers tolerate both so a single
mapper works regardless of which form a given command returns.
"""
from typing import Any, Dict, Optional


def pick(obj: Dict[str, Any], *names: str, default: Any = None) -> Any:
    """
    Return the first present, non-null value for any of `names`, looking both at
    the top level and one level down under `properties`.
    """
    if not isinstance(obj, dict):
        return default
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {}
    for name in names:
        if obj.get(name) is not None:
            return obj[name]
        if props.get(name) is not None:
            return props[name]
    return default


def deep(obj: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Traverse a dotted `path` (e.g. "apiServerAccessProfile.authorizedIpRanges"),
    transparently stepping through a `properties` wrapper at any level.
    """
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        if cur.get(part) is not None:
            cur = cur[part]
            continue
        props = cur.get("properties")
        if isinstance(props, dict) and props.get(part) is not None:
            cur = props[part]
            continue
        return default
    return cur


def first_str(obj: Dict[str, Any], single: str, plural: str, default: Optional[str] = None) -> Optional[str]:
    """
    Resolve fields that `az` exposes as either a single string (`destinationPortRange`)
    or a list (`destinationPortRanges`). Returns the single value if present, else the
    first element of the list, else `default`.
    """
    val = pick(obj, single)
    if isinstance(val, str) and val != "":
        return val
    plural_val = pick(obj, plural)
    if isinstance(plural_val, list) and plural_val:
        return str(plural_val[0])
    return default
