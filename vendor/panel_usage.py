# Function excerpts from PasarGuard/panel; see licenses/PANEL_LICENSE (AGPL).
# Only adaptation: Python 3.14 except syntax parenthesized for Python 3.12.
# Commit: 2b75db15cb0019a00252c59f9d1c34e6082a121f
from collections import defaultdict
from operator import attrgetter

def _process_users_stats_response(stats_response):
    """
    Process stats response (CPU-bound operation) - runs in thread pool.
    Pure function designed for thread-safe execution.
    Returns tuple: (validated_params, invalid_uids) for logging outside thread.
    """
    params = defaultdict(int)
    for stat in filter(attrgetter("value"), stats_response.stats):
        params[stat.name] += stat.value

    validated_params = []
    invalid_uids = []
    for uid, value in params.items():
        try:
            validated_params.append({"uid": int(uid), "value": value})
        except (ValueError, TypeError):
            invalid_uids.append(uid)

    return validated_params, invalid_uids

async def calculate_users_usage(api_params: dict, usage_coefficient: dict) -> list:
    """Aggregate user usage across nodes with coefficients applied."""
    if not api_params:
        return []

    users_usage: dict[int, int] = defaultdict(int)
    for node_id, params in api_params.items():
        if not params:
            continue
        coeff = usage_coefficient.get(node_id, 1)
        for param in params:
            users_usage[int(param["uid"])] += int(param["value"] * coeff)

    return [{"uid": uid, "value": value} for uid, value in users_usage.items()]
