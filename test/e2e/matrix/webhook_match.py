"""Exact fail-closed webhook matchConditions required by offline/live preflight."""

GATEWAY = "ratatoskr.skaldhall.io/gateway"
CREATE = ("(has(object.metadata.labels) && '" + GATEWAY + "' in object.metadata.labels) || "
          "(has(object.metadata.annotations) && '" + GATEWAY + "' in object.metadata.annotations)")
UPDATE = (CREATE + " || "
          "(request.operation == 'UPDATE' && oldObject != null && has(oldObject.metadata.labels) && '" + GATEWAY + "' in oldObject.metadata.labels) || "
          "(request.operation == 'UPDATE' && oldObject != null && has(oldObject.metadata.annotations) && '" + GATEWAY + "' in oldObject.metadata.annotations)")


def matches(hook, *, validate):
    if not isinstance(hook, dict) or "objectSelector" in hook:
        return False
    conditions = hook.get("matchConditions")
    if not isinstance(conditions, list) or len(conditions) != 1 or not isinstance(conditions[0], dict) or \
            set(conditions[0]) != {"name", "expression"} or conditions[0]["name"] != "gateway-opt-in":
        return False
    # No second condition, weaker disjunct, user input or external call may
    # silently broaden/narrow API admission while preflight claims safety.
    expression = conditions[0]["expression"]
    return isinstance(expression, str) and " ".join(expression.split()) == (UPDATE if validate else CREATE)
