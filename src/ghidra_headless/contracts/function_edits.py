"""JVM-free validation shared by the function edit schema and core handler."""


def validate_function_rename(new_name, namespace_path, create_namespace):
    """Return path components, or None when the existing namespace is kept."""
    if new_name is None and namespace_path is None:
        raise ValueError("new_name or namespace_path is required")
    if new_name is not None:
        if not isinstance(new_name, str) or not 1 <= len(new_name) <= 1024:
            raise ValueError("new_name must contain 1-1024 characters")
        if "::" in new_name:
            raise ValueError("new_name must be a simple name; use namespace_path for the namespace")
    if type(create_namespace) is not bool:
        raise ValueError("create_namespace must be a boolean")
    if create_namespace and namespace_path is None:
        raise ValueError("create_namespace requires namespace_path")
    if namespace_path is None:
        return None
    if not isinstance(namespace_path, str) or len(namespace_path) > 4096:
        raise ValueError("namespace_path must be a string of at most 4096 characters")
    if namespace_path == "":
        return []  # Global namespace, distinct from an omitted path.
    parts = namespace_path.split("::")
    if any(not part or len(part) > 1024 or any(c == ":" or c.isspace() or ord(c) < 32 for c in part) for part in parts):
        raise ValueError("namespace_path must contain nonempty names separated by ::, without whitespace or colons")
    return parts
