[English](bsim.md) | [日本語](bsim.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Function similarity with BSim

BSim compares function signatures against a database of previously analyzed programs. The database stores signatures and metadata; the original Ghidra project stores the program needed for decompilation and comparison. Preserve both.

This guide assumes a working database and a loaded program. To create a PostgreSQL backend on macOS, use the separate [setup](bsim-postgresql-macos.md), [bulk ingestion](bsim-ingestion.md), and [operations](bsim-operations.md) guides. Those administrative guides are in Japanese and record their historical validation environments.

## Connect a database

Set `GHIDRA_INSTALL_DIR` and put the database password in `BSIM_PASSWORD`. Point to an existing project and program:

```bash
uv run mecha_ghidra \
  --project-location /work/analysis.gpr \
  --domain-path /sample.bin \
  --transport stdio \
  --add-category bsim \
  --bsim-url postgresql://bsim_user@localhost/malware_curated \
  --bsim-password-env BSIM_PASSWORD
```

`--bsim-url` provides the default; an individual call may supply `bsim_url`. Supported URL schemes are `postgresql://`, `elastic://`, `https://`, and `file:`. For password-based network access, set either `--bsim-password-env` or `--bsim-password`, not both. A URL without a username uses the OS username when a configured password is supplied. Returned URLs mask embedded credentials.

Call `get_bsim_database_status` first. It reports database metadata, executable count, configured categories/function tags, and runtime information. See [tool schemas](tools.md#bsim) for each backend's parameters.

## Search and inspect a match

1. Get a function address from `list_functions`.
2. Call `bsim_query(scope="functions", addresses=[...])` with that address. Alternatively use `function_names`; `scope="program"` searches the loaded program.
3. Inspect scores and the returned `query` provenance. Self matches are excluded unless `exclude_self=false`.
4. Copy the result's `matched_ref` into `bsim_load_matched_executable` without rebuilding it by hand. The reference is versioned and validated.
5. Use the returned target with `get_function` and `decompile_function` to compare the matched code.

Example arguments for `bsim_query` (replace the address):

```json
{
  "target": "default",
  "scope": "functions",
  "addresses": ["<function-address>"],
  "similarity_threshold": 0.8,
  "matches_per_function": 5
}
```

For a `ghidra://` match stored on Ghidra Server, configure `--bsim-remote-cache-dir /work/bsim-cache` and repository credentials on the MCP server. The cache directory must lie under an allowed project root when roots are restricted. A match whose original project is missing can still appear in search results, but cannot be opened for decompilation.

## Register and maintain known programs

| Task | Tool / behavior |
| --- | --- |
| Add a metadata category | `bsim_add_executable_category` |
| Register the loaded program | `bsim_register_target`; optional `categories` is a category-to-single-value object |
| Browse existing records | `list_bsim_executables`, `get_bsim_executable` |
| Change an existing record's categories | `bsim_update_executable_metadata`; identify it by md5 or exact name |
| Update names and metadata after renaming | `bsim_update_target_signatures`; feature vectors are not regenerated |
| Regenerate vectors after reanalysis | Delete the old record explicitly, then register again |

For registration, configure category names in the database first. Unknown names, including wrong case, fail with `BSIM_EXECUTABLE_CATEGORY_NOT_CONFIGURED`. Registration categories are also saved in Program Information, so setting them on a shared program requires a checkout.

For `bsim_update_executable_metadata`, unspecified categories are preserved, supplied categories replace their values, and `null` or an empty list clears a category. This update supports multiple values. Example:

```json
{
  "md5": "0123456789abcdef0123456789abcdef",
  "categories": {
    "FAMILY": "ExampleFamily",
    "SOURCE": "internal_analysis",
    "TRUST_LEVEL": "confirmed"
  }
}
```

Re-registering an existing executable fails with `BSIM_ALREADY_REGISTERED`. `bsim_delete_executable` removes the executable and its function records; `confirm` must repeat the md5, or the exact name when md5 is omitted.

## Apply matching names

Use `bsim_apply_matches(dry_run=true)` to preview names and scores. Review the matches, then explicitly apply them with `dry_run=false`. The default policy targets default-named functions only; the operation runs as one transaction. Save the resulting program with `save_project_program` and, when appropriate, update the database names with `bsim_update_target_signatures`.

For authentication, reachability, or invalid reference errors, see [troubleshooting](troubleshooting.md). For database backup and bulk ingestion issues, see [BSim operations](bsim-operations.md).
