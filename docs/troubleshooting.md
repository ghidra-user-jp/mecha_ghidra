[English](troubleshooting.md) | [日本語](troubleshooting.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Troubleshooting and upgrades

Tool failures set MCP `isError: true`. Domain errors retain `code`, `message`, `retryable`, `hint`, and `details` under `structuredContent.error` and in matching JSON text. Branch on stable codes and inspect partial completion in `details` before retrying. Argument validation failures also include `structuredContent.error.message`. Batch-edit item failures use `status` and `results` in a normal response. Large-result availability is handled [separately](configuration.md#large-results).

## Startup and connection

| Symptom | Check / action |
| --- | --- |
| Ghidra cannot be found (`Ghidra installation directory does not exist` or `Failed to start the Ghidra JVM: ...`, exit code 1) | Set `GHIDRA_INSTALL_DIR` to the extracted distribution root (the directory holding `Ghidra/application.properties`), or pass `--ghidra-path`; configure it in the stdio client's environment |
| Native decompiler missing or not executable | Install matching `decompile` and `sleigh` files for the host OS/CPU; see [native artifacts](usage.md#native-decompiler-artifacts) |
| Project locked / already in use | Close that local project in the other process, or use a separate shared-project cache; do not delete active lock files |
| Invalid project name | Omit `.gpr` from `project_name`, or use an existing `.gpr` path as `project_location` without a name |
| Project not found on a fresh setup | Start with a project directory plus name, then call `create_project`; see [first analysis](usage.md#first-analysis) |
| No program loaded | Call `list_project_programs` and `load_project_program`; target registration alone does not load a program |
| HTTP client cannot connect | Confirm transport, host, port, `/mcp` path, and server logs; the legacy `/sse` endpoint has been removed |
| Invalid Host/Origin after wildcard binding | Match the configured fixed host and client-facing address; see [transport settings](configuration.md#transports) |
| Client timeout during import/analysis | Set an appropriate client tool timeout; the server lock timeout only limits queue waiting |
| A tool is missing | Check the profile, category filters, and explicit enable/disable flags; reconnect/refresh the client's tool list after changing startup flags |

## Tool errors

| Code | Meaning / next step |
| --- | --- |
| `PATH_NOT_ALLOWED` | Use a path inside the corresponding allowed root, after symlink resolution |
| `LOCK_TIMEOUT` | Another call holds the target lock, or a `run_script` run is still executing; `details.script_state` says whether a script is `running` or only `queued` (then `retry_after_seconds` applies). A `run_script` that itself reports `LOCK_TIMEOUT` waited `--script-queue-timeout-seconds` for `details.active_readers` operations and did not start |
| `SCRIPT_RUNTIME_UNAVAILABLE` | Check provider installation and the startup propagation-probe log. A failed probe disables all script languages; install the [pinned PyGhidra dependency](development.md#pyghidra-dependency-and-script-failures) and restart. Stock PyGhidra 3.1.0 fails this check |
| `RAW_LOADER_OPTION_UNAVAILABLE` | Ghidra could not resolve public BinaryLoader metadata for the selected language/compiler or requested option; check these values and the supported Ghidra version |
| `AMBIGUOUS_FUNCTION`, `AMBIGUOUS_DATA_TYPE` | Inspect `details.candidates`; use a function address/qualified name or a full type path |
| `SESSION_CHANGED` | Read current state and restart pagination or update the revision for edits |
| `BSIM_MATCH_STALE` | The loaded program MD5, path, or function entry differs from the match; verify the original program and query result |
| `PROGRAM_NOT_ANALYZED` | Run `analyze_program` before local variable naming/type operations |
| `CHECKOUT_REQUIRED` | Check out the versioned shared file before editing |
| `CHECKOUT_UNAVAILABLE` | Inspect repository checkout status; another user may hold an exclusive checkout |
| `READ_ONLY_PROGRAM` | A historical version is loaded; load the current file to edit |
| `MERGE_REQUIRED`, `UNSAFE_MERGE_REQUIRED` | Follow the [conflict workflow](shared-projects.md#conflicts); headless merging is unsupported |
| `JVM_NOT_HEADLESS`, `HEADLESS_UNSUPPORTED` | Check the [JVM startup rules](development.md); do not retry a display-dependent API in headless mode |
| `BSIM_URL_REQUIRED`, `BSIM_URL_INVALID` | Supply a supported BSim URL |
| `BSIM_AUTHENTICATION_FAILED`, `BSIM_DATABASE_UNREACHABLE` | Check backend credentials and connectivity |
| `BSIM_PARAMETER_INVALID`, `BSIM_INVALID_MATCHED_REF` | Use schema bounds and an unmodified query result reference |
| `BSIM_ALREADY_REGISTERED` | Update the existing record, or explicitly delete it before re-registration |
| `BSIM_EXECUTABLE_CATEGORY_NOT_CONFIGURED` | Add the category first and match its case exactly |

For a full tool's errors and parameters, read `ghidra://docs/tools/{tool_name}`. For PostgreSQL build/start/ingestion failures, see [BSim operations](bsim-operations.md) (Japanese).

<a id="upgrading"></a>

## Upgrading older configurations

The Python distribution and CLI command are now named `mecha_ghidra`, matching the repository and MCP registration name. After updating the checkout, run `uv sync` to install the renamed package, then launch it with `uv run mecha_ghidra`. Replace `ghidra-mcp` with `mecha_ghidra` in existing launch commands and MCP client configurations, keeping the same options. The old command is no longer provided.

The Docker Compose service and default image are now `mecha_ghidra` and `mecha_ghidra:local`. Before updating an existing Docker setup, run `docker compose down` with the old configuration, without `-v`, then rebuild and start using the [Docker guide](docker.md). Keep the same checkout directory and Compose project name so the existing `ghidra-projects` volume is reused.

Version 0.1.5 adds Ghidra 12.1.3 support and matching native overlays. Choose the [correct artifact](usage.md#native-decompiler-artifacts), then update old tool calls using this table.

| Old name / option | Replacement |
| --- | --- |
| `--enable-shared-project-sync` | `--add-category shared_sync` |
| `search_functions_by_name` | `list_functions(filter=...)` |
| `list_classes` | `list_namespaces(classes_only=true)` |
| `reanalyze_program` | `analyze_program(force=true)` |
| `set_decompiler_comment` | `apply_edits`: `kind="set_comment", comment_type="pre"` |
| `set_disassembly_comment` | `apply_edits`: `kind="set_comment", comment_type="eol"` |
| `clear_struct` | `remove_struct_members(clear_all=true)` |
| `delete_struct` | `delete_data_type` |
| `reload_project_program` | `load_project_program` on the current domain path; check `reloaded=true` |
| `list_bsim_categories` | `get_bsim_database_status`: `categories` and `function_tags` |
| `bsim_set_target_metadata` | `bsim_register_target(categories=...)` for registration |
| `add_bookmark(format=...)` | Remove the unused `format` parameter |

### Response and behavior changes

- `get_function` returns signatures, parameters, and locals. `list_imports`, `list_exports`, `list_namespaces`, and `get_call_edges` return objects, not strings. Xrefs include the function at the other end.
- `set_function_prototype`, and `set_local_variable_type` accept function address or name. `search_bytes` accepts `??` wildcard bytes; `list_strings.filter` is case-insensitive.
- Checkout's omitted `exclusive` follows server policy. Commit supports `on_conflict="keep"`. Version diffs accept `include_details`, and BSim queries exclude self matches by default.
- New analysis/editing tools include `get_program_info`, undo/redo, export, comment reading, symbol search, label creation, enum editing, and C declaration parsing. BSim adds match-name application, signature/name updates, and executable deletion; see [tools](tools.md).
- `pull_project_program` declares its returned `checked_out` field, preventing a completed pull from failing output validation. BSim duplicate registration returns `BSIM_ALREADY_REGISTERED`; a refused exclusive checkout returns `CHECKOUT_UNAVAILABLE`.
- Conflict policies and clear modes are enumerated in schemas, and numeric bounds are published. Refresh cached client schemas after upgrading.

Version 0.1.4 moved to MCP 2.x (`mcp>=2.1.1,<3`) and worker-thread tool execution. For integration changes, follow the [development checks](development.md).

## Report a reproducible problem

Include the git revision or package version, OS/CPU, Ghidra and Java versions, transport, redacted startup arguments, tool name/arguments, error code, and a minimal reproduction in [GitHub Issues](https://github.com/ghidra-user-jp/mecha_ghidra/issues). Distinguish a server/tool error from a client timeout, and include the relevant server log excerpt without passwords or private sample data.
