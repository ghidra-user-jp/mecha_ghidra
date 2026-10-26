[English](troubleshooting.md) | [日本語](troubleshooting.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Troubleshooting and upgrades

Tool failures set MCP `isError: true`. A call to a tool the server does not publish (a misspelled name, or a tool hidden by the tool profile or filters) is different: no tool ran, so the reply is a JSON-RPC error `-32602` (`Unknown or unpublished tool`); check `tools/list` and the [tool exposure](configuration.md#tool-exposure) options. Domain errors retain `code`, `message`, `retryable`, `hint`, and `details` under `structuredContent.error` and in matching JSON text. Branch on stable codes and inspect partial completion in `details` before retrying. An argument the input schema refuses is `VALIDATION_ERROR` too, with the schema's reason in `structuredContent.error.message`. Batch-edit item failures use `status` and `results` in a normal response. Large-result availability is handled [separately](configuration.md#large-results).

## Startup and connection

| Symptom | Check / action |
| --- | --- |
| Ghidra cannot be found (`Ghidra installation directory does not exist` or `Failed to start the Ghidra JVM: ...`) | Set `GHIDRA_INSTALL_DIR` to the extracted distribution root (the directory holding `Ghidra/application.properties`), or pass `--ghidra-path`; configure it in the stdio client's environment. A wrong installation path is found before serving and ends with exit code 1. A JVM that will not start (for example, no JDK found) is only found after serving has begun: over stdio every tool call then returns `STARTUP_FAILED`, and an HTTP server exits with code 1 |
| The first tool call after connecting is slow | The server serves before Ghidra is up, and only tool calls wait for it to finish starting. The server log shows how long that took (`Ghidra ready in ...`). A call still waiting after `--lock-timeout-seconds` returns `LOCK_TIMEOUT` with `details.lock` set to `startup`; retry shortly |
| Native decompiler missing or not executable | Install matching `decompile` and `sleigh` files for the host OS/CPU; see [native artifacts](usage.md#native-decompiler-artifacts) |
| Project locked / already in use | Close that local project in the other process, or use a separate shared-project cache; do not delete active lock files |
| Invalid project name | Omit `.gpr` from `project_name`, or use an existing `.gpr` path as `project_location` without a name |
| Project not found on a fresh setup | Start with a project directory plus name, then call `create_project`; see [first analysis](usage.md#first-analysis) |
| No program loaded (`PROGRAM_NOT_OPEN`) | Call `list_project_programs` and `load_project_program`; target registration alone does not load a program |
| HTTP client cannot connect | Confirm transport, host, port, `/mcp` path, and server logs; the legacy `/sse` endpoint has been removed |
| Invalid Host/Origin after wildcard binding | Match the configured fixed host and client-facing address; see [transport settings](configuration.md#transports) |
| Client timeout on a long call | No call waits more than about 50 seconds: jobs (`import_program`, `analyze_program`, `run_script`) reply within `wait_seconds`, and any other call still running after 40 seconds replies `deferred: true`. Call `get_operation` with the returned `operation_id` rather than raising the timeout or repeating the call. A timeout below 50 seconds can still cut calls; see [long calls](usage.md#long-calls) |
| Few or no functions after loading | Loading never analyzes. When the load reports `is_analyzed: false`, run `analyze_program` and wait for the job |
| A tool is missing | Check the profile, category filters, and explicit enable/disable flags; reconnect/refresh the client's tool list after changing startup flags |
| `--backend gui` stops with an argument error | It needs `--project-location` naming an existing project. Ghidra Server credential options, and a `--session` in another project, are refused (see [live sharing with the GUI](gui-live.md#startup)) |
| A stdio client's `--backend gui` returns `STARTUP_FAILED` with `details.stage` `launch` | The runtime the relay started ended before it registered. `details.cause_message` has the last line of its log, `<key>.log` in the [registry directory](gui-live.md#registry). A missing `GHIDRA_INSTALL_DIR` (or `DISPLAY` on Linux) in the client's server configuration is a common cause: clients pass few environment variables |
| `--backend gui` returns `STARTUP_FAILED` with `details.stage` `display` | Start it where a display is available: a logged-in desktop on macOS, a `DISPLAY` that an X server answers on Linux. This is checked before the Ghidra GUI starts, so no window opens |
| `--backend gui` returns `STARTUP_FAILED` with `details.stage` `project_lock` | Another Ghidra or server has the project open (`details.cause_type` is `PROJECT_LOCKED`). Close the project there, then start again. Do not delete an active lock file |
| `--backend gui` does not finish starting | A dialog in `details.modal_dialogs` of the `LOCK_TIMEOUT` (the user agreement, for example) waits for the human. Answer it in the GUI; Mecha does not answer it for them |
| `--backend gui` keeps returning `STARTUP_FAILED` while the GUI is open | A step after the GUI came up failed (`details.stage` is `project_open`, `code_browser`, `default_session` and so on). The GUI stays up for the human. Check `message`, exit Ghidra, fix the configuration and start again |
| On Windows, a stdio client's `--backend gui` returns `RUNTIME_UNAVAILABLE` (`message` says `cannot be detached from this client's job object`) | The client started the server in a job object that ends its processes when the client exits (Codex and clients built on the MCP Python SDK do), so the relay did not start Ghidra (it would end with the client). Start `--backend gui --transport http` in a terminal first, then use the client (see [from a stdio client](gui-live.md#stdio)) |
| On Windows, Ghidra ended without the save prompt when the terminal was closed | Windows ends the processes of a closed terminal without asking. Exit Ghidra before closing the terminal, or use it from a stdio client, whose runtime runs apart from any terminal (see [saving and exiting](gui-live.md#save-and-exit)) |
| On a slow machine, a `--backend gui` call returns `LOCK_TIMEOUT` with `details.lock` `gui_event_thread` | The Ghidra GUI's thread stayed busy for more than 20 s. Nothing changed; wait a moment and call again |
| On Windows, `uv sync` fails building JPype (it needs Microsoft C++ Build Tools) | JPype 1.5.2 has no wheel for Python 3.14. Make the environment with Python 3.13 or older (`uv sync --python 3.13`) |

## Tool errors

| Code | Meaning / next step |
| --- | --- |
| `PATH_NOT_ALLOWED` | Use a path inside the corresponding allowed root, after symlink resolution |
| `NOT_FOUND` | The function, data type, variable, data symbol, bookmark, namespace or repository named in `message` does not exist; `hint` names the tool that finds it, such as `list_functions`, `list_data_types` or `list_namespaces` (or `create_namespace=true`) |
| `VALIDATION_ERROR` | `message` says which argument was refused and why (file paths show as `<path>`): the input schema, a C declaration that does not parse (`C_PARSE_FAILED`), a namespace path through something else (`INVALID_NAMESPACE_TYPE`), or an export path that exists or has no directory (`EXPORT_TARGET_EXISTS`, `EXPORT_DIRECTORY_MISSING`). Correct it and call again |
| `PROGRAM_NOT_OPEN` | The target has no program loaded: find one with `list_project_programs` and load it with `load_project_program`, or add one with `import_program`. With `details.reason` `closed_in_gui`, the human closed the program's tab in the Ghidra GUI; load it again with `load_project_program` |
| `TARGET_NOT_REGISTERED` | No target has that name: `list_targets` shows them, and `register_target` adds one |
| `STARTUP_FAILED` | The startup that runs after serving has begun (starting the JVM, checking the script runtimes, configuring Ghidra Server authentication, loading the startup programs) failed. `details.stage` names the step and `message` the cause, with host paths shown as `<path>`; the server log has the whole line. Retrying does not help: fix the configuration and restart the server |
| `LOCK_TIMEOUT` | Another call holds the target lock, or a `run_script` run is still executing. When `details.lock` is `startup`, Ghidra is still starting: retry shortly. When a background job or a deferred call holds it, `details.operation_id` names it: wait for it with `get_operation`, then retry. A job `cancel_operation` has already ended is not named, although its worker may hold the locks for up to `--lock-timeout-seconds` more; retry after that. `create_project` also returns it while other operations, such as a background import, are running (`details.lock` is `runtime`); retry after they finish. For `run_script`, `details.script_state` says whether a script is `running` or only `queued` (then `retry_after_seconds` applies). A `run_script` job does not fail with it: it keeps waiting (`phase: waiting_for_lock`) until it can start. With `--backend gui`, `details.lock` `program_transaction` means another transaction (`details.transaction`, auto-analysis for example) stayed open and nothing changed; `gui_event_thread` means the GUI's thread did not respond, with any dialog on screen in `details.modal_dialogs`. Retry after it ends |
| `SCRIPT_RUNTIME_UNAVAILABLE` | Check provider installation and the startup propagation-probe log. A failed probe disables all script languages; install the [pinned PyGhidra dependency](development.md#pyghidra-dependency-and-script-failures) and restart. Stock PyGhidra 3.1.0 fails this check |
| `RAW_LOADER_OPTION_UNAVAILABLE` | Ghidra could not resolve public BinaryLoader metadata for the selected language/compiler or requested option; check these values and the supported Ghidra version. `details.cause_message` names the option |
| `AMBIGUOUS_FUNCTION`, `AMBIGUOUS_DATA_TYPE` | Inspect `details.candidates`; use a function address/qualified name or a full type path |
| `SESSION_CHANGED` | Read current state and restart pagination or update the revision for edits. From an analysis or script job: the target was reloaded, closed or switched before the job started, and nothing ran; submit it again |
| `BSIM_MATCH_STALE` | The loaded program MD5, path, or function entry differs from the match; verify the original program and query result |
| `PROGRAM_NOT_ANALYZED` | Run `analyze_program` before local variable naming/type operations |
| `CHECKOUT_REQUIRED` | Check out the versioned shared file before editing |
| `CHECKOUT_UNAVAILABLE` | Inspect repository checkout status; another user may hold an exclusive checkout |
| `READ_ONLY_PROGRAM` | A historical version is loaded; load the current file to edit |
| `MERGE_REQUIRED` | Follow the [conflict workflow](shared-projects.md#conflicts); headless merging is unsupported |
| `JVM_NOT_HEADLESS`, `HEADLESS_UNSUPPORTED` | Check the [JVM startup rules](development.md); do not retry a display-dependent API in headless mode |
| `GUI_UNSUPPORTED` | The GUI backend does not handle this operation or argument, and nothing changed. `details.reason` says why (`dry_run`, `edit_kind_decompiles`, `version`, `discard_changes`, `other_project`, `foreign_undo`, `foreign_redo`, `import`, `version_control`, `delete_file`, `remove_program`). Use the alternative in `hint`, or do it in the Ghidra GUI (see [what is not available](gui-live.md#limits)) |
| `GUI_NAVIGATION_FAILED` | `show_in_gui` showed the program but could not move to the location. Check the address or name and call again |
| `RUNTIME_CONFIG_MISMATCH` | The project's GUI runtime runs with other settings than this client's (`details.differs`: `path_policy`, `targets`, `versions`; `details.missing_tools`: tools it does not publish). Start the client with the runtime's settings, or exit that Ghidra and start again ([stdio clients](gui-live.md#stdio)) |
| `RUNTIME_UNAVAILABLE` | The relay cannot reach the project's GUI runtime (it was killed, or Ghidra exited). With `details.outcome` `unknown` the call may have run: check the program in the GUI before sending a change again. The relay does not start the runtime again; start the client again |
| `SESSION_NOT_FOUND` with `details.reason` `gui_project_closed` | The human closed this server's project in the Ghidra GUI or opened another one. Reopening the same project does not bring this server back; exit Ghidra and start the server again |
| `BSIM_URL_REQUIRED`, `BSIM_URL_INVALID` | Supply a supported BSim URL |
| `BSIM_AUTHENTICATION_FAILED`, `BSIM_DATABASE_UNREACHABLE` | Check backend credentials and connectivity. The database's own report decides these: a refused login is `BSIM_AUTHENTICATION_FAILED`, not a retry. An unreachable database is retryable: a read-only BSim tool can be called again, and a write when its `output_state` is `absent` |
| `BSIM_DATABASE_INIT_FAILED` | The BSim database did not open for another reason, such as a database that does not exist or an H2 file another process holds; `message` has the database's own report. Create or free it (see [BSim operations](bsim-operations.md), in Japanese); a write reports `output_state: absent` |
| `IMPORT_IN_PROGRESS` | Another import is writing the same program name; follow `details.operation_id` with `get_operation`. With `retryable: true`, that import is being cancelled: send the import again once it ends |
| `ANALYSIS_IN_PROGRESS` | Another analysis of the same program with different arguments is queued or running; follow `details.operation_id` with `get_operation` |
| `IMPORT_OUTPUT_UNCERTAIN` | An earlier import of that name failed without confirmed cleanup; inspect `details.operation_id` and the project (`details.output_state` is `uncertain`). This server process refuses the name until it restarts |
| `OPERATION_QUEUE_FULL` | 16 jobs are already waiting, or all 40 tool call slots stayed busy for 40 seconds; nothing was accepted or run, so retry later (a `request_id` call can be resent with the same ID) |
| `REQUEST_ID_CONFLICT` | The `request_id` already identifies an earlier job or tool call with different arguments; send the intended arguments or a new UUID |
| `RESULT_DISCARDED` | A resend's first call succeeded, but its reply was dropped to bound server memory (`details.output_state` is `uncertain`). Do not send the call again: the program shows what it changed. A resend whose first call failed or never ran gets that call's error again instead |
| `OPERATION_NOT_FOUND` | This server process has no record of the job (it restarted, or the record was dropped after 4,096 later jobs); inspect the project before submitting the job again |
| `TARGET_REBOUND` | The target was registered to another project after the import was accepted; nothing was written, so import again |
| `OPERATION_CANCELLED` | `cancel_operation` stopped the job; `details.output_state` says what it left (`absent` when it had not started or rolled back) |
| `OPERATION_SHUTDOWN`, `OPERATION_WORKER_UNAVAILABLE`, `OPERATION_WORKER_FAILED` | The server is stopping, or its job worker failed; check `details.output_state` and the server log, then restart the server |
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

### Background jobs and loading

- `import_program` and `analyze_program` run as background jobs and return a job record. While `state` is `queued` or `running`, call `get_operation`; the former result is in `result` (`result.program` for an import). See [usage](usage.md#saving-and-analysis).
- `import_program` analyzes every format by default; pass `analyze_imported=false` to skip it.
- Loading never analyzes. `load_project_program` and `open_program` report `is_analyzed`; run `analyze_program` when it is `false`. Its result stays unsaved until `save_project_program`.
- `analyze_program` now requires `target`.
- New error codes come with the jobs: `OPERATION_QUEUE_FULL`, `OPERATION_SHUTDOWN`, `OPERATION_WORKER_UNAVAILABLE`, `OPERATION_WORKER_FAILED`, `OPERATION_NOT_FOUND`, `REQUEST_ID_CONFLICT`, `IMPORT_IN_PROGRESS`, `IMPORT_OUTPUT_UNCERTAIN`, `TARGET_REBOUND` and `ANALYSIS_IN_PROGRESS` (see the table above). A `LOCK_TIMEOUT` caused by a running job names it in `details.operation_id`.
- Docker Compose now allows 120 seconds to stop (`stop_grace_period`), so a cancelled analysis can be rolled back.
- `run_script` runs as a background job too and returns a job record: the script's summary is in `result`, a failure in `operation_error` with `details.output_state`. Resending the same arguments while it is pending returns the same job.
- Any other call still running after 40 seconds replies `deferred: true` with a job record and keeps running; `get_operation` returns its outcome. `get_operation` records therefore carry any tool name in `kind` and any JSON in `result`. See [long calls](usage.md#long-calls).
- `cancel_operation` is new and cancels a queued or running job (`OPERATION_CANCELLED`).
- `list_targets` no longer waits for target locks, so it answers at once while a job runs.
- SIGINT and SIGHUP now stop the server the way SIGTERM does: running jobs are cancelled and rolled back, projects are closed, and the exit code is 130 or 129. Before, SIGINT could leave a stdio server running or end it without cleanup, and SIGHUP, or any of these signals during the JVM's start, ended it without cleanup.
- BSim tools report a failure with `error.code`, the `BSIM_...` name its message starts with, and with `retryable`, which is true only for `BSIM_DATABASE_UNREACHABLE`. Some codes also carry a `hint`. The message text is unchanged, except that a database that does not open, without a connection or login failure, is now `BSIM_DATABASE_INIT_FAILED` for every BSim tool (before, each tool's own code, such as `BSIM_LIST_EXECUTABLES_FAILED`); before, the code was only in the text.
- Every tool declares all its hints. Write tools report `readOnlyHint: false`; `destructiveHint` is true for deletions, byte overwrites, repository operations and scripts, and `openWorldHint` only for BSim, shared-project and script tools. Clients that decide confirmations from these hints may now prompt less for ordinary edits.
- Every program write, and `bsim_apply_matches`, accepts `request_id`: a resend with the same one returns the first reply, marked `replayed: true`, instead of applying again (see [batch annotations](tools.md#symbol-comment-edit)). A write that failed without changing anything (`output_state: absent`) does not keep its `request_id`, unless it was cancelled: sending the same ID again runs it.
- A failed write reports `error.details.output_state` (`absent`, `created` or `uncertain`), and `retryable` is true only when nothing was left behind. A project or repository write reports `absent` when its error refused the call before any change, and `uncertain` otherwise. A write turned away while Ghidra starts, by its input schema or for a `request_id` used with other arguments (`REQUEST_ID_CONFLICT`), and a job the server refused to accept, report `absent`; an import refused with `IMPORT_OUTPUT_UNCERTAIN` reports `uncertain`. `cancel_operation` reports none when it refuses to cancel a job, since that job may have run. A resend whose first call succeeded but whose reply was dropped fails with `RESULT_DISCARDED`, and one whose first call failed, and kept the `request_id`, gets that error again; before, both had only `message`.
- Errors say more. A missing function, data type, variable or bookmark fails with `NOT_FOUND` (before, `OPERATION_FAILED`); a target with no program loaded fails with `PROGRAM_NOT_OPEN`, and an unknown target with `TARGET_NOT_REGISTERED` (both before, `SESSION_NOT_FOUND`). `NOT_FOUND` and `VALIDATION_ERROR` messages keep the reason, which fixed text used to replace, and `hint` names the next tool instead of `Check runtime state`. A Java exception inside Ghidra, such as a NullPointerException, is `OPERATION_FAILED`, no longer `VALIDATION_ERROR`. `PROGRAM_NOT_ANALYZED` and `RAW_LOADER_OPTION_UNAVAILABLE` are now codes of their own (before, `OPERATION_FAILED` and `IMPORT_FAILED`), with the cause in `details.cause_message`. An argument the input schema refuses now has `code` `VALIDATION_ERROR` and a `hint`; before, its error had only `message`.
- A reply's text content is compact JSON: a list is one text block with one item per line, instead of one indented block per item. `structuredContent` is unchanged.
- A failed BSim write reports `error.details.output_state` like any other write. `bsim_register_target` and `bsim_update_target_signatures` report `uncertain` once their database write has begun. `BSIM_DATABASE_UNREACHABLE` is retryable only while nothing was left behind, and a login the database refused is `BSIM_AUTHENTICATION_FAILED`.
- More headless codes have a public code of their own: `NAMESPACE_NOT_FOUND` and `REPOSITORY_NOT_FOUND` are `NOT_FOUND`; `C_PARSE_FAILED`, `INVALID_NAMESPACE_TYPE`, `EXPORT_TARGET_EXISTS` and `EXPORT_DIRECTORY_MISSING` are `VALIDATION_ERROR` (before, all `OPERATION_FAILED`). Items of `apply_edits` and `batch_read` keep their own codes; a `batch_read` item that failed inside Ghidra is `OPERATION_FAILED`, no longer `VALIDATION_ERROR`.
- A replayed error keeps its one text block, whose JSON now says `replayed: true`; a replayed stored-result notice keeps its two blocks. Before, both got an extra text block.
- `batch_read` replies no longer carry `source`: the batch names its `program` and `revision` itself. A deferred call's record now keeps `source` beside `result`.
- A call that finds all 40 execution slots busy for 40 seconds fails with a retryable `OPERATION_QUEUE_FULL` instead of waiting without limit, and a call that arrives while Ghidra starts waits at most 40 seconds.
- `cancel_operation` is published whenever a job tool is, unless disabled explicitly; before, a tag filter could publish `run_script` without it.
- `is_analyzed` is `null` when the flag could not be read after `open_program`, or after a `load_project_program` that reloaded the program its target already held; a new load whose flag cannot be read is rolled back and fails. `import_program` accepts `analyze_imported: null` as the default (`true`).
- `STARTUP_FAILED` shows host paths in its cause as `<path>`, as other causes do.
- `decompile_function`'s pseudocode starts with a comment line naming the function and its entry address, such as `/* entry @ 00401e46 */`.
- A program tool's reply carries `source` (`target`, `program`, `revision`) beside `result` in `structuredContent`, and as a last text block. Clients that compare `structuredContent` with `{"result": ...}` exactly must allow the extra key.
- `tools/list` is about half its former size: each tool's output schema keeps its full result shape but only a short form of the replies every tool shares (stored-result notices, deferred replies, errors). Their full shapes are in `ghidra://docs/tools/{tool_name}`. Replies are unchanged, and both forms validate them.
- The JVM starts with `-Xrs`, so it leaves those signals to the server. `kill -3` (SIGQUIT) now prints the Python threads' stacks instead of a Java thread dump; `jcmd <pid> Thread.print` still prints the Java threads.

## Report a reproducible problem

Include the git revision or package version, OS/CPU, Ghidra and Java versions, transport, redacted startup arguments, tool name/arguments, error code, and a minimal reproduction in [GitHub Issues](https://github.com/ghidra-user-jp/mecha_ghidra/issues). Distinguish a server/tool error from a client timeout, and include the relevant server log excerpt without passwords or private sample data.
