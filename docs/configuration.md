[English](configuration.md) | [日本語](configuration.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Configuration

Server options are passed to `uv run mecha_ghidra`. Run `uv run mecha_ghidra --help` for the complete CLI reference. This page covers [transports](#transports), [targets](#targets), [file access](#file-access), [tool exposure](#tool-exposure), and [large results](#large-results).

<a id="transports"></a>

## Transports and authentication

| Option | Default | Purpose |
| --- | --- | --- |
| `--transport` | `stdio` | `stdio` or `http` (alias `streamable-http`) |
| `--mcp-host` | `127.0.0.1` | HTTP bind address |
| `--mcp-port` | `8081` | HTTP port |
| `--mcp-path` | `/mcp` | Streamable HTTP endpoint path |
| `--ghidra-path` | `GHIDRA_INSTALL_DIR` | Ghidra installation |
| `--log-level` | `INFO` | Server logging level |

Streamable HTTP (`--transport http` or `streamable-http`) always uses the [official Python SDK's recommended configuration](https://github.com/modelcontextprotocol/python-sdk/blob/main/examples/snippets/servers/streamable_config.py): `stateless_http=True` and `json_response=True`. Requests receive JSON responses without an MCP session ID. There is no stateful compatibility setting. Ghidra targets, program changes and the result cache remain in the server process across HTTP requests; `--session` configures Ghidra targets, not HTTP sessions. Continue using the same `target` and returned `result_id` values. Restarting the process clears the result cache, and the normal cache limits still apply.

HTTP responses contain the final result, without SSE progress or keepalive events. Allow enough time for analysis in the client and any reverse proxy. A lost response does not prove that a change failed; inspect the program state before retrying a modifying operation. Protocol-level statelessness does not share Ghidra state or cached results between server processes.

For a local HTTP deployment, use the [bounded-path startup example](usage.md#local-setup). The MCP endpoint has no built-in client authentication. Ghidra Server and BSim passwords authenticate those backends; they do not authenticate MCP clients.

A wildcard bind (`0.0.0.0` or `::`) keeps DNS-rebinding protection enabled and accepts only loopback Host/Origin values by default. For deliberate remote access, bind a fixed IP/hostname matching the client-facing Host, and provide TLS, authentication, and access controls in the deployment. Docker publishes the port on host loopback by default.

In stdio mode, JVM `System.out` is redirected to stderr after startup to keep Ghidra output out of the JSON-RPC stream.

<a id="targets"></a>

## Targets and concurrent calls

`--project-location`, optional `--project-name`, and `--target-name` (default `default`) define the initial target. `--domain-path /folder/program` opens a program at startup; omit it to register only project metadata. At least one project or `--session` is required.

To register multiple targets at startup, repeat `--session`. These examples point to existing projects:

```bash
uv run mecha_ghidra \
  --session 'name=sample,project_location=/work/sample.gpr,domain_path=/sample.bin' \
  --session 'name=reference,project_location=/work/reference.gpr,domain_path=/reference.bin' \
  --transport stdio
```

Session definitions are comma-separated `key=value` pairs, not JSON; values cannot contain commas. Supported keys are `name`, `project_location`, optional `project_name`, and optional `domain_path`. See [project concepts](usage.md#project-concepts) for the different path types.

`--lock-timeout-seconds` defaults to `30`. Calls competing for a busy target wait for its lock and return retryable `LOCK_TIMEOUT` when that wait expires. This is a queue timeout, not an analysis execution limit. Set MCP client timeouts separately. The same wait bounds every other call while `run_script` executes: a script holds the process-wide script barrier, and calls that cannot enter within the timeout return retryable `LOCK_TIMEOUT` (with `script_state` and `waited_seconds` in the details) instead of waiting for the script; shutdown likewise stops waiting for a script after this timeout. While a script is merely *queued* behind running operations, other calls are held for at most about one second at a time (a long read on any target lets new reads through), so a pending script never blocks the server.

`--script-queue-timeout-seconds` defaults to `300`. It is how long `run_script` waits for in-flight operations to finish before the script starts; a run that cannot start in time returns retryable `LOCK_TIMEOUT` without executing. It is separate from `--lock-timeout-seconds` because a requested script run should outwait a running analysis rather than fail after 30 seconds.

<a id="file-access"></a>

## File access

Paths refer to the server filesystem. In Docker, use container paths.

| Repeatable option | Controls |
| --- | --- |
| `--allowed-import-root DIR` | Files read by `import_program` |
| `--allowed-project-root DIR` | Projects created or opened through project/session tools, including BSim remote caches |
| `--allowed-export-root DIR` | Files written by `export_program` |

Paths are resolved before validation, including symlinks. Export paths are normalized once and that validated path is passed to the writer. A request outside its configured roots fails with `PATH_NOT_ALLOWED`. If a root type is omitted, that operation is unrestricted by this path policy; filesystem permissions still apply.

Configure all three root types for HTTP deployments. The startup warning is emitted only when **none** of the three are configured, so absence of a warning does not prove that all operations are restricted. These roots are path controls, not a complete sandbox.

<a id="tool-exposure"></a>

## Tool exposure

| Profile | Included tools |
| --- | --- |
| `default` | `core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops` |
| `readonly` | The default categories, limited to the `read_only` safety tag |
| `full` | All categories, including `shared_sync` and `bsim` |

Omitting profile flags selects `default`. Add optional categories with `--add-category shared_sync` or `--add-category bsim`.

The `readonly` profile filters exposed tools. It does not mount projects read-only or prevent analysis/saving during program loading. Use a historical version for immutable version inspection; see [shared projects](shared-projects.md#history).

Each tool has three tags:

| Tag | Values |
| --- | --- |
| `category` | The seven categories above, plus `scripts` (see [script execution](#scripts)) |
| `safety` | `read_only`, `write`, `destructive_write` |
| `operation_level` | `basic`, `standard`, `advanced` |

Filtering order:

1. Select a profile. `--allow-category` replaces its categories; `--add-category` extends them.
2. Apply `--allow-safety` and `--allow-operation-level`. Repeated values of one allow flag are OR; different tag types combine with AND.
3. Add explicit `--enable-tool` names.
4. Remove `--disable-tool` names last. Disabling always wins.

Append these options to your normal startup command:

| Intent | Options |
| --- | --- |
| Default tools plus shared operations | `--add-category shared_sync` |
| Read-only tools from every category | `--tool-profile full --allow-safety read_only` |
| Readonly profile plus batch annotations | `--tool-profile readonly --enable-tool apply_edits` |
| Exclude byte patching | `--disable-tool set_bytes` |

The exact tool arguments and error codes are exposed in `tools/list` and MCP resources `ghidra://docs/tools` / `ghidra://docs/tools/{tool_name}`. See the [tool reference](tools.md) for an overview. The removed `--enable-shared-project-sync` flag is covered in [upgrades](troubleshooting.md#upgrading).

`tools/list` publishes `inputSchema` and `outputSchema` for every exposed tool. Ordinary values and data from `read_result`, `search_result`, and `batch_read` appear in `structuredContent.result`; `content` retains human-readable text. Arrays, strings, and null use the same envelope. For ordinary tools, compaction metadata such as `result_id`, and `error`, remain at the top level of `structuredContent`. Batch retrieval metadata stays inside the batch data at `structuredContent.result`. The advertised schema covers these variants and is validated before delivery. Tool documentation keeps the logical value schema in `output_schema` and the wire data schema in `structured_output_schema`.

Retrieval budgets of `max(threshold, 1024)` include both `content` and `structuredContent` in the tool response. SDK server information and outer JSON-RPC framing are excluded. A page may contain fewer characters or items now that structured output also fits the budget. `batch_read.max_output_chars` instead bounds the response JSON text alone (the `content` text, which `structuredContent` duplicates), as the [tool reference](tools.md#batch-read) states. Follow `has_more`, `next_offset_chars`, or `next_cursor` to continue.

<a id="scripts"></a>

## Script execution

Ghidra scripts (Java, Jython, PyGhidra) are arbitrary code running with the server's OS privileges. The `scripts` tools are exposed like every other category (`--tool-profile full`, or `--add-category scripts` on top of another profile; the default and readonly profiles do not include them).

`run_script` takes the script text directly (`source`), so a client such as an AI assistant can write a script, run it, read the diagnostics and try again. Scripts run inside the server JVM against the loaded program, the way the Ghidra Script Manager runs them, wrapped in a transaction: on success the changes are committed, on an exception or timeout they are rolled back. The result reports `transaction_outcome` (`committed`, `unchanged`, `rolled_back`, `unknown`) read after the transaction ended, plus captured `stdout` / `stderr` and, for Java, compiler diagnostics. A script that leaks a transaction or leaves work running makes the program state unverifiable: the target is quarantined (`TARGET_EXECUTION_INVALID`, mutating tools refused) until `close_session(discard_changes=true)` and a reload. Jython cancellation is cooperative only.

| Option | Effect |
| --- | --- |
| `--script-root [LABEL=]DIR` | Optional library of pre-made scripts (repeatable), addressed by `script_id` = `LABEL:file` through `list_scripts` / `get_script_info` (only the top-level files of a root are scripts, as in the Script Manager; subdirectories are copied but not listed). The labels `inline` and `probe` are reserved for the server's own staging directories and are rejected. Copied into a private per-process snapshot at startup and executed from that copy, so later edits to the original directory do not affect execution. Symlinks to files are copied as regular files; symlinks to directories are not followed. The word `bundled` adds Ghidra's own `ghidra_scripts` directories (`origin=bundled`) |

Roots containing `META-INF/MANIFEST.MF` are supported. Ghidra processes the manifest and its dependencies; load or compilation failures return diagnostics.

Script contents are not hashed or checked for integrity. `catalog_revision` is an opaque identifier generated for each catalog build. `expected_revision` checks whether the loaded program has changed since it was last inspected. A `run_script` request that waits longer than `--script-queue-timeout-seconds` for other operations returns `LOCK_TIMEOUT` without starting the script.

Fixed limits: `.py` scripts must carry an `@runtime Jython` or `@runtime PyGhidra` header (or `run_script` is given `runtime`), a `source` is at most 256 KiB, a root may hold at most 2000 files, and `timeout_seconds` is 300 by default and at most 3600. The timeout cancels through the script monitor, which is cooperative: a script that never calls `monitor.checkCancelled()` (or an equivalent) cannot be interrupted and holds the runtime-wide lock until it ends, so only a server restart stops it.

Runtimes: Java and the PyGhidra provider ship with Ghidra; install the Python dependency pinned by this project (see the [pinned PyGhidra snapshot](development.md#pyghidra-dependency-and-script-failures)). Jython is a Ghidra Extension: unzip `Extensions/Ghidra/ghidra_<version>_Jython.zip` into `Ghidra/Extensions/` and restart (the Docker image does this). Missing runtimes show as `available=false` in `list_scripts`. If the startup exception propagation check fails, all script runtimes become unavailable and execution returns `SCRIPT_RUNTIME_UNAVAILABLE`; other analysis tools remain usable.

Console output is captured per stream up to 64 KiB (`dropped_bytes` reports the rest). Use `println` / `printerr` in Java, `print` / `printerr` in PyGhidra, and `print` / `sys.stderr.write` in Jython, including nested scripts. Java `System.out` / `System.err` and CPython `sys.stdout.write` / `sys.stderr.write` bypass these per-script streams. Ghidra 12.1.4 does not pass script writers to a Jython child of a Jython parent; use the shared interpreter's Python output functions instead of `println` / `printerr` in that child.

<a id="large-results"></a>

## Large results

By default, a successful large result is replaced by a preview and `result_id` **only when the whole replacement is smaller**. Full data is retained in a process-local LRU cache when it fits. Identical payloads reuse a content-addressed ID.

| Option | Default | Meaning |
| --- | --- | --- |
| `--large-result-mode` | `resource` | Conditional compaction; `inline` always returns the full result |
| `--large-result-threshold-chars` | `12000` | Compaction threshold for successful results and anticipated domain errors |
| `--large-result-preview-chars` | `4000` | Preview upper bound, reduced as needed |
| `--result-cache-max-entries` | `512` | Maximum cached entries |
| `--result-cache-max-bytes` | `134217728` (128 MiB) | UTF-8 payload, metadata and JSON index budget |
| `--result-cache-max-memory-bytes` | `134217728` (128 MiB) | Accounted memory of retained strings, metadata and indexes (not process RSS) |
| `--tool-description-mode` | `full` | `full`, `short`, or `none` descriptions in `tools/list` |

Retrieve stored data with `read_result(result_id, offset_chars, limit_chars)` until `has_more=false`, or use `resources/read` on `ghidra://results/{result_id}`. `limit_chars` defaults to the compaction threshold; the returned slice is reduced so both result channels, including JSON escaping and metadata, fit the budget. `read_result` and `search_result` are available in resource mode; full tool documentation resources remain available regardless of description verbosity.

`search_result(result_id, pattern, context_chars, max_matches)` searches with a regular expression. It returns at most 100 snippets with up to 2,000 context characters per side. Match offsets can be passed directly to `read_result`. `max_matches=0` counts without snippets, up to the 10,000-match scan cap; inspect `scan_truncated` before treating the count as complete.

Text previews end at a line boundary where possible. JSON previews contain complete items/entries when they fit; a fallback raw prefix may not be valid JSON. The preview budget is an upper bound: lists/maps use up to a quarter, full `CallToolResult` payloads up to half, and response overhead may reduce it further. Empty lists and results at or below the threshold remain inline. Paged JSON previews include initial items and the original has_more/next_cursor. A preview_kind=summary is a synthetic view, not a raw prefix: use continue_offset_chars (zero for summaries) to read raw text.

If a result cannot fit in the cache, the tool operation still succeeds. The response may contain `RESULT_TOO_LARGE` with no retrievable full payload if that notice is smaller; otherwise the smaller inline result is preserved. Evicted results and server restarts also make stored IDs unavailable. **Do not automatically repeat a mutating tool call to retrieve its output.** For a known-safe read, narrow the query or adjust the cache before explicitly rerunning it.

Large anticipated domain errors also store full diagnostics when the replacement is smaller. isError=true, error codes and execution/transaction status are preserved. result_id retrieves the original error; result_unavailable=true means it did not fit the cache. Small errors and inline mode retain their previous shape.

Use `read_result(result_id, mode="json", path="/items", offset_items=0, limit_items=20, fields=["from", "to"])` to select array items and object fields. Supported paths are `""` (root array) and `"/items"`. Item and character offsets cannot be combined. Omitted fields selects all fields; an empty list projects empty objects. A lazy character index is cached and accounted within both budgets without retaining another full JSON object tree. An oversized item is skipped: `item_too_large=true` reports its `offset_chars`/`item_chars` for text mode, and `next_offset_items` advances past it so paging never stalls. Select fewer fields or read it as text.

For string data in a batch item, use `read_result(result_id, mode="text", path="/items/0/data", offset_chars=0, limit_chars=3000)` or `search_result(result_id, path="/items/0/data", pattern="decode")`. These character positions refer to the decoded string. Both tools return the selected path; keep it when following offsets or search cursors. Only `/items/<index>/data` is supported for string selection, and the selected serialized item is limited to 8,388,608 characters before decoding. Missing items and non-string data are errors. The decoded view is temporary; the existing array index remains charged to the cache. An empty path reads/searches the original serialized result.

`search_result(..., merge_context=true)` shares overlapping contexts; matches refer to context_index in the contexts array. The default false retains per-match context. count_mode="none" stops at the requested snippet count and marks an unconfirmed count with count_complete=false. Default "bounded" counts up to 10,000 matches. Counts apply from the current search start. Pass next_cursor with the same result_id/pattern/path to continue after returned matches, including matches omitted by response fitting. Zero-length matches advance correctly. Search time limits remain in force. Reverse regex supports only bounded searches from the beginning, without continuation cursors.

New disassemble cursors resume at the next instruction address, retain non-contiguous function ranges and avoid converting previous pages again. Legacy offset cursors remain accepted. Revision/query mismatches are rejected. Short description mode now uses explicit per-tool summaries; full descriptions remain available as resources and full remains the default.
