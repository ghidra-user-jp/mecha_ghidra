[English](configuration.md) | [日本語](configuration.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Configuration

Server options are passed to `uv run ghidra-mcp`. Run `uv run ghidra-mcp --help` for the complete CLI reference. This page covers [transports](#transports), [targets](#targets), [file access](#file-access), [tool exposure](#tool-exposure), and [large results](#large-results).

<a id="transports"></a>

## Transports and authentication

| Option | Default | Purpose |
| --- | --- | --- |
| `--transport` | `stdio` | `stdio`, `http` (alias `streamable-http`), or legacy `sse` |
| `--mcp-host` | `127.0.0.1` | HTTP/SSE bind address |
| `--mcp-port` | `8081` | HTTP/SSE port |
| `--mcp-path` | `/mcp` | Streamable HTTP endpoint path |
| `--ghidra-path` | `GHIDRA_INSTALL_DIR` | Ghidra installation |
| `--log-level` | `INFO` | Server logging level |

For a local HTTP deployment, use the [bounded-path startup example](usage.md#local-setup). The MCP endpoint has no built-in client authentication. Ghidra Server and BSim passwords authenticate those backends; they do not authenticate MCP clients.

A wildcard bind (`0.0.0.0` or `::`) keeps DNS-rebinding protection enabled and accepts only loopback Host/Origin values by default. For deliberate remote access, bind a fixed IP/hostname matching the client-facing Host, and provide TLS, authentication, and access controls in the deployment. Docker publishes the port on host loopback by default.

In stdio mode, JVM `System.out` is redirected to stderr after startup to keep Ghidra output out of the JSON-RPC stream.

<a id="targets"></a>

## Targets and concurrent calls

`--project-location`, optional `--project-name`, and `--target-name` (default `default`) define the initial target. `--domain-path /folder/program` opens a program at startup; omit it to register only project metadata. At least one project or `--session` is required.

To register multiple targets at startup, repeat `--session`. These examples point to existing projects:

```bash
uv run ghidra-mcp \
  --session 'name=sample,project_location=/work/sample.gpr,domain_path=/sample.bin' \
  --session 'name=reference,project_location=/work/reference.gpr,domain_path=/reference.bin' \
  --transport stdio
```

Session definitions are comma-separated `key=value` pairs, not JSON; values cannot contain commas. Supported keys are `name`, `project_location`, optional `project_name`, and optional `domain_path`. See [project concepts](usage.md#project-concepts) for the different path types.

`--lock-timeout-seconds` defaults to `30`. Calls competing for a busy target wait for its lock and return retryable `LOCK_TIMEOUT` when that wait expires. This is a queue timeout, not an analysis execution limit. Set MCP client timeouts separately.

<a id="file-access"></a>

## File access

Paths refer to the server filesystem. In Docker, use container paths.

| Repeatable option | Controls |
| --- | --- |
| `--allowed-import-root DIR` | Files read by `import_program` |
| `--allowed-project-root DIR` | Projects created or opened through project/session tools, including BSim remote caches |
| `--allowed-export-root DIR` | Files written by `export_program` |

Paths are resolved before validation, including symlinks. Export paths are normalized once and that validated path is passed to the writer. A request outside its configured roots fails with `PATH_NOT_ALLOWED`. If a root type is omitted, that operation is unrestricted by this path policy; filesystem permissions still apply.

Configure all three root types for HTTP/SSE deployments. The startup warning is emitted only when **none** of the three are configured, so absence of a warning does not prove that all operations are restricted. These roots are path controls, not a complete sandbox.

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
| `category` | The seven categories above |
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

<a id="large-results"></a>

## Large results

By default, a successful large result is replaced by a preview and `result_id` **only when the whole replacement is smaller**. Full data is retained in a process-local LRU cache when it fits. Identical payloads reuse a content-addressed ID.

| Option | Default | Meaning |
| --- | --- | --- |
| `--large-result-mode` | `resource` | Conditional compaction; `inline` always returns the full result |
| `--large-result-threshold-chars` | `12000` | Consider larger successful results for compaction |
| `--large-result-preview-chars` | `4000` | Preview upper bound, reduced as needed |
| `--result-cache-max-entries` | `512` | Maximum cached entries |
| `--result-cache-max-bytes` | `134217728` (128 MiB) | UTF-8 payload and retained metadata budget |
| `--tool-description-mode` | `full` | `full`, `short`, or `none` descriptions in `tools/list` |

Retrieve stored data with `read_result(result_id, offset_chars, limit_chars)` until `has_more=false`, or use `resources/read` on `ghidra://results/{result_id}`. `limit_chars` defaults to one third of the compaction threshold. `read_result` and `search_result` are available in resource mode; full tool documentation resources remain available regardless of description verbosity.

`search_result(result_id, pattern, context_chars, max_matches)` searches with a regular expression. It returns at most 100 snippets with up to 2,000 context characters per side. Match offsets can be passed directly to `read_result`. `max_matches=0` counts without snippets, up to the 10,000-match scan cap; inspect `scan_truncated` before treating the count as complete.

Text previews end at a line boundary where possible. JSON previews contain complete items/entries when they fit; a fallback raw prefix may not be valid JSON. The preview budget is an upper bound: lists/maps use up to a quarter, full `CallToolResult` payloads up to half, and response overhead may reduce it further. Errors, empty lists, and results at or below the threshold remain inline.

If a result cannot fit in the cache, the tool operation still succeeds. The response may contain `RESULT_TOO_LARGE` with no retrievable full payload if that notice is smaller; otherwise the smaller inline result is preserved. Evicted results and server restarts also make stored IDs unavailable. **Do not automatically repeat a mutating tool call to retrieve its output.** For a known-safe read, narrow the query or adjust the cache before explicitly rerunning it.
