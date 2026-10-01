[English](usage.md) | [日本語](usage.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Getting started

Install Mecha Ghidra, connect an MCP client, and open your first program. The shell examples use Bash/zsh; replace `/absolute/path/...` with paths on the machine running the server. For a Ghidra-bundled environment, use the [Docker guide](docker.md).

## Documentation map

| I want to… | Read |
| --- | --- |
| Install and analyze a first binary | Continue on this page |
| Connect an AI assistant | [MCP clients](clients.md) |
| Change tool exposure, paths, or output size | [Configuration](configuration.md) |
| Find a tool | [Tool reference](tools.md) |
| Run a container | [Docker](docker.md) |
| Share analysis through Ghidra Server | [Shared projects](shared-projects.md) |
| Work on the same programs as a human in the Ghidra GUI | [Live sharing with the GUI](gui-live.md) |
| Search for similar functions | [BSim](bsim.md) |
| Resolve an error or update an old configuration | [Troubleshooting and upgrades](troubleshooting.md) |
| Change or release the code | [Development](development.md) |

<a id="requirements"></a>

## Requirements

| Component | Requirement |
| --- | --- |
| Python | 3.10 or newer |
| Package manager | [uv](https://docs.astral.sh/uv/getting-started/installation/) |
| Ghidra | A full installation, including native decompiler files for your OS/CPU |
| Java | The JDK required by that Ghidra distribution; Ghidra 12.1.x uses JDK 21 |
| MCP client | Streamable HTTP or stdio support |

The build scripts pin Ghidra 12.1.4 in [ghidra_release.env](../scripts/ghidra_release.env). Ghidra Server and a BSim database are optional.

<a id="native-decompiler-artifacts"></a>

### Native decompiler files

The upstream Ghidra 12.1.4 ZIP omits native decompiler directories for Linux ARM64 and both macOS architectures. Choose the matching assets from [Mecha Ghidra releases](https://github.com/ghidra-user-jp/mecha_ghidra/releases):

| Asset | Use |
| --- | --- |
| `ghidra_12.1.4_decompiler_natives_all.zip` | A complete Ghidra installation with the additional natives already installed |
| `ghidra_decompiler_natives_all.zip` | An overlay to extract into an existing Ghidra 12.1.4 installation |
| GitHub's `Source code` archives | Mecha Ghidra source code; not a Ghidra installation |

The overlay supplies matching `decompile` and `sleigh` files under `Ghidra/Features/Decompiler/os/{linux_arm_64,mac_arm_64,mac_x86_64}/`. Keep the native files and Ghidra version together. To build them yourself, see [native builds](development.md#native-builds).

<a id="local-setup"></a>

## 1. Install and start the server

```bash
git clone https://github.com/ghidra-user-jp/mecha_ghidra.git
cd mecha_ghidra
uv sync
```

Put a binary named `sample.bin` in the `samples` directory created below. It can be a recognized executable format such as PE, ELF, or Mach-O; raw binaries need explicit language/import settings from the tool schema.

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
mkdir -p projects samples exports

uv run mecha_ghidra \
  --project-location "$PWD/projects" \
  --project-name analysis \
  --transport http \
  --allowed-import-root "$PWD/samples" \
  --allowed-project-root "$PWD/projects" \
  --allowed-export-root "$PWD/exports"
```

This registers a target named `default` pointing to the future `projects/analysis.gpr`. It does not yet create the project or load a program. Keep the server running and complete the MCP calls below from a second application.

The server accepts MCP requests without waiting for Ghidra to start (the JVM and Ghidra initialization, and the program named by `--domain-path`). Connecting and listing the tools finish at once; only tool calls that use Ghidra wait for the startup to finish. The server log then reports how long it took (`Ghidra ready in ...`).

On PowerShell, set the installation path with `$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra"`; use PowerShell line continuation or put each shell command on one line.

## 2. Connect a client

Use Streamable HTTP at `http://127.0.0.1:8081/mcp`. See [client configuration](clients.md) for complete examples. Call `list_targets` to confirm that `default` is registered.

<a id="first-analysis"></a>

## 3. Create, import, and load

These are **MCP tool calls**, shown as a name followed by JSON arguments. They are not shell commands. Substitute the repository's absolute path for `/absolute/path/to/mecha_ghidra`.

Create the empty project once with `create_project`:

```json
{
  "project_location": "/absolute/path/to/mecha_ghidra/projects",
  "project_name": "analysis"
}
```

Import the file with `import_program`. The import runs as a background job: the call waits up to `wait_seconds` (default 20) for it and returns the job record. The job also runs Ghidra auto-analysis by default. Pass `analyze_imported=false` only when you do not need it: loading never analyzes, so the program stays unanalyzed until you run [`analyze_program`](#saving-and-analysis).

```json
{
  "target": "default",
  "binary_path": "/absolute/path/to/mecha_ghidra/samples/sample.bin"
}
```

While `state` is `queued` or `running`, call `get_operation` with the returned `operation_id`. It also waits up to `wait_seconds` for the job, so call it again at once until `state` is `succeeded` or `failed`. Use this tool for job status: `list_targets` answers at once while a job runs, but does not show jobs.

```json
{"operation_id": "<returned-operation-id>"}
```

On success, **`result.program`** is the project path, usually `/sample.bin`. Pass it to `load_project_program` as `domain_path`. When reading MCP `structuredContent` directly, the job record is inside the usual `result` envelope, so the path is `structuredContent.result.result.program`.

Import, analysis and script jobs share one queue and run one at a time in submission order; at most 16 wait, and a full queue answers `OPERATION_QUEUE_FULL` without accepting anything. `cancel_operation` cancels a queued or running job (see [long calls](#long-calls)); a cancelled job no longer takes a place in the queue. If a reply is lost, resending the same arguments while the job is queued or running returns that job instead of running it twice. Once a job is being cancelled, the same analysis or script sent again is a new job that runs after it, and the same import fails with a retryable `IMPORT_IN_PROGRESS` until the cancelled one ends, since it may still leave the program behind. To look a job up without resending, pass your own UUID as `request_id` and later query `get_operation` with `{"request_id":"<same-UUID>"}`. The same request ID with different arguments is rejected. Keep the input file unchanged until the job finishes.

For `failed`, `operation_error` keeps the error's `code`, `message` and `hint`, and `operation_error.details.output_state` says what the failure left in the project:

| `output_state` | Meaning | Next step |
| --- | --- | --- |
| `absent` | Nothing was written | Fix the cause and import again; `retryable: true` marks a transient cause such as a busy lock |
| `created` | The program exists in the project | Load it with `load_project_program`; this server process refuses another import of that name until it restarts |
| `uncertain` | Cleanup could not be confirmed | Inspect the project; this server process refuses further imports of that name |

An analysis job reports `absent` when its transaction was rolled back, `created` when a failure came after its commit, and `uncertain` when the failure could not be cleaned up after (`details.cleanup_error`).

Job records live in server memory only. Beyond 4,096 finished jobs the oldest are dropped, and all records are lost on restart, so `OPERATION_NOT_FOUND` is not proof the job never ran: inspect the project before submitting it again. When the server stops, it cancels a running analysis: an import deletes the half-analyzed program, and an analysis job rolls its changes back (`OPERATION_SHUTDOWN` with `output_state: absent`).

Load the successful program:

```json
{
  "target": "default",
  "domain_path": "/sample.bin"
}
```

The reply's `is_analyzed` is `true` because the import analyzed the program. Then call `list_functions` with `{"target":"default","limit":20}`. Choose an address from the response and pass it to `decompile_function` as `{"target":"default","address":"<function-address>"}`. You should receive C-like pseudocode, or a preview with instructions to retrieve a [large result](configuration.md#large-results).

On later starts, reuse the existing project. Skip creation and import, list its programs, then load one. `create_project` refuses an existing project unless `overwrite=true`; overwriting is unnecessary for ordinary startup.

<a id="project-concepts"></a>

## Project, program, and target

| Name | Meaning | Example |
| --- | --- | --- |
| Project location | Host directory containing a project, or an existing `.gpr` file | `/work/projects` or `/work/projects/analysis.gpr` |
| Project name | Name without `.gpr`; used with a directory | `analysis` |
| Domain path | Program path inside the project | `/samples/sample.bin` |
| Target | Name of a registered project/program in this server process | `default`, `reference` |

For `--project-name` and `project_name`, omit `.gpr`; names ending in it are rejected. To open an existing `.gpr` file, pass it as `project_location` and omit `project_name`. A `.gpr` file and its sibling `.rep` directory together form the local project.

`register_target` registers project metadata; `open_program` adds a target and opens a program; `load_project_program` loads or switches a program on an existing target. Use `list_targets` to inspect the available names. Most program tools accept `target`, with `default` used when it is omitted.

<a id="saving-and-analysis"></a>

## Saving and analysis

Call `save_project_program` after edits when you need an explicit save point. Switching programs or calling `close_session` also saves unsaved changes. Each program-editing tool call is a transaction; `undo_program_change` and `redo_program_change` operate on the current session's history, which is lost on reload. `get_program_info` reports analysis, unsaved changes, and undo availability.

Loading never analyzes. `load_project_program` and `open_program` open the program as it is and report `is_analyzed`. A program opened at startup with `--domain-path` is not analyzed either; `get_program_info` reports the same flag for it. When it is `false`, run `analyze_program` before listing functions or decompiling; with few functions found, most tools have little to show.

`analyze_program` runs as a background job like an import: the reply waits up to `wait_seconds`, then call `get_operation` until the job finishes. On success, `result` is `{"program": "/sample.bin", "analyzed": true, "forced": false}`; an analyzed program is left as is (`analyzed: false`) unless `force=true`. The analysis is not saved: it becomes unsaved changes, kept by `save_project_program`, a program switch or `close_session`.

| Situation | Result |
| --- | --- |
| The job runs | It holds the target and its project. Other calls there fail with `LOCK_TIMEOUT`; `details.operation_id` names the job to wait for |
| The target is reloaded, closed or switched to another program before the job starts | `SESSION_CHANGED`: nothing was analyzed. Submit the job again for the program now loaded |
| Another analysis of the same program with different arguments is queued or running | `ANALYSIS_IN_PROGRESS` with that job's `details.operation_id` |
| The analysis fails, or the server stops during it | The analysis is rolled back (`output_state: absent`). Only a failure after the analysis committed reports `created`: the changes are applied, unsaved |

A historical version opened read-only cannot be analyzed (`READ_ONLY_PROGRAM`), and a shared program needs a checkout first (`CHECKOUT_REQUIRED`).

Close a local project in the Ghidra GUI before opening that same `.gpr/.rep` in the server. For concurrent GUI and MCP work, use [separate local caches of a shared repository](shared-projects.md).

<a id="long-calls"></a>

## Long calls

No call keeps the client waiting for more than about 50 seconds, so it finishes inside the 60-second limit that many clients and proxies apply (Claude Code over HTTP among them).

- `import_program`, `analyze_program` and `run_script` are background jobs. Startup, admission (including waiting for an admission thread) and waiting for completion share the `wait_seconds` budget. With `wait_seconds=0`, admission has a 40-second deadline and the reply does not wait for completion. If admission expires, `LOCK_TIMEOUT` with `details.lock: admission` and `output_state: absent` means no job was accepted and none will start later; the same request can be retried. If admission already completed at the deadline, the reply returns that job's record. Accepted jobs run one at a time.
- Any other call still running after 40 seconds replies with `deferred: true` and a job record in `operation`, and keeps running on the server. Call `get_operation` with `operation.operation_id` for its outcome: `result` is exactly what the tool returns (with `source` beside it for a program tool), and `operation_error` is the error it would have returned; a `batch_read` in which no read succeeded keeps its whole result, every item's error included, in `operation_error.result`. Do not call the tool again, or it runs twice. Calls that finish within 40 seconds reply as before.
- At most 40 calls run at once, and waiting calls get freed slots in arrival order. A call that finds no free slot within those 40 seconds does not run and fails with a retryable `OPERATION_QUEUE_FULL` (`output_state: absent`); with a `request_id`, sending the same ID again runs it.
- A call that arrives while Ghidra is still starting waits for it at most 40 seconds as well, then fails with a retryable `LOCK_TIMEOUT`.
- A client that sends a `progressToken` (`_meta.progressToken`) with the call hears from it while it waits: a `notifications/progress` every second, whose `progress` is the seconds waited so far and whose `message` says what is running (`<tool>: running`, or `<job kind>: <job state>` while a job is waited for). There is no `total`. A call that finishes within a second sends nothing, and nothing follows the reply. Over HTTP such a reply arrives as an event stream ([transports](configuration.md#transports)); over stdio the notifications are lines before the reply.
- While a deferred call runs, calls that need its target or project fail with `LOCK_TIMEOUT`; `details.operation_id` names the call to wait for.
- `cancel_operation` stops a queued or running job. A job that has not started changing the program ends at once with `OPERATION_CANCELLED`; a running one rolls back at its next cancellation check. A deferred call cannot be cancelled.
- When the server stops, it cancels running jobs and waits for deferred calls before closing projects. SIGTERM, SIGINT (Ctrl+C) and SIGHUP (a closed terminal or ssh session) all stop it this way, and it exits with 128 plus the signal number. Signals that arrive during this cleanup, including while it waits for a startup step in progress, wait until the projects are closed; SIGKILL skips it.

If the client cancels an ordinary tool call while it is still waiting for an execution slot, the tool does not run. With a `request_id`, its record ends as `failed` with `OPERATION_CANCELLED` and `output_state: absent`; resending that ID returns the cancellation. Use a new ID to retry. A call that has already obtained its slot is treated by what it is:

- **A read** (a call that changes nothing, such as `decompile_function`, `search_bytes` or `batch_read`) is stopped through its Ghidra monitor, so it gives its locks back: a decompile stops, and a `batch_read` stops with the item it is on. A read cancelled while it still waits for its locks does not run once it gets them.
- **A write** that has obtained its slot always finishes.
- **A job**, and **a call that was deferred** (its request was answered already), go on to the end. `cancel_operation` stops a job.

Over stdio the client cancels with `notifications/cancelled`; over HTTP it closes its connection. With protocol 2026-07-28 the MCP Python SDK's client closes it, but with the earlier handshake it sends `notifications/cancelled`, which a stateless server cannot match to a request: such a read goes on to its end unless the client drops the connection.

The deferral applies only while `get_operation` is published, since it is the only way to read the outcome.
