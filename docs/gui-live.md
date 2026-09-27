[English](gui-live.md) | [日本語](gui-live.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Live sharing with the Ghidra GUI

With `--backend gui`, Mecha Ghidra starts the Ghidra GUI in its own process and shares the project and programs the GUI has open with MCP clients. The AI's changes appear in the GUI as they happen, and a human's GUI edits are in the AI's next read. No Ghidra Server check-in, save or reload is needed in between.

This page covers [startup](#startup), [usage](#usage), [the GUI tools](#gui-tools), [writes](#writes), [saving and exiting](#save-and-exit), [what is not available](#limits) and [remaining risks](#risks).

<a id="startup"></a>

## Startup

The GUI backend needs a display (a logged-in macOS desktop, or an X display on Linux) and runs over HTTP only. The stdio transport is not available yet.

```bash
uv run mecha_ghidra --backend gui --transport http \
  --project-location /Users/me/analysis/project.gpr \
  --domain-path /sample.exe \
  --mcp-host 127.0.0.1 --mcp-port 8081 --mcp-path /mcp \
  --allowed-project-root /Users/me/analysis \
  --allowed-export-root /Users/me/analysis/exports
```

- `--project-location` must name an existing project. The GUI backend does not create projects.
- With `--domain-path`, the program opens in a CodeBrowser after startup and is bound to the default target.
- The server serves before Ghidra is up, as the headless backend does. Until the GUI is ready, a tool call returns `LOCK_TIMEOUT` with `details.lock="startup"` and the current step in `details.stage`. A dialog waiting for the human (the user agreement, for example) is listed in `details.modal_dialogs`.
- Without a usable display (no logged-in desktop on macOS; no `DISPLAY`, or one no X server answers, on Linux), or when another process holds the project's lock, the GUI does not start: tool calls return `STARTUP_FAILED` with `details.stage` set to `display` or `project_lock`, and the server exits. When a step after the GUI came up fails (the `--domain-path` program is missing, say), the GUI stays up for the human and every tool call keeps returning `STARTUP_FAILED` with that step in `details.stage`; exiting Ghidra ends the server.
- On macOS the application is named "Ghidra (Mecha)" (`-Dapple.awt.application.name`).

The GUI uses the person's normal Ghidra settings (window positions, tool layouts, the user agreement). Ghidra restores the tools and programs that were open at its last exit, as usual.

Configure MCP clients as for any HTTP server ([MCP clients](clients.md)).

<a id="usage"></a>

## Usage

A program the AI loads with `load_project_program` or `open_program` opens as a tab in the CodeBrowser. The human's current tab does not change (only a tool's first program becomes current). A program that is already open in the GUI is bound as it is, without a second tab.

The AI's targets do not follow the human's tab, window or cursor. After the human switches tabs, the AI's calls still act on the programs it loaded. When the human closes a tab, its target expires and later calls return `PROGRAM_NOT_OPEN` with `details.reason="closed_in_gui"`; load the program again with `load_project_program`. When the human closes this server's project or opens another one, every target of this server stops working and later calls return `SESSION_NOT_FOUND` with `details.reason="gui_project_closed"`. Reopening the same project does not bring the server back; exit Ghidra and start the server again. A running call holds the program until it ends, so it completes even if the tab closes meanwhile, and the program closes afterwards.

Disconnecting an MCP client leaves the GUI and the targets in the server. A restarted client that connects again continues with the same targets.

When an unanalyzed program becomes a tool's current program, Ghidra asks whether to analyze it. Mecha leaves the answer to the human: the load response and `get_gui_context` name the dialog in `modal_dialog`. Reads keep working while the dialog is open. When a load makes Ghidra ask first (to check out a file, to recover after a crash), the load waits for the human's answer; a call still running after 40 seconds replies `deferred: true` and its result comes from `get_operation` ([long calls](usage.md#long-calls)).

<a id="gui-tools"></a>

## GUI tools

The `gui` category has two tools, offered by the GUI backend only. The GUI backend also offers `rename_variable` (category `symbol_comment_edit`), because its `apply_edits` cannot batch variable renames (see [writes](#writes)).

| Tool | What it does |
| --- | --- |
| `get_gui_context` | Returns what the human sees (the CodeBrowsers, the active tool's program, location, function and selection) with the targets bound to that program and their revisions. While the human uses another application (the chat with the AI, for example) and Ghidra is in the background, it reports the CodeBrowser they used last. Changes neither the view nor any target |
| `show_in_gui` | Shows a target's program in the human's CodeBrowser and moves to `address` or to the function `name` if given. Changes the view only: no edit, save or analysis |

`show_in_gui` is meant for when the human asks to see something, or to point them at a result, not for routine steps of an analysis. An invalid address or name fails before the view changes. `GUI_NAVIGATION_FAILED` means the program was shown but the move did not happen. When showing the program brings up a dialog (the analysis prompt, say) and the move waits behind it, the call does not fail: `shown` and `navigated` are `null` where they could not be confirmed, and `modal_dialog` names the dialog.

To let the AI guide the view without writing, start with `--tool-profile readonly --enable-tool show_in_gui`. The usual [tool exposure](configuration.md#tool-exposure) rules apply; hiding the two GUI tools does not stop live sharing.

<a id="writes"></a>

## Writes

A Ghidra transaction started on any thread joins the transaction already open, and when one change in it fails and rolls back, everything that joined rolls back too. Because the human and the AI change the same program, the GUI backend writes as follows.

- Before a write starts, the backend checks for another open transaction (auto-analysis, the background work of a human's command). It waits, and if the transaction is still open after `--lock-timeout-seconds`, returns `LOCK_TIMEOUT` with `details.lock="program_transaction"` and the transaction's description in `details.transaction`, having changed nothing.
- The transaction runs on Swing's event thread, where the human's GUI edits run. A human edit never joins the AI's transaction, so a failed AI write does not roll back the human's edits (for background work, see [remaining risks](#risks)).
- The AI's transactions are named `Mecha: ...` (for example `Mecha: Apply annotation edits`), so its steps are recognizable in Ghidra's undo list.
- `undo_program_change` and `redo_program_change` step back only while the next step is a `Mecha: ` one. A human's step returns `GUI_UNSUPPORTED` with `details.reason="foreign_undo"` (or `foreign_redo`) and its name in `details.top_undo_name` (or `top_redo_name`).
- `apply_edits` runs the whole batch as one transaction on the event thread. Kinds whose before/after records decompile (`rename_variable`, `set_local_variable_type`) cannot be batched and return `GUI_UNSUPPORTED` with `details.reason="edit_kind_decompiles"`. Rename a variable and change its type with the standalone `rename_variable` and `set_local_variable_type` tools; only the GUI backend offers `rename_variable`. `dry_run=true` is refused too. With `atomic=false`, a later item that finds another transaction open fails alone with `LOCK_TIMEOUT` instead of joining it.
- `rename_variable` and `set_local_variable_type` return `SESSION_CHANGED` (retryable), having changed nothing, when the program changed after their decompile: they never write from a stale decompiler view.

A failed write's `output_state` means what it means with the headless backend.

<a id="save-and-exit"></a>

## Saving and exiting

Live sharing needs no saves. `save_project_program` saves the whole program as the GUI's File > Save does, including the human's unsaved changes; there is no "save only the AI's changes". Ghidra clears the undo history when it saves, the human's included, and a `.gzf` `export_program` may clear undo and redo history too. A program with nowhere to save to (read-only, or a versioned file that is not checked out) returns an error without opening a Save As dialog. A save and a `.gzf` export wait for other transactions to close, as writes do, and return `LOCK_TIMEOUT` without doing anything if they stay open: Ghidra would otherwise offer to roll that transaction back to save.

`close_session` only unbinds the target: the program stays open in the GUI, neither saved nor discarded. `discard_changes=true` is refused.

The human exits with File > Exit in the GUI. Ghidra and the Mecha server are one process, so exiting Ghidra ends the server too. Programs the AI opened or changed are in Ghidra's usual save prompt. SIGINT (Ctrl+C) or SIGTERM from a terminal starts the same exit, with the prompt if anything is unsaved; Cancel keeps Ghidra running. A SIGINT or SIGTERM while that prompt is up does not stack a second one. A signal that was already ignored when the server started stays ignored (SIGINT for a job a script started with `&`, SIGHUP under `nohup`); use SIGTERM then. SIGHUP does not close the GUI; it stops output to the terminal (this version writes no log file, so later log lines are not kept).

<a id="limits"></a>

## What is not available

The first GUI backend does not offer these tools.

| Tools | Why |
| --- | --- |
| `import_program`, `analyze_program` | Running analysis as the GUI's background work is not designed yet |
| `create_project`, `close_session_and_remove_program` | The GUI owns one project, and deleting its programs conflicts with that ownership |
| BSim, shared-project sync and script tools | The human versions files in the GUI; the script isolation does not fit the GUI |

`--tool-profile full` and `--enable-tool` do not bring them back; the startup log lists them. Ghidra Server credential options such as `--ghidra-server-user` are errors: Ghidra's own login dialog handles the server. `--bsim-*` and `--script-root` have no effect.

`version` on `load_project_program`, and another project on `open_program` or `register_target`, return `GUI_UNSUPPORTED`.

<a id="risks"></a>

## Remaining risks

While an AI transaction is open, work that runs off the event thread (auto-analysis, a tool's background commands) can still join it; this is how Ghidra's transactions work. Once joined, a failure of either change rolls both back. If the joined work is still running or has failed when the AI's write ends, the write does not report success: it returns an error with `output_state` `uncertain` or `absent`. Short write sections make this less likely but cannot rule it out. A human's GUI command runs follow-up background work right after it, so an AI write just after a human edit may wait briefly.

The GUI does not respond to the human while an AI write section runs on the event thread. Most writes are short: 100-edit `apply_edits` batches (comments, function names, prototypes) each took under 0.1 s. `parse_c_declarations` grows with its input and took about 1 s at the 1,000,000-character limit (14,029 structures; measured on macOS, 2026-09-26). Passing a large header in parts shortens each pause.

Revisions also move with human edits and auto-analysis, so `expected_revision` mismatches are more frequent than with the headless backend.
