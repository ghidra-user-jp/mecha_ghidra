[English](shared-projects.md) | [日本語](shared-projects.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Shared projects with Ghidra Server

Use Ghidra Server when people and MCP clients need to share analysis results. Each GUI or MCP process uses its **own local project cache**, connected to the same repository. Changes are exchanged through checkout and check-in; a GUI view is refreshed by reloading the saved/shared state.

```text
Ghidra GUI → local cache A ─┐
                          ├→ Ghidra Server repository
Mecha Ghidra → local cache B ┘
```

Never open the same local `.gpr/.rep` bundle in two processes. `create_project` creates a local project; it does not create a Ghidra Server repository.

## Prepare the repository

Install and configure the server using the bundled `server/svrREADME.md` or the [official Ghidra Server guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/Common/server/svrREADME.md). A local-password setup uses `-a0` and `-u`; the repository directory is the last application argument in `server/server.conf`:

```text
wrapper.app.parameter.1=-a0
wrapper.app.parameter.2=-u
wrapper.app.parameter.3=${ghidra.repositories.dir}
```

Set the repository directory and service account for your machine before installing the service. For the Linux/macOS scripts, a typical administrative sequence is:

```bash
sudo "$GHIDRA_INSTALL_DIR/server/svrInstall"
sudo "$GHIDRA_INSTALL_DIR/server/svrAdmin" -add analyst
sudo "$GHIDRA_INSTALL_DIR/server/svrAdmin" -add mecha-ghidra
```

After later configuration changes, restart that service with `sudo "$GHIDRA_INSTALL_DIR/server/ghidraSvr" restart`. On Windows, follow the `.bat` service instructions in the official guide.

In the Ghidra GUI:

1. Select **File → New Project → Shared Project**, then connect to the server.
2. Log in with each newly created account and set its password. In local-password mode, an account created without an explicit password initially uses `changeme` and requires a password change.
3. Create/select a repository and grant the `mecha-ghidra` account Read/Write permission.
4. Create a separate local shared-project cache for MCP, then close that cache in the GUI before starting Mecha Ghidra.

<details>
<summary>Shared-project setup screenshots</summary>

![Choose Shared Project](https://github.com/user-attachments/assets/1091c615-1590-4a49-aa2c-7628d6efed70)
![Select the Ghidra Server](https://github.com/user-attachments/assets/0d1a0cef-fbee-4513-af18-3193a3529c2f)
![Log in](https://github.com/user-attachments/assets/e03718b4-89df-4a2b-8609-521a42dd1878)
![Change the initial password](https://github.com/user-attachments/assets/24da9ede-db7b-4ba2-8107-2fb7fe895968)
![Create the repository](https://github.com/user-attachments/assets/3da1693c-3dd7-4ba8-a6e6-95b4767cf95c)
![Configure repository access](https://github.com/user-attachments/assets/76ef63d5-de7a-48ca-8758-76b5157a98c3)
![Finish shared-project setup](https://github.com/user-attachments/assets/80a8aa7e-659b-4d8e-bf5f-65eea292dc7f)

</details>

## Start Mecha Ghidra

Set `GHIDRA_INSTALL_DIR` as in [local setup](usage.md#local-setup). Set `GHIDRA_SERVER_PASSWORD` in the server process environment, then point to the existing MCP cache:

```bash
uv run mecha_ghidra \
  --project-location /work/mcp-cache/shared.gpr \
  --transport stdio \
  --add-category shared_sync \
  --shared-sync-exclusive-checkout \
  --ghidra-server-user mecha-ghidra \
  --ghidra-server-password-env GHIDRA_SERVER_PASSWORD
```

Supply the username with exactly one of `--ghidra-server-password-env` or `--ghidra-server-password`. Missing/empty passwords and conflicting options fail startup. Prefer an environment variable to putting the password in process arguments. For HTTP, also apply the [transport and file-access settings](configuration.md).

## Edit and share a program

These are MCP operations. Use the target `default` unless you registered another name.

1. Call `list_project_programs`, then `get_project_sync_status(domain_path="/sample.bin")`.
2. For a versioned file, call `checkout_project_program(domain_path="/sample.bin")`. For a private file in a repository-connected project, use `add_project_program_to_version_control` before the versioned workflow.
3. Call `load_project_program(domain_path="/sample.bin")`, then edit with `apply_edits` to add names and comments.
4. Call `save_project_program` to save the local project, then `commit_project_program` to check changes into the repository. Inspect the returned `committed` value.
5. From the other local cache, obtain the latest repository state and reload the GUI program to see it. Use `pull_project_program` to follow the latest version from MCP.

Mutating tools on versioned shared files require a checkout (`CHECKOUT_REQUIRED`). `exclusive` omitted from checkout follows `--shared-sync-exclusive-checkout`. Exclusive checkout prevents another checkout while it is held, reducing conflicts that headless mode cannot merge. Checkout, commit, pull, and related operations close/reopen the loaded program when needed to release Ghidra's in-use constraints.

<a id="conflicts"></a>

## Resolve conflicts deliberately

Headless Ghidra does not resolve merge conflicts. Default operations stop rather than choosing which edits to lose.

| Operation | Result |
| --- | --- |
| Commit with the default `on_conflict="abort"` | `MERGE_REQUIRED` if the checkout needs a merge |
| Commit with `on_conflict="keep"` | Park local edits in a `.keep` copy; return `kept_program` and `committed=false`; the loaded target follows the kept copy |
| Commit with `on_conflict="discard"` | Drop conflicting local edits and follow the latest state; `committed=false` |
| Pull with `on_local_changes="discard"` | Drop a disposable stale checkout and follow the latest version |
| Pull requiring a merge without a disposable checkout | `UNSAFE_MERGE_REQUIRED` |

`status="ok"` on a keep/discard response does not mean a check-in happened. Check `committed`, `conflict_kept`, and `conflict_discarded`. To combine competing edits, resolve them in a GUI-capable Ghidra workflow.

<a id="history"></a>

## Inspect history

Use `get_version_history` and `get_version_diff(include_details=true)` to inspect changes. `load_project_program(domain_path="/sample.bin", version=N)` opens a past version read-only and reports `read_only=true`. Mutations fail with `READ_ONLY_PROGRAM`; sync operations do not retarget the pinned historical session. Load without `version` to return to the current file. Loading the already-held domain path reloads it and reports `reloaded=true`.

## Delete a shared file

`delete_shared_project_file` requires an explicit `domain_path` and `confirm` equal to its normalized path. The file must be unloaded with no active checkouts. Private files require `allow_private=true`.

Versioned deletion additionally requires `expected_latest_version` and `allow_non_atomic_versioned_delete=true`. Ghidra provides no atomic compare-and-delete operation, so exclude concurrent writers before using that opt-in. `terminate_project_program_checkout` is a separate administrative operation that requires an explicit checkout ID.
