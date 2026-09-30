"""Which tools each backend publishes (spec §7.2, §7.3; G01 to G04), and the GUI argument refusals (§7.4)."""

from __future__ import annotations

import pytest

from ghidra_mcp.contracts.tool_spec import ToolCategoryTag, get_all_tool_specs
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation import cli
from ghidra_mcp.presentation.gui_policy import GuiArgumentPolicy

GUI_TOOLS = ("get_gui_context", "show_in_gui")
# Offered with the GUI backend only, outside the gui category (spec §7.2).
GUI_ONLY_TOOLS = ("rename_variable",)

# The default headless tool set before the GUI backend existed (base 9f4ca8e/6ca3a7b, recorded in Phase 0).
HEADLESS_DEFAULT = {
    "add_bookmark", "add_struct_members", "analyze_program", "apply_edits", "batch_read", "cancel_operation",
    "close_session", "close_session_and_remove_program", "create_enum", "create_function", "create_label",
    "create_project", "create_struct", "decompile_function", "delete_bookmark", "delete_data_type",
    "delete_function", "disassemble", "export_program", "get_bytes", "get_call_edges", "get_comments",
    "get_data_by_label", "get_data_type", "get_function", "get_operation", "get_program_info", "get_xrefs",
    "import_program", "list_bookmarks", "list_data_items", "list_data_types", "list_exports", "list_functions",
    "list_imports", "list_namespaces", "list_project_programs", "list_segments", "list_strings", "list_targets",
    "load_project_program", "open_program", "parse_c_declarations", "redo_program_change", "register_target",
    "remove_struct_members", "rename_data_type", "save_project_program", "search_bytes", "search_symbols",
    "set_bytes", "set_enum_values", "set_function_prototype", "set_global_data_type", "set_local_variable_type",
    "undo_program_change",
}  # fmt: skip


@pytest.fixture
def project(tmp_path):
    (tmp_path / "sample.gpr").write_text("")
    return tmp_path


def published(*argv: str) -> set[str]:
    return set(cli.resolve_tool_specs_from_args(cli.parse_args(list(argv))))


def gui(project, *argv: str) -> set[str]:
    return published(
        "--backend", "gui", "--transport", "http", "--project-location", str(project), "--project-name", "sample",
        *argv,
    )  # fmt: skip


def test_the_headless_default_is_unchanged():
    assert published() == HEADLESS_DEFAULT


@pytest.mark.parametrize("profile", ["default", "readonly", "full"])
def test_headless_publishes_the_canonical_specs_only(profile):
    """No GUI variant leaks into headless: the published specs are the very objects of the registry."""
    from ghidra_mcp.contracts.tool_spec import filter_tool_specs, get_tool_spec

    for name, spec in filter_tool_specs(profile=profile).items():
        assert spec is get_tool_spec(name), name


@pytest.mark.parametrize(
    "argv",
    [
        (),
        ("--tool-profile", "full"),
        ("--add-category", "gui"),
        ("--enable-tool", "show_in_gui"),
        ("--enable-tool", "rename_variable"),
        ("--allow-category", "symbol_comment_edit"),
    ],
)
def test_headless_never_publishes_the_gui_tools(argv):
    assert published(*argv).isdisjoint({*GUI_TOOLS, *GUI_ONLY_TOOLS})


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ((), {"get_gui_context", "show_in_gui"}),
        (("--tool-profile", "readonly"), {"get_gui_context"}),
        (("--tool-profile", "readonly", "--enable-tool", "show_in_gui"), {"get_gui_context", "show_in_gui"}),
        (("--allow-safety", "read_only"), {"get_gui_context"}),
        (("--allow-category", "function_analysis"), set()),
        (("--allow-category", "function_analysis", "--add-category", "gui"), {"get_gui_context", "show_in_gui"}),
        (("--enable-tool", "show_in_gui", "--disable-tool", "show_in_gui"), {"get_gui_context"}),
        (("--tool-profile", "full"), {"get_gui_context", "show_in_gui"}),
    ],
)
def test_the_gui_backend_follows_the_exposure_table(project, argv, expected):
    assert gui(project, *argv) & set(GUI_TOOLS) == expected


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ((), True),
        (("--tool-profile", "readonly"), False),
        (("--allow-category", "function_analysis"), False),
        (("--allow-category", "function_analysis", "--enable-tool", "rename_variable"), True),
        (("--disable-tool", "rename_variable"), False),
    ],
)
def test_the_gui_only_rename_variable_follows_its_category(project, argv, expected):
    """It is a symbol_comment_edit write tool like set_local_variable_type; only headless lacks it."""
    assert ("rename_variable" in gui(project, *argv)) is expected


# The U rows of spec §7.2, written out rather than read from the implementation's own tables.
SPEC_U_TOOLS = {"import_program", "analyze_program", "create_project", "close_session_and_remove_program"}
SPEC_U_CATEGORY_SIZES = {ToolCategoryTag.BSIM: 11, ToolCategoryTag.SHARED_SYNC: 10, ToolCategoryTag.SCRIPTS: 3}


def test_the_gui_backend_drops_what_it_cannot_run_whatever_the_flags(project):
    specs = get_all_tool_specs()
    by_category = {
        category: {name for name, spec in specs.items() if spec.category_tag is category}
        for category in SPEC_U_CATEGORY_SIZES
    }
    assert {category: len(names) for category, names in by_category.items()} == SPEC_U_CATEGORY_SIZES
    unsupported = SPEC_U_TOOLS.union(*by_category.values())
    assert gui(project, "--tool-profile", "full").isdisjoint(unsupported)
    assert "import_program" not in gui(project, "--enable-tool", "import_program")
    assert gui(project) == (HEADLESS_DEFAULT - SPEC_U_TOOLS) | set(GUI_TOOLS) | set(GUI_ONLY_TOOLS)


def test_asked_for_tools_the_backend_cannot_run_are_named_in_the_startup_log(project, caplog):
    args = cli.parse_args(
        ["--backend", "gui", "--transport", "http", "--project-location", str(project), "--project-name", "sample",
         "--enable-tool", "run_script"]
    )  # fmt: skip
    with caplog.at_level("WARNING"):
        cli._warn_tools_the_backend_cannot_run(args)
    assert "run_script" in caplog.text and "import_program" in caplog.text
    caplog.clear()
    with caplog.at_level("WARNING"):
        cli._warn_tools_the_backend_cannot_run(cli.parse_args(["--tool-profile", "full"]))
    assert caplog.text == ""


@pytest.mark.parametrize(
    ("argv", "named"),
    [
        (("--allow-category", "symbol_comment_edit"), False),
        (("--add-category", "symbol_comment_edit"), False),
        (("--enable-tool", "rename_variable"), True),
    ],
)
def test_headless_names_rename_variable_only_when_asked_for_by_name(caplog, argv, named):
    """The tool never existed for headless: its category does not ask for it there."""
    with caplog.at_level("WARNING"):
        cli._warn_tools_the_backend_cannot_run(cli.parse_args(list(argv)))
    assert ("rename_variable" in caplog.text) is named


@pytest.mark.parametrize(
    "flags",
    [("--tool-profile", "readonly"), ("--allow-category", "function_analysis"), ("--disable-tool", "import_program")],
)
def test_tools_the_flags_never_selected_are_not_named(project, caplog, flags):
    args = cli.parse_args(
        ["--backend", "gui", "--transport", "http", "--project-location", str(project), "--project-name", "sample",
         *flags]
    )  # fmt: skip
    with caplog.at_level("WARNING"):
        cli._warn_tools_the_backend_cannot_run(args)
    assert "import_program" not in caplog.text


class TestGuiArguments:
    """--backend gui refuses before anything starts (spec §4.1)."""

    def run(self, *argv: str) -> SystemExit:
        with pytest.raises(SystemExit) as raised:
            cli.parse_args(["--backend", "gui", *argv])
        return raised.value

    def test_stdio_is_a_relay_with_the_same_checks(self, project, capsys):
        """stdio relays to the project's runtime (spec §10.2); the project still has to exist."""
        args = cli.parse_args(["--backend", "gui", "--project-location", str(project / "sample.gpr")])
        assert args.transport == "stdio"
        self.run("--project-location", str(project), "--project-name", "missing")
        assert "missing.gpr not found" in capsys.readouterr().err

    def test_a_project_is_required_and_must_exist(self, project, capsys):
        self.run("--transport", "http")
        assert "--project-location" in capsys.readouterr().err
        self.run("--transport", "http", "--project-location", str(project), "--project-name", "missing")
        assert "missing.gpr not found" in capsys.readouterr().err

    def test_server_login_options_are_refused(self, project, capsys):
        self.run(
            "--transport", "http", "--project-location", str(project / "sample.gpr"), "--ghidra-server-user", "me"
        )  # fmt: skip
        assert "--ghidra-server-user" in capsys.readouterr().err

    def test_sessions_must_use_the_runtime_project(self, project, tmp_path_factory, capsys):
        other = tmp_path_factory.mktemp("other")
        (other / "other.gpr").write_text("")
        self.run(
            "--transport", "http", "--project-location", str(project / "sample.gpr"),
            "--session", f"name=second,project_location={other / 'other.gpr'},domain_path=/a",
        )  # fmt: skip
        assert "another project" in capsys.readouterr().err
        args = cli.parse_args(
            ["--backend", "gui", "--transport", "http", "--project-location", str(project / "sample.gpr"),
             "--session", f"name=second,project_location={project / 'sample.gpr'},domain_path=/a"]
        )  # fmt: skip
        assert args.backend == "gui"


class TestArgumentPolicy:
    @pytest.fixture
    def policy(self, project):
        from ghidra_headless.session.project_handle import ProjectHandle

        return GuiArgumentPolicy(
            project_key=ProjectHandle.make_key(str(project), "sample"),
            resolve_project_key=ProjectHandle.make_key,
        )

    def refused(self, policy, tool, arguments) -> DomainError:
        with pytest.raises(DomainError) as raised:
            policy(tool, arguments)
        assert raised.value.code is ErrorCode.GUI_UNSUPPORTED
        return raised.value

    def test_apply_edits_dry_run(self, policy):
        assert self.refused(policy, "apply_edits", {"dry_run": True, "edits": []}).details == {"reason": "dry_run"}

    def test_apply_edits_kinds_that_decompile(self, policy):
        error = self.refused(
            policy,
            "apply_edits",
            {"edits": [{"kind": "rename_function"}, {"kind": "set_local_variable_type"}, {"kind": "rename_variable"}]},
        )
        assert error.details == {
            "reason": "edit_kind_decompiles",
            "kinds": ["rename_variable", "set_local_variable_type"],
        }

    def test_the_decompiling_kinds_point_to_tools_the_gui_publishes(self, policy, project):
        error = self.refused(policy, "apply_edits", {"edits": [{"kind": "rename_variable"}]})
        for tool in ("rename_variable", "set_local_variable_type"):
            assert f"the {tool} tool" in error.hint
            assert tool in gui(project)

    def test_apply_edits_that_do_not_decompile_pass(self, policy):
        policy("apply_edits", {"edits": [{"kind": "rename_function"}, {"kind": "set_comment"}]})

    def test_past_versions_and_discarding_changes(self, policy):
        assert self.refused(policy, "load_project_program", {"version": 3}).details == {"reason": "version"}
        policy("load_project_program", {"version": None, "domain_path": "/a"})
        assert self.refused(policy, "close_session", {"discard_changes": True}).details == {"reason": "discard_changes"}
        policy("close_session", {"discard_changes": False})

    def test_only_the_runtime_project(self, policy, project, tmp_path_factory):
        other = tmp_path_factory.mktemp("other")
        (other / "other.gpr").write_text("")
        assert self.refused(policy, "open_program", {"project_location": str(other / "other.gpr")}).details == {
            "reason": "other_project"
        }
        policy("register_target", {"project_location": str(project / "sample.gpr")})

    def test_an_empty_location_is_another_project(self, policy):
        """ "" resolves to the working directory, which is not the runtime's project."""
        error = self.refused(policy, "register_target", {"project_location": "", "project_name": "other"})
        assert error.details == {"reason": "other_project"}

    @pytest.mark.parametrize("location", ["~no-such-user-for-mecha/x.gpr", "no-project-name-given"])
    def test_a_location_that_does_not_resolve_is_left_to_the_call(self, policy, location):
        policy("register_target", {"project_location": location})


@pytest.mark.parametrize(
    ("profile", "disabled"),
    [("default", ()), ("readonly", ()), ("full", ()), ("default", ("get_gui_context",)), ("default", ("show_in_gui",))],
)
@pytest.mark.parametrize("mode", ["resource", "inline"])
def test_gui_instructions_tell_when_to_use_the_gui_tools_within_budget(profile, disabled, mode):
    from ghidra_mcp.contracts.tool_spec import filter_tool_specs
    from ghidra_mcp.presentation.config import ToolPresentationConfig
    from ghidra_mcp.presentation.server_instructions import build_server_instructions

    specs = filter_tool_specs(profile=profile, backend="gui", disable_tools=disabled)
    text = build_server_instructions(specs=specs, config=ToolPresentationConfig(large_result_mode=mode))
    assert "Ghidra GUI" in text
    for tool in GUI_TOOLS:  # each tool is named exactly when it is published
        assert (tool in text) == (tool in specs), tool
    assert "analyze_program" not in text
    assert len(text.encode("utf-8")) <= 1900
    headless = build_server_instructions(specs=filter_tool_specs(profile=profile), config=ToolPresentationConfig())
    assert "Ghidra GUI" not in headless


def test_show_in_gui_takes_the_default_target_like_the_core_tools():
    """Spec §8.1: target defaults to "default"; registry tools elsewhere still require it."""
    from ghidra_mcp.presentation.tool_registry import public_arguments_model, public_input_schema

    specs = get_all_tool_specs()
    schema = public_input_schema(specs["show_in_gui"])
    assert schema["properties"]["target"]["default"] == "default"
    assert "target" not in schema.get("required", [])
    assert public_arguments_model(specs["show_in_gui"])(name="main").model_dump()["target"] == "default"
    assert "target" in public_input_schema(specs["load_project_program"])["required"]


@pytest.mark.parametrize("code", [ErrorCode.GUI_NAVIGATION_FAILED, ErrorCode.OPERATION_FAILED])
def test_a_show_in_gui_failure_says_the_program_is_unchanged(code):
    """Spec §8.5: show_in_gui changes only the view, so every failure leaves output_state absent."""
    from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool

    class Registry:
        def show_in_gui(self, target, **_kwargs):
            raise DomainError(code=code, message=f"{code.value}: moved nowhere", details={"target": target})

    with pytest.raises(RuntimeError) as raised:  # the presentation form of the DomainError
        dispatch_tool("show_in_gui", {"address": "00401000"}, "default", registry=Registry())
    assert raised.value.domain_error["code"] == code.value
    assert raised.value.domain_error["details"]["output_state"] == "absent"


def test_rename_variable_sends_the_command_the_keys_of_an_apply_edits_item():
    """The command is apply_edits' own primitive; the tool's public names map onto its keys."""
    from ghidra_mcp.contracts.tool_spec import filter_tool_specs
    from ghidra_mcp.presentation.tool_registry import build_tool_functions

    calls = []
    tools = build_tool_functions(
        specs=filter_tool_specs(backend="gui"),
        dispatcher_provider=lambda: lambda name, raw_args, target, **_: calls.append((name, raw_args, target)),
        registry_provider=lambda: None,
    )
    tools["rename_variable"](old_name="param_1", new_name="ctx", function_name="main")
    tools["rename_variable"](old_name="a", new_name="b", function_address="0x401000", target="second")
    assert calls == [
        ("rename_variable", {"oldName": "param_1", "newName": "ctx", "functionName": "main"}, "default"),
        ("rename_variable", {"oldName": "a", "newName": "b", "functionAddress": "0x401000"}, "second"),
    ]
