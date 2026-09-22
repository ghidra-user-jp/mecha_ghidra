"""Bounded, discriminated edit requests; no arbitrary command dispatch."""

from typing import Annotated, Literal, Union

from pydantic import Field, model_validator

from ghidra_headless.contracts.function_edits import validate_function_rename

from .tool_models import ToolInputModel

Address = Annotated[str, Field(min_length=1, max_length=256)]
Name = Annotated[str, Field(min_length=1, max_length=1024)]
TypeName = Annotated[str, Field(min_length=1, max_length=8192)]


class RenameFunctionEdit(ToolInputModel):
    kind: Literal["rename_function"]
    address: Address
    new_name: Name | None = Field(
        default=None, description="Simple function name; omitted/null keeps the current name."
    )
    namespace_path: Annotated[str, Field(max_length=4096)] | None = Field(
        default=None,
        description="Global-rooted namespace path (AI::crypto); omitted/null keeps the namespace, empty string uses Global.",
    )
    create_namespace: bool = Field(
        default=False, description="Create missing namespace parents; requires namespace_path."
    )

    @model_validator(mode="after")
    def validate_rename(self):
        validate_function_rename(self.new_name, self.namespace_path, self.create_namespace)
        return self


class RenameDataEdit(ToolInputModel):
    kind: Literal["rename_data"]
    address: Address
    new_name: Name


class RenameVariableEdit(ToolInputModel):
    kind: Literal["rename_variable"]
    function_address: Address
    old_name: Name
    new_name: Name


class SetPrototypeEdit(ToolInputModel):
    kind: Literal["set_function_prototype"]
    function_address: Address
    prototype: TypeName


class SetLocalTypeEdit(ToolInputModel):
    kind: Literal["set_local_variable_type"]
    function_address: Address
    variable_name: Name
    new_type: TypeName


class SetGlobalTypeEdit(ToolInputModel):
    kind: Literal["set_global_data_type"]
    address: Address
    data_type: TypeName
    # Batch edits use CHECK_FOR_SPACE. Destructive conflict clearing remains an
    # explicit option on the existing single-operation tool.
    length: Annotated[int, Field(ge=1, le=1048576)] | None = None


class SetCommentEdit(ToolInputModel):
    kind: Literal["set_comment"]
    address: Address
    comment: Annotated[str, Field(max_length=65536)]
    comment_type: Literal["pre", "eol", "post", "plate", "repeatable"]


Edit = Annotated[
    Union[
        RenameFunctionEdit,
        RenameDataEdit,
        RenameVariableEdit,
        SetPrototypeEdit,
        SetLocalTypeEdit,
        SetGlobalTypeEdit,
        SetCommentEdit,
    ],
    Field(discriminator="kind"),
]
Edits = Annotated[list[Edit], Field(min_length=1, max_length=100)]
