"""Derive a discriminated batch contract from the existing read input models."""

from typing import Annotated, Literal, Union

from pydantic import Field, create_model, model_validator

# ghidra_headless.contracts is the JVM-free part of the headless package; the
# layering test allows exactly this import so the schema and the core enforce
# the same rules.
from ghidra_headless.contracts.batch_read import BATCH_READ_TOOLS, validate_requests

from .tool_models import ToolInputModel

__all__ = ["BATCH_READ_TOOLS", "BatchInput", "batch_input_model"]


class BatchInput(ToolInputModel):
    @model_validator(mode="after")
    def check_requests(self):
        # The typed request models above fix the field shapes; the semantic
        # rules (required selectors, unique ids, the 2000-row page budget) run
        # once here and once more in the core for callers that bypass MCP.
        validate_requests([request.model_dump(exclude_none=True) for request in self.requests])
        return self


def batch_input_model(specs):
    variants = []
    for name in sorted(BATCH_READ_TOOLS):
        extra = (
            {"item_timeout_seconds": (Annotated[int, Field(ge=1, le=60)], 15)} if name == "decompile_function" else {}
        )
        variants.append(
            create_model(
                "Batch" + specs[name].input_model.__name__,
                __base__=ToolInputModel,
                id=(Annotated[str, Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")], ...),
                tool=(Literal[name], ...),
                arguments=(specs[name].input_model, ...),
                fields=(
                    Annotated[
                        list[Annotated[str, Field(min_length=1, max_length=128)]], Field(min_length=1, max_length=32)
                    ]
                    | None,
                    None,
                ),
                **extra,
            )
        )
    request_type = Annotated[Union[tuple(variants)], Field(discriminator="tool")]
    return create_model(
        "BatchReadInput",
        __base__=BatchInput,
        requests=(Annotated[list[request_type], Field(min_length=1, max_length=20)], ...),
        expected_revision=(Annotated[str, Field(max_length=128)] | None, None),
        timeout_seconds=(Annotated[int, Field(ge=1, le=60)], 10),
        max_output_chars=(Annotated[int, Field(ge=2048, le=12000)], 12000),
    )
