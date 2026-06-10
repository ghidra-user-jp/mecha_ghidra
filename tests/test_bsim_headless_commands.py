from __future__ import annotations

from ghidra_headless.handlers.commands.read_only_bsim import _rows_to_result


class FakeDomainFile:
    def getPathname(self):
        return "/query_sample"


class FakeProgram:
    def getDomainFile(self):
        return FakeDomainFile()


class FakeContext:
    program = FakeProgram()


class FakeExecutableRecord:
    def __init__(self, *, md5: str, name: str) -> None:
        self._md5 = md5
        self._name = name

    def getMd5(self):
        return self._md5

    def getNameExec(self):
        return self._name

    def getRepository(self):
        return "ghidra:/tmp/bsim_project"

    def getURLString(self):
        return "ghidra:/tmp/bsim_project"

    def getPath(self):
        return "/matches"

    def isLibrary(self):
        return False

    def getAllCategories(self):
        return None


class FakeFunctionDescription:
    def __init__(self, *, address: int, name: str, record: FakeExecutableRecord | None = None) -> None:
        self._address = address
        self._name = name
        self._record = record

    def getAddress(self):
        return self._address

    def getFunctionName(self):
        return self._name

    def getExecutableRecord(self):
        return self._record


class FakeMatchRow:
    def __init__(self, *, md5: str, similarity: float, significance: float, address: int) -> None:
        self._matched = FakeFunctionDescription(
            address=address,
            name=f"match_{md5[:4]}",
            record=FakeExecutableRecord(md5=md5, name=f"{md5[:4]}.bin"),
        )
        self._similarity = similarity
        self._significance = significance

    def getOriginalFunctionDescription(self):
        return FakeFunctionDescription(address=0x401000, name="query_func")

    def getMatchFunctionDescription(self):
        return self._matched

    def getSimilarity(self):
        return self._similarity

    def getSignificance(self):
        return self._significance


def test_bsim_rows_are_versioned_and_stably_sorted_before_limit():
    rows = [
        FakeMatchRow(md5="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", similarity=0.8, significance=9.0, address=0x30),
        FakeMatchRow(md5="cccccccccccccccccccccccccccccccc", similarity=0.9, significance=1.0, address=0x20),
        FakeMatchRow(md5="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", similarity=0.9, significance=5.0, address=0x10),
    ]

    result = _rows_to_result(FakeContext(), {"query_target": "query", "max_results": 2}, rows)

    assert result["count"] == 2
    assert result["truncated"] is True
    assert [item["matched_ref"]["executable_md5"] for item in result["matches"]] == [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "cccccccccccccccccccccccccccccccc",
    ]
    assert result["matches"][0]["matched_ref"]["matched_ref_version"] == 1
