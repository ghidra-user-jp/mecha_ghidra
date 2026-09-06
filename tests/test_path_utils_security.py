from __future__ import annotations

from ghidra_headless.session import path_utils


def test_read_prp_basic_info_rejects_doctype(tmp_path):
    prp_path = tmp_path / "unsafe.prp"
    prp_path.write_text(
        """<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<FILE_INFO>
  <BASIC_INFO>
    <STATE NAME="CONTENT_TYPE" TYPE="string" VALUE="Program" />
  </BASIC_INFO>
</FILE_INFO>
""",
        encoding="utf-8",
    )

    assert path_utils._read_prp_basic_info(prp_path) is None
