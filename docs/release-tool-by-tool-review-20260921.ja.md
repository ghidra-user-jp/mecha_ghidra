# 公開80ツールの個別レビュー（2026-09-21）

対象は現在の作業ツリーのToolSpec 78件と、結果取得用のread_result / search_resultの2件。プロファイルで通常は非公開になる高度操作・BSim・共有同期・scriptsも含めた。内部専用のrename_function等はapply_editsの各操作として確認した。

各行は、公開引数と内部引数の対応、処理と出力、副作用・失敗時の状態、関連テストを個別に照合した記録。「確認済」はこの範囲で新たな不具合を特定しなかった意味であり、全環境・全入力の保証ではない。テスト群の成功件数を個別レビューの代わりにはしていない。

## 今回特定した問題

- **F1 / P2: BSimの関数別件数制限。** 自己一致除外用に1件多く検索した後、実際に自己一致を除外した場合だけ再制限していた。対象ProgramがDBに未登録の場合などにmatches_per_function=1でも2件返る。共通の_collect_matchesで常に上限を適用した。bsim_query / bsim_apply_matchesに影響。再現テストは修正前1 failed・8 passed。
- **F2 / P2: BSim significanceの誤った上限。** bsim_apply_matchesの公開入力だけ0〜1となっており、内部APIが受け付ける2.5等をMCP経由で使用できなかった。bsim_queryと共通の「有限・非負、上限なし」に統一。負数・非有限値を早期拒否する契約も揃えた。MCP call_tool境界で修正前4 failed・4 passed（内3件はqueryの境界検証位置の不一致で、サービス層では元から拒否）。
- **F3 / P2: 構造体offsetの暗黙変換。** create_struct / add_struct_membersが32.5を32、trueを1へ変換して異なる配置を確定していた。浮動小数・booleanを拒否し、従来の整数・整数文字列の扱いを保持。実Ghidraで修正前4 failed・2 passed。失敗前のmember追加もtransactionで戻ることを検証した。

## 個別確認

| # | ツール / 主な実装 | 個別確認内容 | 結論 | テスト参照 |
|---:|---|---|---|---|
| 1 | [list_targets](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:241) | 登録のみ・ロード済みの両状態、取得中のcloseとの競合、返却するdomain_pathを確認。 | 確認済 | L |
| 2 | [create_project](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:91) | .gpr名の正規化、既存.gpr/.repの保護、overwrite時の使用中判定、作成後closeを確認。 | 確認済 | L |
| 3 | [open_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:72) | 新規targetの作成、初回解析・保存、失敗時の旧binding復元とconsumer解放を確認。解析を伴うwriteとして説明されている。 | 確認済 | L |
| 4 | [register_target](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:209) | プログラムを開かずprojectを登録する動作、別projectにロード中のtargetとの衝突、再登録の扱いを確認。 | 確認済 | L |
| 5 | [close_session](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:570) | 通常の保存、discard時の未保存破棄、quarantine回復、close失敗時の状態保持を確認。projectの登録は残る。 | 確認済 | L |
| 6 | [close_session_and_remove_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:570) | remove_program=Trueの配線、versionedファイル拒否、closeとprivateファイル削除の順序を確認。 | 確認済 | L |
| 7 | [list_project_programs](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:294) | DomainFileの一覧と同期情報、project-only target、PROJECT_LOCKED時のmetadata snapshotの明示を確認。 | 確認済 | L |
| 8 | [import_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:485) | auto/rawの切替、BinaryLoaderの数値変換、entry bootstrap、重複名、後処理失敗のrollbackとpartial_importを確認。 | 確認済 | L |
| 9 | [load_project_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:336) | 同一プログラムの再open、切替前の保存、過去versionのread-only、別targetの所有、初期化失敗の復元を確認。 | 確認済 | L |
| 10 | [save_project_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:520) | 現在のdomain_pathとの一致、Program.isChangedによる保存判定、保存後のdirty/pending_syncの扱いを確認。 | 確認済 | L |
| 11 | [get_program_info](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/program_tools.py:27) | Program Informationの未登録optionを読み取りで作らないこと、revision、dirty、undo/redo、entry上限を確認。既存のGhidra hash属性を読むだけ。 | 確認済 | P |
| 12 | [undo_program_change](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/program_tools.py:180) | count=1..100、履歴なしのnoop、実際のundo件数、decompilerとdirty状態の追従を確認。履歴はreloadで消える。 | 確認済 | P |
| 13 | [redo_program_change](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/program_tools.py:197) | redo件数、履歴枯渇時の停止、返却する残り履歴、undo後の状態復元を確認。 | 確認済 | P |
| 14 | [export_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/program_tools.py:226) | 許可rootで解決したパスをそのまま使用、overwrite/親ディレクトリ、exporter失敗の伝播を確認。gzfは保存済み状態を出力する仕様。 | 確認済 | P |
| 15 | [list_scripts](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/script_service.py:202) | 実行せずcatalogを列挙、runtime/category/originで絞込、offset/limit、bundled公開設定とavailabilityを確認。 | 確認済 | S |
| 16 | [get_script_info](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/script_service.py:238) | 完全ID・一意な短名・曖昧名の扱い、snapshotからのsource取得、サイズ超過時のsource_truncatedを確認。 | 確認済 | S |
| 17 | [run_script](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/script_service.py:323) | sourceとIDの排他、runtime判定、args/timeout/revision、Java/Jython/PyGhidra例外、transaction、残存thread、inline後始末を確認。timeoutは協調キャンセル。 | 確認済 | S |
| 18 | [get_bsim_database_status](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/bsim_service.py:656) | DB初期化/close、count/categories/backend情報、PostgreSQL追加情報の任意性、資格情報のmaskを確認。 | 確認済 | B |
| 19 | [bsim_add_executable_category](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/bsim_service.py:684) | category名の検証、既存categoryのalready_exists、登録結果とDB closeを確認。 | 確認済 | B |
| 20 | [list_bsim_executables](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/bsim_service.py:717) | name/md5/arch/compilerとlimitの転送、category情報、満杯ページのtruncated、資格情報maskを確認。 | 確認済 | B |
| 21 | [get_bsim_executable](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/bsim_service.py:750) | nameの完全一致による再選別、複数候補の拒否、100件+sentinelで不完全な一意性判断を防ぐ実装を確認。 | 確認済 | B |
| 22 | [bsim_update_executable_metadata](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/bsim_service.py:786) | 既存category名、完全MD5/名前、最新recordからのcategory merge、空値での削除、bad_executables返却を確認。 | 確認済 | B |
| 23 | [bsim_load_matched_executable](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/bsim_service.py:1252) | matched_refのversion/MD5/path/関数、既存target再利用、remote cacheのhost/port/repo、ロード検証失敗のrollbackを確認。 | 確認済 | B |
| 24 | [bsim_register_target](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_bsim.py:173) | 署名生成とDB insert、library stub件数、事前category設定、checkout要求、DB/GenSignatures解放を確認。categoryは先にProgram Informationへ保存する仕様。 | 確認済 | B |
| 25 | [bsim_apply_matches](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_bsim.py:383) | F1・F2修正済。自己除外後の件数、significance、既定名のみ、同率別名の除外、dry_run、部分的rename失敗の明示を確認。 | 修正済 F1/F2 | B |
| 26 | [bsim_update_target_signatures](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_bsim.py:299) | feature vectorを再生成しない更新、未登録Program拒否、DBのみのcategory保持、更新・失敗件数を確認。 | 確認済 | B |
| 27 | [bsim_delete_executable](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/bsim_service.py:1061) | confirm照合、名前の完全一致・一意性、対象MD5を固定したdelete、missedと実削除件数を確認。 | 確認済 | B |
| 28 | [list_functions](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_functions.py:20) | 大文字小文字を無視したfilterとDEFAULT sourceによる絞込がpaginationより先、body size・thunk情報を確認。 | 確認済 | F |
| 29 | [list_namespaces](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:114) | global除外、namespace階層の列挙、SymbolTypeによるClass判定、絞込後のpaginationを確認。 | 確認済 | M |
| 30 | [decompile_function](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_decompile.py:31) | address優先・名前の一意性、function containing、失敗伝播、decompiler再利用と大きな結果の回収を確認。 | 確認済 | F |
| 31 | [create_function](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_symbols.py:347) | 既存entryはcreated=false、関数内部は拒否、必要時のみdisassemble、作成失敗時rollbackを確認。 | 確認済 | E |
| 32 | [delete_function](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_symbols.py:385) | entry/包含関数の選択、removeFunctionの成否確認、命令を残して関数定義を削除する範囲を確認。 | 確認済 | E |
| 33 | [analyze_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_symbols.py:408) | 解析済みのnoopとforce、解析transaction、分析完了のmark、例外伝播を確認。 | 確認済 | E |
| 34 | [get_function](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_functions.py:106) | address優先・同名の曖昧性、prototype、local/parameter storage、namespace、thunk、bodyの返却を確認。 | 確認済 | F |
| 35 | [list_segments](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:31) | MemoryBlockの範囲・サイズ・R/W/Xとoffset/limit、空結果を確認。 | 確認済 | M |
| 36 | [list_imports](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:72) | ExternalSymbolsの列挙、library・full_name・address、paginationを確認。 | 確認済 | M |
| 37 | [list_exports](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:88) | external entryからprimary symbolを取得、export判定後のpaginationを確認。 | 確認済 | M |
| 38 | [list_data_items](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:135) | DefinedDataのみ、型名はDisplayName、label/value/length、paginationを確認。 | 確認済 | M |
| 39 | [list_strings](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:162) | hasStringValueによる選択、case-insensitive filter後のpagination、標準limit=2000を確認。 | 確認済 | M |
| 40 | [get_data_by_label](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:192) | 同じ短いlabel名の全symbolを列挙し、DefinedDataAtがあるものだけ返す処理を確認。namespace付きの一意選択APIではない。 | 確認済 | M |
| 41 | [list_data_types](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:292) | category完全一致とname/display/pathの部分一致、絞込後のpagination、型の要約を確認。 | 確認済 | M |
| 42 | [get_bytes](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:215) | size=1..1MiB、address解決、memory read失敗の伝播とhexdump出力を確認。 | 確認済 | M |
| 43 | [search_bytes](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:259) | 公開patternから内部bytesへの変換、whole-byte ??、空/全wildcard拒否、重複位置、memory終端停止を確認。 | 確認済 | M |
| 44 | [set_function_prototype](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_symbols.py:200) | address優先、C signature parse、ApplyFunctionSignatureCmdのfalse/例外でrollback、返却する実関数名を確認。 | 確認済 | E |
| 45 | [set_local_variable_type](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_symbols.py:250) | 型解決、高位symbol/parameterのDB commit、local/parameter fallback、見つからない変数のrollbackを確認。 | 確認済 | E |
| 46 | [set_global_data_type](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_data_types.py:220) | 型とclear_mode解決、DataUtilities.createData、失敗時rollback、lengthの転送を確認。 | 確認済 | D |
| 47 | [set_bytes](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_symbols.py:327) | 公開bytes_hexから内部bytesへの変換、1MiB制限、空の拒否、Memory.setBytesのtransactionを確認。 | 確認済 | E |
| 48 | [get_comments](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/program_tools.py:79) | 5種類のCommentType公開API、未設定null、編集・削除とのround tripを確認。 | 確認済 | P |
| 49 | [search_symbols](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/program_tools.py:104) | 部分一致とglob、大文字小文字を無視した検索、SymbolTypeによる絞込後のpaginationを確認。 | 確認済 | P |
| 50 | [create_label](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/program_tools.py:129) | 空名拒否、USER_DEFINED source、make_primaryの挙動と既存label再利用を確認。 | 確認済 | P |
| 51 | [add_bookmark](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_symbols.py:416) | address/category/typeの必須条件、BookmarkManager.setBookmark、transactionと返却値を確認。 | 確認済 | E |
| 52 | [list_bookmarks](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/read_only_memory_data.py:325) | address/type/categoryの組合せ、filter後のpagination、削除に使えるidの返却を確認。 | 確認済 | M |
| 53 | [delete_bookmark](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_symbols.py:441) | id優先またはaddress+type+category、comment絞込、未一致の拒否、削除前snapshotを確認。 | 確認済 | E |
| 54 | [create_struct](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_data_types.py:29) | F3修正済。size/明示offset/暗黙append、管理下datatype、途中失敗時の新規型・成長のrollbackを確認。 | 修正済 F3 | D |
| 55 | [add_struct_members](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_data_types.py:70) | F3修正済。既存型の一意解決、明示offsetのgrow、packed配置の固定、既存memberとrollbackを確認。 | 修正済 F3 | D |
| 56 | [delete_data_type](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_data_types.py:153) | category指定時の完全解決、曖昧名拒否、manager.removeの成否、削除前の型情報を確認。 | 確認済 | D |
| 57 | [remove_struct_members](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_data_types.py:108) | members=[]のnoop、clear_allの明示、混在拒否、ordinal降順削除による対象ずれの防止を確認。 | 確認済 | D |
| 58 | [rename_data_type](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_data_types.py:188) | category/一意な名前での解決、renameのtransaction、返却情報を確認。 | 確認済 | D |
| 59 | [create_enum](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_data_types.py:287) | size=1/2/4/8、整数/数値文字列/コメント、bool拒否、Ghidraの値範囲・signednessとrollbackを確認。 | 確認済 | D |
| 60 | [set_enum_values](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_data_types.py:309) | 置換対象を先に全部削除してsignednessの順序依存を除去、remove未一致拒否、残存値との衝突rollbackを確認。 | 確認済 | D |
| 61 | [parse_c_declarations](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/mutating_data_types.py:345) | 1M文字上限、public CParserで型を実登録、構文エラー情報、途中作成のrollbackを確認。 | 確認済 | D |
| 62 | [get_project_sync_status](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:36) | domain_path明示/active選択、refresh、未保存編集のoverlay、取得失敗を成功としない処理を確認。 | 確認済 | Y |
| 63 | [get_version_history](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:806) | versioned限定、降順、limitとtotal_versions、接続/履歴取得失敗を確認。 | 確認済 | Y |
| 64 | [get_version_diff](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:829) | 存在する2version、同版の空差分、range/details上限、timeout、read-only Programのconsumer解放を確認。 | 確認済 | Y |
| 65 | [checkout_project_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:52) | exclusiveの設定既定値、checkout拒否、未保存編集、既checkout、reloadと事後確認のpartial successを確認。 | 確認済 | Y |
| 66 | [add_project_program_to_version_control](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:127) | comment必須、既versionedのnoop、保存/close/add/reopen順、keep_checked_outの実効値を確認。 | 確認済 | Y |
| 67 | [commit_project_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:184) | auto checkoutとclean noop時の取消、stale checkoutのabort/discard/keep、保存後再確認、commit済みのpartial successを確認。 | 確認済 | Y |
| 68 | [pull_project_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:376) | 未保存・保存済み編集のabort/discard、hijack解消、metadataだけ更新されたProgramのreopen、最新versionの事後確認を確認。 | 確認済 | Y |
| 69 | [undo_checkout_project_program](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:541) | 未checkoutのnoop、discard/keep、.keep名の特定、preserved Programへのreopen、事後確認を確認。 | 確認済 | Y |
| 70 | [terminate_project_program_checkout](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:653) | 実在checkout ID、現在使用中のcheckout拒否、複数cache間の所有者、排他区間と事後確認を確認。 | 確認済 | Y |
| 71 | [delete_shared_project_file](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/sync_operations.py:709) | 正規化pathのconfirm、複数cacheのload状態、checkout、expected version、非atomic削除の明示、削除後確認を確認。 | 確認済 | Y |
| 72 | [get_xrefs](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/analysis_queries.py:9) | to/from、両端の関数、operand index、cursorのquery/revision固定、途中変更検出を確認。 | 確認済 | Q |
| 73 | [get_call_edges](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/analysis_queries.py:67) | in/out、data参照除外、tail call/thunk、未解決call、EXTERNAL宛先、cursorを確認。 | 確認済 | Q |
| 74 | [disassemble](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/analysis_queries.py:137) | functionとrangeの排他、end/length、address space境界、非連続bodyとseek cursorを確認。既存命令を読むだけ。 | 確認済 | Q |
| 75 | [get_data_type](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/analysis_queries.py:199) | 完全pathまたは一意名、struct/union/enum/typedef、include_members=false、revision metadataを確認。 | 確認済 | Q |
| 76 | [apply_edits](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/batch_edits.py:55) | 7種類のedit、atomic/非atomic/dry_run、before/after取得失敗も含むrollback、revision・checkout、項目別statusを確認。 | 確認済 | A |
| 77 | [bsim_query](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/application/services/bsim_service.py:801) | F1・F2修正済。program/functionsのselector制約、閾値、自己一致除外、関数別上限と全体上限、matched_ref/provenanceを確認。 | 修正済 F1/F2 | B |
| 78 | [batch_read](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_headless/handlers/commands/batch_read.py:11) | 5子ツールの公開可否、全入力事前検証、1lock、revision変化時の全破棄、soft deadline、項目errorとfield projectionを確認。 | 確認済 | A |
| 79 | [read_result](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/presentation/result_tools.py:344) | text/JSONの引数排他、offsetと上限、エスケープ込みresponse予算、巨大itemを飛ばすoffsetとtext回収、期限切れを確認。 | 確認済 | R |
| 80 | [search_result](/Users/samsepi0l/ghidra/mecha_ghidra/src/ghidra_mcp/presentation/result_tools.py:405) | regex worker/timeout、scan上限、count_complete、zero-lengthと\Kのcursor、reverse制約、context共有、response予算を確認。 | 確認済 | R |

## 関連テストの対応

各行の記号は関連テスト群。1ファイルが複数ツールを呼ぶものもあり、記号ごとの成功件数をツール数として数えていない。

- **L**: [test_target_service.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_target_service.py), [test_runtime_target_lifecycle.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_target_lifecycle.py), [test_project_handle.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_project_handle.py), [test_runtime_import_lifecycle.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_import_lifecycle.py), [test_runtime_registry_shared_sync_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_registry_shared_sync_commands.py)
- **P**: [test_program_tools.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_program_tools.py), [test_runtime_dirty_state.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_dirty_state.py), [test_runtime_resource_safety.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_resource_safety.py)
- **S**: [test_script_catalog.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_script_catalog.py), [test_script_service.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_script_service.py), [test_runtime_script_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_script_commands.py), [test_runtime_script_threads.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_script_threads.py)
- **B**: [test_bsim_service.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_bsim_service.py), [test_bsim_infra_helpers.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_bsim_infra_helpers.py), [test_bsim_headless_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_bsim_headless_commands.py), [test_runtime_bsim_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_bsim_commands.py), [test_runtime_bsim_loading.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_bsim_loading.py)
- **F**: [test_function_lookup_precedence.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_function_lookup_precedence.py), [test_runtime_readonly_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_readonly_commands.py), [test_runtime_tool_revision.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_tool_revision.py)
- **M**: [test_headless_command_helpers.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_headless_command_helpers.py), [test_runtime_readonly_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_readonly_commands.py), [test_runtime_mutating_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_mutating_commands.py)
- **E**: [test_mutating_command_units.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_mutating_command_units.py), [test_runtime_mutating_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_mutating_commands.py), [test_runtime_dirty_state.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_dirty_state.py)
- **D**: [test_mutating_command_units.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_mutating_command_units.py), [test_program_tools.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_program_tools.py), [test_runtime_datatype_edits.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_datatype_edits.py), [test_runtime_mutating_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_mutating_commands.py)
- **Y**: [test_sync_service.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_sync_service.py), [test_runtime_sync_operations.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_sync_operations.py), [test_runtime_registry_shared_sync_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_registry_shared_sync_commands.py), [test_project_handle.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_project_handle.py)
- **Q**: [test_query_pagination.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_query_pagination.py), [test_runtime_tool_revision.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_tool_revision.py), [test_runtime_readonly_commands.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_readonly_commands.py)
- **A**: [test_batch_read.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_batch_read.py), [test_runtime_batch_read.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_batch_read.py), [test_runtime_tool_revision.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_tool_revision.py), [test_runtime_dirty_state.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_runtime_dirty_state.py)
- **R**: [test_result_efficiency.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_result_efficiency.py), [test_presentation_context_compaction.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_presentation_context_compaction.py), [test_wire_envelopes.py](/Users/samsepi0l/ghidra/mecha_ghidra/tests/test_wire_envelopes.py)

公開境界はtest_mcp_boundary_contract.py、test_tool_specs.py、test_spec_handler_parameters.py、test_tool_contracts.py、test_wire_envelopes.pyでも横断確認。個別のサービス・handlerまで追跡し、公開契約と実行後の状態を確認した。今回の変更で非推奨APIや非公開APIへのパッチは追加していない。

## 実行結果

今回の変更は製品コード3ファイルとテスト6ファイル。開始時の作業ツリーを保存し、その状態との差分を記録した。既存の変更は保持した。

| 検証 | 結果 |
|---|---|
| 変更前の通常テスト | 1,617 passed / 215 skipped |
| BSim・MCP境界の関連テスト | 154 passed |
| 変更後の通常テスト全体 | **1,627 passed / 219 skipped** |
| 実Ghidraの型編集・rollback | 30 passed |
| Java / Jython / PyGhidraスクリプト | 82 passed |
| リソース解放・BSimロード・worker thread | 18 passed |
| 使い捨てGhidra Serverによる共有同期 | 2 passed |
| 使い捨てH2によるBSim | 5 passed。追加プローブでBSim全11ツールを含む19回の呼び出しも成功 |
| MCP stdio / HTTP × PyGhidra / Jython | 4 passed。入出力schema、実編集、rollback、結果取得、終了時の後始末を確認 |
| Ruff lint / format、compileall、git diff --check | 成功 |

通常実行でskipされる実機テストは、用途ごとに別のJVM・プロジェクトで実行した。JUnitのテストIDを照合した結果、**219件すべてに成功記録があり、未解消の失敗は0件**。上表の実機テストには重複実行があるため、件数を単純合算しない。MCP SDKの非推奨警告は `-W error::mcp.MCPDeprecationWarning` でエラーとして扱った。

最初の実Ghidra横断実行は171 passed / 15 failedだった。15件は既存のテスト配線のずれで、スクリプトの補助関数と異なるToolHarnessを使用していたこと、およびqueue timeout用のテストが一般のlock timeoutを変更していたことが原因。テスト側を修正し、該当3ファイルを82 passedで再確認した。製品側のtimeoutや有効化条件は緩和していない。F3の修正前4件の失敗も、修正後の型編集30件ですべて解消した。

BSim追加プローブは、DB未登録のquery Programと2件の別Programを用い、自己一致がない場合の上限2件→1件を実測した。significance=2.5での検索と適用、dry_runでの変更なし、適用後の名前、matched executableのロード、category追加・metadata更新・署名情報更新・登録・削除・状態取得を確認した。

ユーザーの稼働中サービスは操作せず、一時領域に作成したプロジェクト・DB・サーバーを使用した。共有テスト用サーバーは停止済みで、停止結果も保存した。

[検証記録ZIP](/Users/samsepi0l/ghidra/mecha_ghidra/docs/release-tool-by-tool-evidence-20260921.zip)に、80ツールの台帳、通常・実機テストのログとJUnit、修正前の再現ログ、今回の変更差分、実機テストの照合表と補助スクリプトを収録した。証明書の秘密鍵やプロジェクト・DB本体は含めていない。

## 仕様上の境界

- run_scriptのtimeoutはmonitorを確認する処理への協調キャンセル。任意スクリプトのOS/ネットワーク操作はProgram transactionではrollbackされない。Java/Jython/PyGhidraを実行する製品の既存仕様として確認した。
- batch_readの時間制限は各読み取りの間で確認するsoft deadline。全入力・全出力が同じrevisionであることを検査する。
- export_programのgzfは保存済みProgramを対象とする。最新編集を含める場合はsave_project_programが必要。
- 共有versionedファイルの削除はGhidra側にatomic compare-and-deleteがなく、既存の明示オプションとversion照合を保持。
- BSim update_target_signaturesは名前・metadataの更新。feature vectorの再生成はdelete後の再登録で行う。
- 今回の実機検証対象はmacOS arm64 / Ghidra 12.1.3 / Java 21。Windows、Linux、remote PostgreSQL/Elasticsearchの実機検証を今回実施したとは扱わない。
