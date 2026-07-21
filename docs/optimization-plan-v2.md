# wasm2go 最適化計画 v2 — wasmtime とのギャップを閉じる

（v1 = `docs/ssa-memopt-plan.md`。v1 の「Cranelift ミッドエンド移植」という前提は
今回の実測で否定された。本 v2 がそれを置き換える。）

---
## ★ 引き継ぎメモ（2026-07-21 第2便。次の担当者はここから読む）

**FOLLOW-UP バグ（下記）は修正・コミット済み。さらに修正の副産物として
arm64 gcasm の未知の miscompile（ジャンプテーブル flag-replay の arm64 未移植）を
発見・修正した。ベンチは想定外の大幅改善: cpubench gcasm 127.8→97.1ms（−24.0%,
5/5ペア）、pure 100.4→82.4ms（−18.0%, 3/3ペア）、同セッション wasmtime 77.5ms
→ ギャップ gcasm 1.66×→**1.25×**、pure 1.30×→**1.06×**。詳細は bench-metrics.md
の memaddr エントリ。**残作業: ユーザーによる push/PR 判断のみ**（コミットは
feat/ssa-memopt-licm-gvn に積んである）。**旧引き継ぎメモは下記に残す（歴史）。**

### 今回入った変更（3コミット）

1. **memaddr パス（FOLLOW-UP バグの恒久修正）**: `pass.FoldMemAddend`
   （internal/ssa/pass/memaddr.go）。`Load/Store(base=Add32(x, 大定数c))` の
   c を AuxInt オフセットへ畳み込み、既存の `_consts` テーブルガードに乗せる。
   emit 改修不要。**fixpoint ループの後に1回だけ**実行（fold 後の constprop が
   base を定数化すると emit の非ラップ u33 純定数経路と衝突し、i32 ラップに依存
   する加算で誤アドレスになるハザードを構造的に排除）。負の大加数も uint32 ビット
   パターンで fold（runtime 経路は uint32 ラップなので正確）。小加数は不変
   （テーブルロードで common case を悪化させない）。python.wasm で `_consts`
   サイト ~2,700 増 = 従来リテラルプール危険地帯だった母集団。
2. **arm64 ジャンプテーブル flag-replay 移植（新発見の重大 miscompile 修正）**:
   amd64 の Bug B 修正（d4b6ca3）が arm64 に未移植だった。`a64EmitJumpTree` の
   CMPW/BHS が NZCV を破壊したまま、pre-dispatch の bounds-check フラグを消費する
   ターゲットへ飛ぶ → 分岐誤り → メモリ破損。**症状: go-python arm64 gcasm が
   ベースライン(d4b6ca3)で SIGSEGV**（Fn3705 のディスパッチが破損源、Fn3708 が
   被害者。pure/arm64 は green、[0,5114) fallback で green の切り分け済み）。
   修正: `a64FindJumpTables` に replay 検出を移植 + 厳密化（テーブルベース/
   ターゲットレジスタを読む compare は replay 不可として pure fallback）、
   `a64EmitJumpTree` の全リーフに replay 注入。
3. **docs**: 本ファイルの引き継ぎ更新。

### 検証（すべて本セッションで exit 0 観測、修正版バンドル）

wasm2go: `go test ./...` 9pkg / `make lint` 0 issues / `make test-cover` 85.4%。
`GOARCH=arm64 go test ./...` は gcasm gate 9件が FAIL するが**ベースラインでも
同一の9件が FAIL**（amd64 capture フィクスチャに GOARCH が漏れる既存の環境問題、
変更起因ではない）。コンシューマ（wasmify 正規パイプライン、buf generate 再生成）:
- go-python: amd64±race, arm64±race 全て exit 0（**arm64 はベースラインで
  SIGSEGV だったものが修正で green 化**）
- go-spidermonkey: amd64±race, arm64±race 全て exit 0
- googlesqlite: amd64 -race 35pkg ok, arm64 -race 35pkg ok
- go-googlesql スモーク: exit 0

### ベンチ（cpubench, arm64 native, 交互 A/B, idle, wasmtime 46.0.1）

- gcasm: BASE(=d4b6ca3 の /tmp/cpu_gcasm_fix.test) 126.1/127.6/125.9/127.6/131.7
  → NEW 97.6/98.0/97.0/97.3/95.8 ms。**−24.0%、5/5、レンジ非重複。**
- pure: BASE 98.7/105.6/97.0 → NEW 83.1/81.9/82.1 ms。**−18.0%、3/3。**
- 同セッション wasmtime コントロール: 77.5 ms/op（前セッション 78.6 と整合）。
- 値検証: cpubench の計算結果 9335250 を amd64/arm64 両方で確認（miscompile で
  速くなった可能性を排除）。
- **帰属の仮説**（未分離）: pure レーンは memaddr のみ含む → memaddr 単独で
  −18%。gcasm の追加 −6% は a64 replay 修正で「フラグ消費 dispatch を持つ関数が
  pure fallback 化」した効果の可能性（pure は ABIInternal で呼び出し密コードに
  速い）。なぜ memaddr が −18% も出るかは未解明（仮説: 大定数の
  マテリアライズ/アドレッシング形状が gc の巨大関数 regalloc・命令選択を
  改善）。**0c 型の pprof 帰属をやる価値あり。**
- **注意**: BASE の arm64 gcasm バイナリは flag-replay バグを内包した世代
  （cpubench 経路で誤計算していた証拠はないが、厳密には「バグ入り世代との差」）。

### 次の候補（更新）

1. **なぜ memaddr で −18% 出たかの pprof 帰属**（新しい主要ホットスポットの把握。
   ギャップ 1.06×(pure)/1.25×(gcasm) まで来たので、残りの構造も見える）
2. depth-2 インライン再挑戦（前提だった FOLLOW-UP バグは解消済み。ただし予想
   ROI ≤1-2% は据え置き。A/B は新しい NEW バイナリを baseline に）
3. gcasm ABI0 マーシャリング/チャンクレイアウト（残ギャップ 1.25× の主成分候補）

**旧メモ（第1便）**:

**ブランチ**: `feat/ssa-memopt-licm-gvn`（origin に push 済み）。

**コミット済み（d4b6ca3）**: memopt(Phase A) + PureOnly(`-pure`) + 1e(eqz融合) +
1b(リーフインライナ) + gcasm 2修正(ssaConstBase / jump-table フラグ replay)。
全コンシューマ検証済み（wasm2go 9pkg / go-python / go-spidermonkey +race /
googlesqlite 35pkg、すべて exit 0）。ベンチ: **spidermonkey cpubench gcasm
−12.9%(≈−14%)、pure −5.3%。wasmtime ギャップ 1.91× → ~1.66×。** これが確定成果。

**depth-2 インライン: 試行 → REVERT 済み（tree は committed d4b6ca3 と一致）。**
bounded depth-2（非リーフ callee も深さ上限2 + サイクルガード + サイズ上限で splice、
callee のコールは depth+1 で再帰）を実装し wasm2go 9pkg green・e2e(TestInlineDepth2)
PASS まで到達したが、**spidermonkey 生成で新しい arm64 リテラルプールエラーを露出**して
revert した（理由は下記 follow-up バグ + 予想 ROI の低さ）。判断根拠:
  - **予想 ROI ≤1-2%**: 1b 後の pprof で残りホット時間の ~80% は
    Fn1083(53712行,61.5%flat)/Fn2121(3865行,9.5%)/Fn1098(1453行,5.8%)/
    Fn1467(1702行,4.6%) の4巨大関数の**自身処理**で、すべてサイズ上限超でインライン不可。
    小非リーフ(Fn3504 237行/Fn3505 568行、≈計3.6%flat)だけが候補。さらに Fn1083 に
    折り込むと gc regalloc 悪化で**ネット negative**のリスク。
  - **露出した follow-up バグ(下記)の堅牢修正が emit の非自明改修を要する。**
depth-2 を再挑戦するなら、まず下記バグを直し、A/B（baseline=`/tmp/cpu_gcasm_fix.test`
の leaf-only、5ペア交互）で中立/negative でないことを確認してから。中立なら leaf-only
を最終形に据える。

### FOLLOW-UP バグ: 大定数アドレス加数が arm64 リテラルプールを溢れさせる（潜在・要修正）

depth-2 が露出させたが **leaf-only や非インラインコードでも理論上起こりうる潜在バグ**。
症状: `p3_pure.go: LDPSW 27325896(R2): constant is not in pool`（arm64 capture の
go build 失敗）。原因: メモリアクセスのベースが `OpAdd32(runtimeX, OpConst32[大])`
の形のとき、`emit_memops.go` の `memOffsetExpr` は `constInt32(baseExpr)` も
`ssaConstBase(baseVal)`（純粋定数ベースのみ検出）も外し、runtime パスで
`uint32(baseExpr)` をそのまま出す → baseExpr 内に `int32(27325896)` が加数として残り、
gc がアドレッシング即値に折り込む。`_consts` テーブル routing は AuxInt オフセットと
純粋定数ベースしかカバーせず、**「runtime + 大定数」ベースを取りこぼす**。
修正案: `ssaConstBase` を「ベースを (runtimeVal, 大定数加数) に分解」するヘルパに拡張し、
大定数加数があれば `uint32(emit(runtimeVal)) + uint32(_consts[加数+offset])` を出す。
ただし memOffsetExpr は emitExpr を持たないので、emitMemLoadExpr/emitMemStoreStmt 側で
runtime 部を別途 emit して渡す必要がある（非自明）。回帰テスト用 fixture:
「定数アドレス + ランタイム index」で 27MB 級の加数を作る形。
**注意: committed の leaf-only はこのバグを踏んでいない（全コンシューマ green）が、
入力次第で踏みうる。優先度は中（アセンブラ失敗＝ビルド不能なので踏めば即分かる）。**

**depth-2 が空振りの場合の次の方向**（残りギャップは gc コード生成品質＝構造的天井）:
  - (a) gcasm ABI0 マーシャリング/`gcasmFwd` トランポリンの削減。ホット callee を
    Fn1083 と**同一チャンク**に配置すればクロスチャンク forwarder が消える(チャンク
    レイアウト最適化、インラインより低リスク)。
  - (b) Fn1083 の emit 形改善で gc の regalloc を助ける（P1 の mBase hoist 型。ただし
    P1 は実施済み。call 後の mBase refresh を「grow 不能な callee では省略」できるか
    ＝ HelperIsInline の一般化）。高難度・不確実。
  - (c) −14% を最終形として受容し、backend 追求を打ち切る判断。

**検証規律(厳守)**: コード生成変更のたびに wasmify 正規パイプラインで A/B。直接
`wasm2go` CLI 生成は**ホスト import を持つモジュールでは無効**（bridge を欠く。import
無しマイクロベンチのみ CLI 可）。googlesqlite はメモリ/regalloc 系変更の必須バリデータ、
go-spidermonkey は共有メモリ`-race`必須。ディスク注意: gcasm capture は数GB必要。
go-build キャッシュが肥大化(186GB になっていた)したら `go clean -cache`、
`/tmp` の debug バンドルも随時削除。

**保存済み資産**: `/tmp/cpu_{gcasm,pure}_{1e,fix}.test`(A/B baseline)、
`/tmp/sm_fix_pure/bundle`(committed inline+fix の pure ソース、コール解析用)。
bench-metrics.md に全数値、本ファイルに設計。**注意: docs/consumer-verification.md と
docs/pure-vs-asm-benchmarks.md は意図的 untracked のローカル文書 — コミットしないこと。**
---

## 0. v1 で確定した事実（再計画の出発点）

Phase A（ブロック内 RLE + store-to-load forwarding、Cranelift の
`alias_analysis.rs` 相当）を実装・正規 wasmify e2e で全コンシューマ検証した結果:

- **効果はノイズ内**（go-python でメモリアクセス 0.02% 削減、Fib/LoopSum/Startup
  すべて ±2% 以内）。
- **正しく、かつ中立**（wasm2go / go-python / go-spidermonkey(共有, -race含む) /
  googlesqlite 35pkg すべてグリーン）。共有メモリでは defensive にゲート。

なぜミッドエンド移植が効かないか（v2 の全提案の前提）:

1. **入力 wasm は既に `clang -O2`。** RLE/GVN/LICM は C→wasm 段階で適用済み。
2. **gc が生成 Go を再最適化する。** SSA レベルでの *純粋値* の CSE/畳み込み/GVN/
   LICM の純粋部分は gc と冗長 → ランタイムを動かせない（ソースサイズのみ）。
3. **gc が構造的にできないのは unsafe メモリ跨ぎの推論だけ** = Phase A が狙った所。
   だが (1) が上限を抑え、実測 0.02%。
4. **wasm→Go 変換由来の2大コストは対処済み。** heap base リロード（P1 の mBase
   hoist）、per-access バウンズチェック（wasm2go は出さない = wasmtime の
   guard-page 相当）。

**結論（限定版）: 残りのギャップはミッドエンドでは*ない*。** ミッドエンド以外の
どこか（ABI0 / gc のコード生成 / Go ランタイム税）にあるが、**その内訳は未計測**。
「pure が wasmtime に対しどれだけ遅いか」は測っていない（下の弱点#2）。

## 0.5 レビューで判明した弱点（自己批判・第1回 #1–#7 / 第2回 #8–#11）

計画を批判的に検証した結果、以下の過剰主張・見落としがあった。§1 以降はこれを
織り込んで読むこと（#8–#11 は本文に反映済み）。

- **#1 「pure が asm を数倍上回る」は誇張。** 実データ（bench-metrics 17h）では
  asm/pure は **ワークロード依存**: googlesqlite の集約/mixed/tpch は 0.95–1.06×
  （ほぼ同等、q3 は asm が速い）、window だけ 1.11–1.28×、go-python(インタプリタ)
  だけ 6×。つまり **pure 優位は「呼び出し密なコード」限定**で、データ並列 SQL では
  ほぼ引き分け。「pure に寄せれば速い」と単純化できない。
- **#2 「ギャップはバックエンド」は測れていない結論。** 分かっているのは
  (a) ミッドエンド ≈ 0、(b) asm には ABI0 コストがある、の2つだけ。
  **pure vs wasmtime は未計測**。25% が gc-vs-Cranelift なのか Go ランタイム税なのか
  不明。§0 の「結論」はここまで弱める。
- **#3 引用データが古い。** `pure-vs-asm-benchmarks.md`(004c83d) と 17h は **gcasm
  (#19) より前**の own-emitter asm 世代。現行 gcasm の pure-vs-asm は測っていない。
  Phase 0b の第一目的はこれ。
- **#4 「LICM は ROI ~0」は自分の P1 実績と矛盾。** P1 の mBase hoist は
  *ループ不変ロードの巻き上げ = LICM の一種* で −30〜70% を出した。よって
  「不変式の巻き上げ」は**最も実証済みの手**であり、Phase 1 の筆頭に置くべき
  （§3 で 1a に格上げ）。正しくは「*汎用* LICM パスの追加は、profile 誘導の
  的を絞った巻き上げを超える分が少ない」という主張であって「LICM は無価値」ではない。
- **#5 ミッドエンド=0 の帰納が弱い。** 測ったのは *1パス(ブロック内RLE) × 1ワーク
  ロード(go-python)* のみ。cross-block も googlesqlite も未測。Phase 0c の pprof で
  「冗長ロード/不変式がホット」なら結論を見直す（0c はミッドエンド=0 の再検証も兼ねる）。
- **#6 「構造的天井」の可能性を明示していない。** 25% の相当部分が **Go ランタイム
  由来の不可避税**（GC write barrier、morestack、per-call オーバーヘッド、
  クロス関数インライン不可）や「gc は Cranelift ではない」という事実 かもしれない。
  その場合 Phase 0 の成果は「25% の内訳 + 現実的な到達可能ライン」であって、
  25% 短縮の保証ではない。これを期待値として先に置く。
- **#7 ユーザー計測の config が不明。** 25% は asm 対 wasmtime か pure 対 wasmtime か。
  これが Phase 0 の解釈の第一入力。着手前に確認すべき（下記で質問）。
- **#8（第2回）§1 の洞察が #1/#3 と自己矛盾していた。** 「6×」を事実扱いし
  「速度対策の対象は pure」と誤断。加えて重要な見落とし: **gcasm は gc が同じ
  生成 Go をコンパイルした結果の capture** なので、emit 形の改善(1a 型)は
  **pure と asm の両方に効く**。P1 で asm に効かなかったのは当時の asm が
  旧 own-emitter（Go ソース不使用）だったから。→ §1 を書き直し。
- **#9（第2回）§4 の「CLI 生成は無効」が 0b と矛盾。** 0b のマイクロベンチは
  import 無しの自己完結 wasm でホストブリッジ不要 → CLI 生成で正当。ルールは
  「ホスト import を持つモジュール / コンシューマ検証」に限定する。→ §4 修正。
- **#10（第2回）0b の計測方法論に穴。** `wasmtime run` は起動時 JIT コンパイルを
  含む。`wasmtime compile` の AOT(.cwasm) 実行か guest 内ループの定常状態計測で
  コンパイル時間を除外する。native arm64 同士で統一（Rosetta 混入禁止）。→ 0b 修正。
- **#11（第2回）実ワークロードの再現が欠落。** 25% が観測された**ユーザーの実
  ベンチそのもの**の再現・分解ステップが無かった（マイクロベンチだけでは代表性
  なし）→ 0d として追加。また Phase A(memopt) を PR に含めるか（中立だが複雑さを
  足す）は未決 → ユーザー判断事項として §4 に明記。

## 0.6 確定した前提（ユーザー回答 2026-07-20）

弱点 #7 の回答が得られ、計画の焦点が確定した:

- **ワークロード = spidermonkey。** wasmtime レーンは
  `spidermonkey-wasm/tests/cpubench.cc`（js_eval で fib(20)×50 + array
  push/reduce、warmup 3、ms/op 出力）を wasmtime で実行。Go レーンは同一
  ワークロードの go-spidermonkey ベンチ（cpubench.cc いわく bench/cpu_test.go —
  未コミットのローカル計測。ワークロードは cpubench.cc から再構成可能）。
- **本番モードは gcasm。** pure は ABIInternal で速いが、**巨大 pure Go ソースが
  lint / gopls / ビルドを遅くする**ため常用できない。→ 高速化の対象は gcasm。
  「pure を速度既定に」という §2 の分岐は spidermonkey では採れない。
- **gcasm は pure Go 版を gc でコンパイルした結果の capture。** よって
  「生成 Go の改善」が gcasm 高速化の主レバー（ユーザー確認済み = #8 の訂正と一致）。
  さらに帰結として: **pure ビルド時に gc がインライン展開した呼び出しは capture
  前に消える → その呼び出しの ABI0 マーシャリング自体が消滅**。生成 Go の
  インライン可能化は gcasm では二重に効く（§3 の 1b を参照）。
- spidermonkey は**共有メモリ（threads）モジュール**: memopt は gate で無効
  （中立なので影響なし）。共有メモリのインラインアクセス emit は #31 で入った
  ばかりの形であり、その形自体が 0c のプロファイル対象。

## 1. まだ分かっていない決定的なこと（→ 計画は「まず計測」から）

「25%」がバックエンドのどこにあるかは**未計測**。候補と、それぞれで打てる手は別物:

| ギャップの所在 | 説明 | 打てる手 | 可動性 |
|---|---|---|---|
| **ABI0 マーシャリング** | asm(gcasm)は ABI0。関数が gc のインライナに不透明 → 呼び出し密なコードで致命的 | pure に寄せる / 17k 系の再挑戦(過去に失敗) | pure で回避可 |
| **gc のコード生成品質** | pure でも gc は Cranelift ではない。regalloc/命令選択が劣る | emit 形の改善で gc を助ける（mBase hoist 型） | 中 |
| **Go ランタイム税** | GC write barrier / morestack / 非メモリ slice の bounds check | emit 形で削減（barrier回避, nosplit注意, bounds除去） | 一部のみ |
| **ホストブリッジ** | import/コールバックのディスパッチ、型アサーション | call_indirect 具象化、ブリッジ簡素化 | 中（ワークロード依存） |

構造的洞察（2点、いずれも #1/#3 の限定つき）:

- **gcasm(asm) の存在理由は「ビルド資源」**（gc が巨大関数のコンパイルに苦しむのを
  回避）。速度面では ABI0 関数が gc のインライナに不透明なため、呼び出し密コードで
  pure に劣る *はず* — ただし「6×」は旧 own-emitter 世代の数字で、**現行 gcasm の
  pure-vs-asm は未計測**（0b で測る）。gcasm 世代の既知データは M1 計測の
  「gcasm-vs-pure の差は ABI0 呼び出しマーシャリングのみ」という1点。
- **emit 形の改善は両バックエンドに効く。** gcasm は「gc が同じ生成 Go を
  コンパイルした結果」を capture するので、1a 型の emit 改善は pure にも asm にも
  伝播する。P1 時代に asm へ効かなかったのは当時の asm が旧 own-emitter だったため。
  よって Phase 1 は「pure 専用の投資」ではない（1b のインライン可能化のみ pure 限定）。

## 2. Phase 0 — ギャップの分解（最優先・安価・決定的）

目的: 「25%」を上表のバケツに定量配分し、Phase 1 の投資先を証拠で選ぶ。
**§0.6 により spidermonkey 中心に再構成**: 実行順は 0a → 0d（主計測）→ 0c
（pprof 帰属）。0b のマイクロベンチは補助に格下げ（帰属が曖昧な時だけ）。

- **0a. pure 強制ビルド経路の回復。** PR #31 が purego タグを削除したので、arm64/amd64
  で pure を測る手段がない。dev 限定のビルドタグ escape を再追加するか、wasm2go に
  「pure-only 出力」フラグを足す（`-emit=pure`）。
- **0b. 三者同一ベンチ（2種のワークロード）。** 弱点#1 より asm/pure はワークロード
  依存なので、**呼び出し密**（再帰 fib のような call-heavy wasm）と**データ並列**
  （tight numeric loop / mandelbrot）の *両方* を、**import 無しの自己完結 wasm** で
  用意し、(i) wasmtime、(ii) wasm2go-pure、(iii) wasm2go-asm で同一マシン計測。
  → **ABI0 税 = asm/pure**、**コード生成ギャップ = pure/wasmtime** をワークロード別に
  算出。呼び出し密で pure≫asm、データ並列で pure≈asm を予想（17h データの再確認）。
  方法論（#10）: wasmtime 側は `wasmtime compile` の AOT(.cwasm) 実行か guest 内
  ループの定常状態計測で **起動時 JIT コンパイルを除外**。全構成 native arm64 で統一
  （Rosetta 混入禁止）。wasmtime のバージョンを記録。import 無しなので wasm2go は
  直接 CLI 生成で正当（§4 の制限はホスト import を持つモジュールの話）。
- **0c. pprof で pure ホットパスを帰属。** 生成コード計算 / Go ランタイム(GC・morestack・
  write barrier・非メモリ bounds) / ホストブリッジ に時間を分解。**可動な割合**を出す。
  ミッドエンド=0 の再検証（#5: 冗長ロード/不変式がホットに残っていないか）も兼ねる。
- **0d.（主計測）spidermonkey cpubench の三者再現。** cpubench.cc のワークロード
  （fib(20)×50 + array push/reduce）を
  (i) wasmtime × cpubench.wasm、(ii) go-spidermonkey × gcasm バンドル、
  (iii) go-spidermonkey × pure バンドル（0a が前提）
  の3レーンで同一マシン・native arm64・`-count=5` 計測。
  → **wasmtime/gcasm（ユーザーの 2× の再現）**、**ABI0 税 = gcasm/pure**、
  **コード生成ギャップ = pure/wasmtime（ユーザーの 25% の再現）** を確定。
  wasmtime レーンは AOT（`wasmtime compile`）か十分な warmup で JIT コンパイル時間を
  除外（cpubench.cc は warmup 3 済み）。wasmtime バージョンを記録。
- **成果物**: 「25% の内訳」表（spidermonkey 実ワークロード + 必要なら 0b で補強）。
  これ無しに Phase 1 を選ぶのは v1 の轍を踏む。

分岐（§0.6 により更新）: 本番が gcasm 固定なので「pure を速度既定に」は不採用。
- gcasm/pure が大きい（ABI0 税が主）→ **1b（インライン可能化で呼び出しごと消す）**
  を筆頭に、残る呼び出しの ABI0 マーシャリング削減を検討（17k の轍に注意）。
- pure/wasmtime が大きい（gc コード生成 or ランタイム税が主）→ 0c の帰属に従い
  1a / 1c / 1d へ。どちらも生成 Go の改善なので gcasm に伝播する。

## 3. Phase 1 — 最大の可動バケツを叩く（Phase 0 で選択）

いずれも「Cranelift のパスを移植」ではなく「**gc に良いコードを書かせる emit 形**」。

- **1a. 追加の reload 潰し（mBase hoist の一般化）。** pprof で「ループ毎に再ロード
  される Module フィールド/アドレス」を特定し、非エスケープ local に巻き上げ。P1 が
  −30〜70% を出した実績のクラス。gc が unsafe ストア/コール後に無効化する値が対象。
- **1b. ホット小関数のインライン可能化。** gc のインライン予算に収まるよう生成関数を
  整形（インラインを阻む emit パターンの除去、巨大 switch の分割、defer/recover の
  局所化）。**gcasm では二重に効く**（§0.6: gc が pure ビルド中にインラインした
  呼び出しは capture 前に消える = その ABI0 マーシャリングごと消滅）。呼び出し密な
  spidermonkey（インタプリタ）の本丸候補。
- **1c. call_indirect 具象化。** 現状 `m.t0[idx].(func(*Module,...))(...)` の型アサーション
  ディスパッチ → 型インデックス毎の具象 `[]func(*Module,...)` テーブルでアサーション除去。
  **C++ vtable 由来の call_indirect が多い SpiderMonkey では中〜大効果の見込み**。
  gc の devirt も助ける。
- **1d. Go ランタイム税の削減（該当時）。** write barrier を生む pointer 中間値の回避、
  非メモリ slice の bounds check 除去、安全な範囲での nosplit（deep helper には禁物 —
  既存メモリ note 参照）。

- **1e.（実装済み・実行時間は中立と判明）比較/eqz→分岐の融合。** eqz を第一級比較
  （OpEq{32,64} vs 0）に lowering、分岐は `if x == 0` に直接融合。90k ヘルパ呼び出し
  除去・pure バイナリ −5.3%・gcasm .s −0.6% だが、**同一セッション交互 A/B で
  実行時間は ±0**。gc は旧形状を既に同じ機械語に畳んでいた — 0c の「eqz ~10% flat」
  は inline 帰属の錯覚だった（bench-metrics の 1e エントリ参照）。サイズ/IR 整理
  として維持、性能主張は撤回。

**Phase 0/1e の実測結果（bench-metrics 参照）**: 1.91× = ABI0 税 1.38× × コード生成
1.39× でほぼ半々。時間の 91% はインタプリタ主ループ Fn1083 配下。Go ランタイム税
≈ 0（1d は不要）。**1e の中立結果により「pure 計算のソース形状改善は gc と冗長」が
3度目の確認となった** — 実コール削減だけが gc と冗長でないレバー。
方法論の教訓: **巨大関数の pprof inline 帰属は「削減可能な仕事」の証拠にならない**。
投資前にソースレベル A/B で裏取りする。

**1b 実装完了（2026-07-21）— 初の実測優位。** wasm レベルのリーフインライナ
（internal/lower/inline.go、詳細は bench-metrics の 1b エントリ）:
**gcasm −14.3%（149.4→128.0ms、交互 A/B 10/10 全勝）、pure −5.7%**。
対 wasmtime ギャップ **1.91× → 1.59×**（全ギャップの ~35% を回収）。
予測どおり「クロスチャンク linkname が gc のインライナに不透明」構造を突いた
実コール削減が効いた。露出した潜在バグ（SSA 定数ベースの _consts ガード迂回 →
arm64 literal-pool 溢れ）も修正済み。

次の候補（効果順の見込み）:
  1. **1b 拡張: 深さ2インライン**（非リーフの Fn2121/Fn1467 は callee がインライン
     で消えればリーフ化する — 2パス解析 or 不動点で到達可能）
  2. インラインしきい値チューニング（MAXBODY/MAXPRODUCT を振って
     サイズ↔速度トレードオフの knee を探す）
  3. gc-vs-Cranelift の巨大関数品質（残り 1.30×/pure — 構造的天井の可能性）

**やらないこと**: *汎用* cross-block GVN パスの本格実装（gc が pure 値の GVN を再実行
するため冗長）。汎用 LICM *パス* も、1a の的を絞った巻き上げを超える分が少ないと
予想されるため後回し（ただし 0c で「不変式がホット」と出れば 1a を厚くする）。
これらは「無価値」ではなく「1a に対する追加 ROI が薄い」という位置づけ。

## 4. 検証規律（今回確立した e2e を必須化）

コード生成を変えるたび、**wasmify 正規パイプライン**で A/B:

1. wasmify に wasm2go をローカル replace → `protoc-gen-wasmify-go` 再ビルド。
2. `buf generate`（spidermonkey-wasm / googlesql-wasm）→ bridge+bundle を配線。
3. **googlesqlite（メモリ系変更の必須バリデータ, 35pkg）** + **go-spidermonkey
   （共有メモリ, `-race`）** + **go-python** をグリーン確認。
4. bench は `-count=5`、平均+レンジ、2% 未満はノイズ扱い（bench-metrics.md の規約）。

直接 `wasm2go` CLI 生成は、**ホスト import を持つモジュール（= 全コンシューマ）では
無効**（wasmify ホストブリッジを欠く）。今回これで2度誤診断した。CLI 出力を
consumer 検証に使わない。**例外**: 0b のような import 無しの自己完結マイクロベンチは
ブリッジ不要なので CLI 生成で正当（#9）。

memopt(Phase A)は正しく中立なのでブランチ上の土台として維持。共有メモリゲートも維持。
ただし **PR に含めて main へ入れるかは別判断**（実測ノイズ内の効果に対して
パス1本ぶんの複雑さを足す）— ユーザーが決める事項として残す（#11）。

## 5. 実行順序（§0.6 で確定）

0. ~~ユーザーに確認~~ → 回答済み（§0.6）。**未決は Phase A(memopt) を PR に
   含めるかのみ**。
1. Phase 0a（pure 強制ビルド経路）→ 0d（spidermonkey cpubench 三者計測）→
   0c（pprof 帰属）。0b は帰属が曖昧な時だけ。
2. 帰属表をユーザーに提示し、Phase 1 の投資先（1a/1b/1c/1d）を合意。
3. 1x を1つ実装 → §4 で A/B 検証（spidermonkey e2e が主戦場）→ bench-metrics に
   追記 → 次を判断。

各ステップ後に立ち止まって数値を見る（v1 の「効くはず」で突っ走らない）。
