# CLAUDE.md — mailsec-probe

## Project Overview

Go 製 CLI ツール。指定したドメインのメールセキュリティ関連 DNS レコード
(SPF / DMARC / DKIM / MX / MTA-STS / TLS-RPT / BIMI / DNSSEC) を
外部観測し、各機能の有無を確信度付きで構造化出力する。

モジュールパス: `github.com/shigeya/mailsec-probe`

詳細設計は [DESIGN.md](DESIGN.md) を参照。

## Build & Test

```bash
go build ./...              # ビルド
go test ./...               # ユニット + ゴールデンテスト
go vet ./...                # 静的解析
golangci-lint run           # lint (CI 必須)

go test -tags integration ./...   # 実 DNS / 実 HTTPS 依存テスト
```

## Phase Scope

現在 Phase 2.5 完了。次フェーズ Phase 3.0 計画中。

**実装済み**:
- **Phase 1.0** — SPF / DMARC / DKIM (固定 selector) / MX / MTA-STS / TLS-RPT / BIMI / DNSSEC (AD ビットのみ)、json/human 出力、ゴールデンテスト
- **Phase 1.5** — SPF→DKIM selector 推定、MTA-STS↔MX 一致性、DMARC rua HTTPS 到達性
- **Phase 2.0** — `--active`: SMTP STARTTLS + 証明書観察 + DANE/TLSA 照合 (mtatls probe)
- **Phase 2.5** — `--input` バッチ、TSV 出力、`--stats` 横断統計

**計画中**:
- **Phase 3.0** — DNSSEC chain validation を `github.com/shigeya/dnsdata-go` (別 module で co-develop) 経由で導入。BOGUS / INSECURE を区別。`--dnssec-mode ad-only` で旧挙動を保存。詳細は [DESIGN.md §16](DESIGN.md#16-phase-30-計画--dnssec-validation-via-dnsdata-go)

**含まない (Phase 3.0 までは)** — BIMI VMC 検証 / TLSA Usage 0/2 (trust-anchor) の厳密検証 / メール送信。
迷ったらまず観測の中立性を優先し TODO コメントで追跡。

## Directory Layout

- `cmd/mailsec-probe/` — エントリポイント
- `internal/cli/` — cobra コマンド定義 + `--input` パーサ
- `internal/probe/` — 観測器
  - `dnsclient/` — 共通 DNS クライアント (TXT / MX / TLSA / DS)
  - `httpfetcher/` — 共有 HTTPS Fetcher (Get + Head)
  - `spf/` `dmarc/` `dkim/` `mx/` `mtasts/` `tlsrpt/` `bimi/` `dnssec/`
  - `mtatls/` — active 専用 (STARTTLS + DANE)
- `internal/signals/` — Signal / Feature / Report 型
- `internal/classifier/` — 観測結果から Feature を作る集約層 (probe を flatten)
- `internal/output/` — フォーマッタ (json, human, tsv) + stats 集計
- `rules/` — 埋め込み YAML (`go:embed`)
  - `dkim_selectors.yaml` — 固定 selector 集合
  - `dkim_selector_inference.yaml` — SPF→selector マッピング
- `testdata/` — 含めるなら fixtures, golden
- `docs/` — ARCHITECTURE.md, DKIM_SELECTORS.md

## Coding Conventions

- Go 1.22+ (toolchain は 1.26 を許容)
- `gofmt`, `goimports` 強制
- `golangci-lint` で CI チェック
- エクスポートされる型・関数には godoc
- エラーは `%w` でラップ
- パッケージ名は単数、ディレクトリ名と一致
- ロギングは `log/slog` (デフォルト Warn 以上、`-vv` で Debug)
- イミュータブル指向: Signal/Feature は生成後ミューテートしない

## Commit Convention

Conventional Commits 準拠: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`
機能単位で分割。各コミット前に `go build ./... && go test ./...` を実行。

## Design Principles

1. **観測と判定の分離** — 観測器は中立的な Signal を生成、判定はルール/分類器
2. **非侵襲デフォルト** — DNS 問い合わせと HTTPS GET のみ。SMTP は `--active`
3. **ルールの外部化** — YAML を `go:embed`、`--rules-dir` で差し替え可能
4. **確信度の明示** — Feature ごとに `status` と `confidence` (0.0–1.0)
5. **JSON-first** — 機械可読が primary output

## Ethical Considerations

- **User-Agent**: HTTPS GET 時は `mailsec-probe/<ver>` を名乗る (偽装しない)
- **robots.txt**: MTA-STS 取得時もデフォルト尊重 (`--respect-robots=true`)
- **非侵襲的観測**: DNS と HTTPS のみ。SMTP / メールサーバへの直接接続は禁止
- **生鍵の秘匿**: DKIM 公開鍵などはデフォルトでハッシュ + 長さのみ。
  `--include-raw` で生 TXT を含める
- **レート制限**: DNS は per-server 50 qps、HTTPS は per-host 1 req/s

## Testing

- ユニットテスト + ゴールデンテスト (最低 4 ドメインケース)
- 外部ネットワーク依存テストは `//go:build integration` タグで分離
- テストファイルは `_test.go`
- DNS クライアントは interface 化しテスト時にモックを差し込む
- HTTP クライアントも interface 化し fixtures に差し替え可能

## Key Technical Decisions

- DNS: `miekg/dns` を使用 (直接問い合わせ、`--dns-server` 対応)
- HTTP: 標準 `net/http`
- YAML: `gopkg.in/yaml.v3`
- CLI: `cobra` + `viper`
- 並行制御: `golang.org/x/sync/errgroup`
- DNSSEC 検証 (Phase 3.0): `github.com/shigeya/dnsdata-go` (別 module、co-develop)
- 単一バイナリ、CGO 不要

## DKIM Selector Strategy

Phase 1.0 は **固定 selector 集合のみ**。`rules/dkim_selectors.yaml` に
高頻度な selector (google, s1, selector1, k1, protonmail, fm1 …) を埋め込み、
`--dkim-selector <name>` で追加、`--dkim-selectors-file` で差し替え可能。

「設定なし」と「selector が見つからなかった」を区別するため、
DKIM Feature の details には `selectors_tried` / `selectors_found` を必ず残す。

Phase 1.5 で SPF レコード (`include:_spf.google.com` 等) から
selector を推定する強化を予定。
