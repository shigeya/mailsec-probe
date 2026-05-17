# mailsec-probe — 設計書

## 1. 概要

指定したドメインに対し、メールセキュリティ関連の DNS レコードおよび
公開ポリシ (MTA-STS) を**外部観測**し、各機能の有無・健全性・確信度を
構造化された結果として返す Go 製 CLI ツール。

- モジュールパス案: `github.com/shigeya/mailsec-probe`
- バイナリ名: `mailsec-probe`
- 言語: Go 1.22+ / 単一バイナリ / CGO 不要

## 2. 設計思想

1. **観測と判定の分離** — 観測器は中立的な Signal を生成、判定はルールエンジン
2. **非侵襲デフォルト** — DNS 問い合わせと HTTPS GET のみ。SMTP 接続は `--active`
3. **ルールの外部化** — YAML を `go:embed`、`--rules-dir` で差し替え可能
4. **確信度の明示** — 各機能ごとに `present / absent / unknown` と confidence (0.0–1.0)
5. **JSON-first** — 機械可読が primary output。human format はサブセット

## 3. 何を観測するか (Phase 1 = MVP)

| # | 機能 | 観測点 | 主要な解釈 |
|---|------|--------|------------|
| 1 | **SPF** | `TXT @ <domain>` で `v=spf1 ...` | mechanism, qualifier (`-all`/`~all`/`?all`/`+all`), 含まれる include/redirect |
| 2 | **DMARC** | `TXT @ _dmarc.<domain>` で `v=DMARC1; ...` | `p=` (none/quarantine/reject), `sp=`, `pct=`, `rua=`, `ruf=`, `aspf=`, `adkim=` |
| 3 | **DKIM** | `TXT @ <selector>._domainkey.<domain>` で `v=DKIM1; ...` | 鍵タイプ (rsa/ed25519)、鍵長、`t=`, `s=` |
| 4 | **MX** | `MX @ <domain>` | preference 順のホスト一覧 |
| 5 | **MTA-STS** | `TXT @ _mta-sts.<domain>` + `https://mta-sts.<domain>/.well-known/mta-sts.txt` | `id=`, `mode=` (enforce/testing/none), `mx:`, `max_age` |
| 6 | **TLS-RPT** | `TXT @ _smtp._tls.<domain>` で `v=TLSRPTv1; ...` | `rua=` (mailto/https) |
| 7 | **BIMI** | `TXT @ default._bimi.<domain>` で `v=BIMI1; ...` | `l=` (logo SVG URI), `a=` (VMC URI) |
| 8 | **DNSSEC** | クエリ応答の AD ビット、DS の有無 | ゾーンが署名済みか否か |

### スコープ外 (Phase 1 では実装しない)

- 実 SMTP 接続による STARTTLS / 証明書 / 暗号スイートの確認
- DANE/TLSA 検証
- MTA-STS ポリシで宣言された MX と実 MX の一致確認のうち、**SMTP 側まで踏み込む検証**
  (DNS と HTTPS 範囲の一致確認は MVP に含める)
- 鍵ローテーション履歴
- 一括処理 (CSV/JSON ファイル入力)
- ベイズ的なスコア統合 (将来 `internal/classifier` で導入)

## 4. DKIM の扱い (設計上の最大の難所)

DKIM レコードは `<selector>._domainkey.<domain>` という階層にあり、
**selector を知らないと観測できない**。DNS には「全 selector 列挙」が無い。

### 採るアプローチ

1. **デフォルト selector 集合をプローブ** — 経験的に高頻度なもの:
   `google`, `s1`, `s2`, `selector1`, `selector2`, `k1`, `k2`,
   `mail`, `default`, `dkim`, `mandrill`, `mxvault`, `everlytickey1`,
   `everlytickey2`, `protonmail`, `protonmail2`, `protonmail3`,
   `mlsend`, `zoho`, `fm1`, `fm2`, `fm3` …
   → `rules/dkim_selectors.yaml` で外部化、`--dkim-selectors` で上書き
2. **ユーザ指定** — `--dkim-selector <name>` (複数可)
3. **MX/SPF からの推定** — 例: SPF に `include:_spf.google.com` があれば
   `google` selector を優先試行。これは Phase 1.5 候補。
4. **観測結果の明示** — 「unknown - no selector matched」を結果として
   許容し、誤って「DKIM 未設定」と断じない。
   confidence は `unknown` で 0.0、`absent (all known selectors tried)` で 0.5 程度。

### 出力例 (DKIM)
```json
{
  "feature": "dkim",
  "status": "present",
  "confidence": 0.95,
  "details": {
    "selectors_tried": ["google", "s1", "selector1", "k1"],
    "selectors_found": ["google"],
    "records": [
      {
        "selector": "google",
        "key_type": "rsa",
        "key_size": 2048,
        "raw": "v=DKIM1; k=rsa; p=MIIBIjANBgkqh..."
      }
    ]
  }
}
```

## 5. CLI 仕様

### サブコマンド/呼び出し

```
mailsec-probe <domain>                       # 単一ドメインを観測
mailsec-probe <d1> <d2> ...                  # 複数 (各々独立に並行実行)
mailsec-probe --input list.txt               # ファイルから読み込み
mailsec-probe --input - < list.txt           # stdin から
```

### 主要フラグ (実装済み)

| フラグ | デフォルト | 用途 |
|--------|------------|------|
| `--output, -o` | `human` | `human` / `json` / `tsv` |
| `--color` | `auto` | `auto` / `always` / `never` (NO_COLOR 環境変数尊重) |
| `--input` | (なし) | ドメインリストファイル (`-` で stdin)。positional args とマージ重複排除 |
| `--stats` | `false` | 横断統計を末尾に追加 (human/tsv/json 全対応) |
| `--dns-server` | システム解決器 | `1.1.1.1:53` のような明示指定 |
| `--dkim-selector` | (なし、複数可) | 試行する selector を追加 |
| `--dkim-selectors-file` | (組み込み YAML) | selector 集合の差し替え |
| `--no-spf-inference` | `false` | SPF 由来の DKIM selector 推定を無効化 |
| `--no-rua-check` | `false` | DMARC `rua=` の HTTPS HEAD 到達性チェックを無効化 |
| `--timeout` | `10s` | 単一観測のタイムアウト |
| `--concurrency` | `8` | ドメイン横断の並列度 |
| `--include-raw` | `false` | 出力に生 TXT 文字列を含めるか |
| `--active` | `false` | SMTP STARTTLS + DANE 能動プローブを有効化 |
| `--smtp-port` | `25` | active プローブの SMTP ポート |
| `--smtp-timeout` | `10s` | per-MX SMTP タイムアウト |
| `--ehlo-name` | `mailsec-probe.local` | EHLO で名乗る名前 |
| `-v`, `-vv` | Warn / Debug | slog レベル |

### 終了コード (実装済み)

- `0` — 全ドメインで何らかの Feature が取れた
- `1` — いずれかのドメインで観測自体が失敗した (全 Feature が unknown 等)
- `2` — フラグ解釈エラー

## 6. ディレクトリ構成 (実装済み)

```
cmd/mailsec-probe/         エントリポイント (main.go)
internal/cli/              cobra コマンド定義 + --input パーサ
internal/probe/            観測器
  dnsclient/                 共通 DNS クライアント (TXT / MX / TLSA / DS) + Mock
  httpfetcher/               共有 HTTPS Fetcher (Get + Head) — mtasts と dmarc が利用
  spf/                       TXT @ apex を引いて v=spf1 を抽出
  dmarc/                     TXT @ _dmarc.<d> + rua= HTTPS HEAD
  dkim/                      固定 selector ループ + SPF inference
  mx/                        MX レコード (RFC 7505 null MX 対応)
  mtasts/                    DNS TXT + HTTPS GET + MX 一致性
  tlsrpt/                    TXT @ _smtp._tls.<d>
  bimi/                      TXT @ default._bimi.<d>
  dnssec/                    AD ビット / DS
  mtatls/                    (active 専用) STARTTLS + cert + DANE/TLSA
  txttag/                    tag=value 形式 TXT 共通パーサ
internal/signals/          中立的な Signal 型
internal/classifier/       probe を flatten して Report を組み立て
internal/output/           human / json / tsv フォーマッタ + stats + color
rules/                     埋め込み YAML
  dkim_selectors.yaml             固定 selector 集合
  dkim_selector_inference.yaml    SPF→selector マッピング
testdata/                  fixtures + golden (classifier/testdata)
docs/
  ARCHITECTURE.md            レイヤ / 型 / probe 追加手順
  DKIM_SELECTORS.md          selector 戦略の根拠と実装状態
```

## 7. Signal 型と Feature 判定

### Signal (観測結果, 中立)

```go
type Signal struct {
    Source   string            // "dns_txt" / "https_get" / "dns_mx"
    Target   string            // 問い合わせ先 (FQDN, URL)
    OK       bool              // 取得自体に成功したか
    Records  []string          // 生レコード列
    Meta     map[string]string // RCODE, AD ビット, HTTP ステータス等
    Err      string            // OK=false のときの理由
}
```

### Feature (判定後)

```go
type Feature struct {
    Name       string   // "spf" / "dmarc" / "dkim" / "starttls" / "dane" / ...
    Status     Status   // "present" / "absent" / "unknown" / "misconfigured"
    Confidence float64  // 0.0–1.0
    Reasons    []string // なぜその結論に達したか (人間向け)
    Details    any      // 機能ごとの構造化詳細 (各 probe で定義)
    Signals    []Signal // 判定の元になった観測
}
```

### Probe interface

```go
type Probe interface {
    Name() string
    Run(ctx context.Context, domain string) []signals.Feature  // 複数 Feature 返却可
}
```

ほとんどの probe は単一要素スライスを返す。`mtatls` は 1 つの SMTP
セッションから `starttls` と `dane` の 2 Feature を返す。

### 最終結果

```go
type Report struct {
    Domain    string
    QueriedAt time.Time
    Features  []Feature
    Errors    []string // 観測中の致命的エラー
}
```

## 8. ルールの形 (YAML)

例: `rules/dmarc_health.yaml`

```yaml
feature: dmarc
rules:
  - id: dmarc-reject
    when: { tag: p, equals: reject }
    set: { health: strong, confidence_delta: +0.1 }
  - id: dmarc-quarantine
    when: { tag: p, equals: quarantine }
    set: { health: moderate }
  - id: dmarc-none
    when: { tag: p, equals: none }
    set: { health: weak, reason: "monitor-only policy" }
  - id: dmarc-no-rua
    when: { tag: rua, missing: true }
    set: { reason: "no aggregate reporting endpoint" }
```

ルールは「観測値を入力に、Feature の `Status` / `Confidence` / `Details` を
逐次更新する」純粋関数として実装。

## 9. 並行制御

- ドメイン横断: `errgroup` で `--concurrency` 並列
- ドメイン内: 8 機能を `errgroup` で並列 (DNS 問い合わせ 7 件 + HTTPS 1 件)
- DKIM だけは selector 集合のサブ並列 (最大 8) を別途持つ
- DNS クライアントは共通のキャッシュ付きラッパ (`internal/probe/dns`)
  を全機能で共有

## 10. エシカル考慮

- **User-Agent**: HTTPS GET 時は `mailsec-probe/<ver>` を名乗る
- **robots.txt**: `--respect-robots=true` (デフォルト)
- **非侵襲**: DNS と HTTPS のみ。SMTP 接続は `--active` 必須
- **生レコード秘匿**: DKIM 公開鍵などは長大かつ生っぽいので、デフォルトでは
  ハッシュ + 長さのみ。`--include-raw` で生 TXT を含める
- **レート**: DNS は per-server で 50 qps 上限、HTTPS は per-host 1 req/s

## 11. テスト戦略

- ユニット: 各 probe の parser を `_test.go` で
- ゴールデン: `testdata/domains/<name>/` 配下に DNS モックと期待 JSON を置き、
  少なくとも以下のドメイン相当を含める
  - `google.com` 相当 (SPF/DMARC/DKIM/MTA-STS フル装備)
  - `<no-mx>.example` 相当 (MX 不在)
  - `<spf-only>.example` (SPF はあるが DMARC なし)
  - `<dmarc-none>.example` (DMARC p=none のみ)
- 統合: `//go:build integration` で実 DNS / 実 HTTPS。CI では別ジョブ
- DNS クライアントは interface 化し、テスト時にモックを差し込む

## 12. 出力例 (human)

```
$ mailsec-probe example.jp

example.jp
├─ SPF       PRESENT      conf=0.95   v=spf1 include:_spf.example.jp ~all
├─ DMARC     PRESENT      conf=0.95   p=quarantine; rua=mailto:dmarc@example.jp
├─ DKIM      PRESENT      conf=0.90   selectors: google, selector1
├─ MX        PRESENT      conf=1.00   10 mx1.example.jp., 20 mx2.example.jp.
├─ MTA-STS   PRESENT      conf=0.90   mode=enforce, max_age=604800
├─ TLS-RPT   ABSENT       conf=0.80   no TXT at _smtp._tls.example.jp
├─ BIMI      ABSENT       conf=0.80   no TXT at default._bimi.example.jp
└─ DNSSEC    PRESENT      conf=1.00   AD bit set, DS in parent
```

## 13. 出力例 (JSON, 抜粋)

```json
{
  "domain": "example.jp",
  "queried_at": "2026-05-17T09:30:00+09:00",
  "features": [
    {
      "name": "spf",
      "status": "present",
      "confidence": 0.95,
      "reasons": ["v=spf1 found at apex", "qualifier=~all (softfail)"],
      "details": {
        "qualifier": "softfail",
        "includes": ["_spf.example.jp"],
        "raw": "v=spf1 include:_spf.example.jp ~all"
      }
    }
  ]
}
```

## 14. 開発フェーズ (現状: Phase 2.5 完了)

| Phase | 状態 | スコープ |
|-------|------|----------|
| **1.0** | ✅ 実装済み | SPF / DMARC / DKIM (固定 selector) / MX / MTA-STS / TLS-RPT / BIMI / DNSSEC (AD ビットのみ)、json/human 出力、ゴールデンテスト |
| **1.5** | ✅ 実装済み | SPF → DKIM selector 推定 (`--no-spf-inference` で無効化)、DMARC `rua=` の HTTPS HEAD 到達性 (`--no-rua-check`)、MTA-STS policy の `mx:` パターンと実 MX の一致性 |
| **2.0** | ✅ 実装済み | `--active`: SMTP STARTTLS / 証明書観察 / PKIX 検証 / DANE/TLSA 照合 (Usage 3 = DANE-EE は厳密、Usage 0/2 は観察のみ) |
| **2.5** | ✅ 実装済み | `--input <file>` バッチ (`-` で stdin)、`--output tsv`、`--stats` 横断統計、ANSI カラー出力 (`--color auto\|always\|never`) |
| **3.0** | 🛠 計画中 | DNSSEC chain validation を `github.com/shigeya/dnsdata` (別 module で co-develop) 経由で導入。Phase 1.0 の AD ビット観測モードは `--dnssec-mode ad-only` として残す。詳細は §16 |
| **3.x** | 候補 | 下記 §17 参照 |

### Phase 1.5 で見つけた事実

- example.com (IANA) は `<任意>._domainkey.example.com` に `v=DKIM1; p=` のワイルドカードを返す → revoked-wildcard として ABSENT 扱いに修正
- example.com は RFC 7505 null MX (`0 .`) → MX 機能の `null MX` ガード追加
- Google は古い DKIM selector (`20161025` / `20210112` / `20221208` / `20230601`) を**全部 revoke** に切替済み — selector rotation の現実を確認、`rules/dkim_selector_inference.yaml` に最新候補を継続追加する運用が必要

### Phase 2.0 で見つけた事実

- nlnetlabs.nl (mailbox.org backend) は 3/3 MX が DANE-EE で TLSA 検証通過。実例として integration テストに採用
- google.com は MTA-STS enforce / TLS 1.3 / PKIX valid だが DANE 未採用
- DANE 普及率はまだ低く、メジャーなプロバイダ (Fastmail / Google) も未採用

## 15. 決定事項 (実装で確定)

| # | 項目 | 決定 |
|---|------|------|
| 1 | ツール名 / バイナリ名 | `mailsec-probe` |
| 2 | モジュールパス | `github.com/shigeya/mailsec-probe` |
| 3 | DKIM selector 戦略 | 固定集合 + SPF inference (Phase 1.5 実装済み) |
| 4 | DNSSEC | Phase 1.0–2.5 は AD ビット + DS のみ。Phase 3.0 で `dnsdata` 経由の chain validation を導入し、BOGUS / INSECURE を区別 |
| 5 | 入力単位 | ドメインのみ。`user@domain` は受け付けない |
| 6 | BIMI 深さ | TXT パースまで。VMC 検証は Phase 3 候補 |
| 7 | 出力 | human / json / tsv の 3 形式。`--stats` で各形式に集計付加 |
| 8 | 倫理 | 非侵襲がデフォルト。SMTP は `--active` 必須、EHLO で自己同定、メール送信なし |
| 9 | Probe interface | `Run` は `[]signals.Feature` 返却 (mtatls が STARTTLS + DANE の 2 feature を 1 接続で出すため) |

## 16. Phase 3.0 計画 — DNSSEC validation via dnsdata

### 背景

Phase 1.0 の DNSSEC probe は **AD ビット + DS の有無のみ** を観測しており、
署名失敗 (BOGUS) を検出できない。実用上、misconfigured な DNSSEC ゾーンを
SECURE と区別できないのは観測ツールとして弱い。

Phase 3.0 では DNSSEC chain validation を **`dnsdata` に委譲** する形で導入する。

### 依存先

`github.com/shigeya/dnsdata` — 別 module として開発する Go DNS / DNSSEC library。
TypeScript の `dnsjs` (wide-cpp-lib 由来) を Go に純血ポートしたもの。
mailsec-probe と co-develop する (両 repo を同一作者が所有)。

```
mailsec-probe (this repo)
    └─ depends on → github.com/shigeya/dnsdata/verifier  (DNSSEC chain validator)
                  → github.com/shigeya/dnsdata/dnssec    (DNSKEY/RRSIG/DS primitives)
                  → github.com/shigeya/dnsdata/resolver  (DoH / authoritative DNS)
```

### 検証範囲

- root trust anchor (KSK-2017 + KSK-2024 を埋め込み) からの **chain of trust 検証**
- 結果は `Secure | Insecure | Bogus | Indeterminate` の 4 値
- insecure delegation (chain の途中で DS が無くなる) を BOGUS と区別

### dnsdata に対する Requirements

mailsec-probe (= consumer) が dnsdata に求める API 契約。
`dnsdata` 側 DESIGN.md / Issue にも転記し、co-design の北極星にする。

#### MUST

1. `Validate(ctx, qname, qtype) → (*Result, error)` がゴルーチン安全
2. `Result.Verdict` は `Secure | Insecure | Bogus | Indeterminate` の enum
3. `Result.Chain` に各 zone の DNSKEY/DS タグ・アルゴリズム・RRSIG 検証結果
4. `Result.InsecureAt` / `Result.BogusAt` で問題発生点を string で返す
5. `Result.Evidence` に取得した DS/DNSKEY/RRSIG の生情報 (mailsec-probe の Signal に流す)
6. `context.Context` で cancel / deadline を伝播
7. trust anchor のソースを caller が指定可能 (`WithTrustAnchors(io.Reader)` 等)
8. DoH provider をスライスで渡せる (Google / Cloudflare / Quad9 を順次フェイルオーバ)
9. 権威 NS への直接問い合わせモードを持つ (mailsec-probe の `--dns-server` 連携)
10. `Result` が `encoding/json` でそのままマーシャル可能
11. `Verdict.String()` が `"secure"` / `"insecure"` / `"bogus"` / `"indeterminate"`
12. エラーは `errors.Is` 可能な sentinel (`ErrNoDS`, `ErrSigExpired`, `ErrUnsupportedAlgo`, `ErrChainTimeout`, ...)

#### SHOULD

13. キャッシュ層を差し込み可能 (`WithCache(c Cache)`)。バッチ実行で root/TLD DNSKEY を再利用
14. 検証ステップを stream で吐ける (`WithStepHandler(func(StepEvent))`)。verbose ログ用
15. RR type は `uint16` で受ける (miekg/dns 互換)
16. 100 ドメイン並列でも許容範囲のメモリ効率

#### MAY (将来)

17. `miekg/dns.RR` への変換 helper (エコシステム相互運用)
18. NSEC/NSEC3 を使った aggressive negative caching (RFC 8198)
19. RFC 5011 ベースの trust anchor 自動更新

#### MUST NOT

20. `os.Exit` を呼ばない
21. `init()` で副作用を出さない (logger 取得等)
22. グローバル状態を持たない (複数 Verifier を独立に使える)
23. デフォルトでファイルシステム書き込みをしない (明示指定時のみ `~/.dnsdata/` 等を触る)
24. stdout / stderr に何も書かない (caller が好きな logger に流す)

### 新 dnssec probe の API モック (mailsec-probe 側)

```go
// internal/probe/dnssec/dnssec.go (Phase 3.0 後の想定)
package dnssec

import (
    "context"

    "github.com/miekg/dns"
    "github.com/shigeya/dnsdata/verifier"
    "github.com/shigeya/mailsec-probe/internal/signals"
)

type Probe struct {
    V *verifier.Verifier
}

func New(v *verifier.Verifier) *Probe { return &Probe{V: v} }

func (*Probe) Name() string { return "dnssec" }

func (p *Probe) Run(ctx context.Context, domain string) []signals.Feature {
    r, err := p.V.Validate(ctx, domain+".", dns.TypeTXT)
    if err != nil {
        // StatusUnknown + Reasons に err.Error()
    }
    switch r.Verdict {
    case verifier.Secure:
        // StatusPresent, confidence 0.95
        // Reasons: "DNSSEC chain validated from root"
    case verifier.Insecure:
        // StatusAbsent, confidence 0.9
        // Reasons: "insecure delegation at <r.InsecureAt>"
    case verifier.Bogus:
        // StatusMisconfigured, confidence 0.95
        // Reasons: "BOGUS at <r.BogusAt>: <r.BogusReason>"
    case verifier.Indeterminate:
        // StatusUnknown
    }
    // r.Evidence を Signal[] に変換
    // r.Chain を Details に格納
}
```

### `signals.Status` の拡張

Phase 3.0 で **`StatusMisconfigured`** を `internal/signals/signals.go` に追加する。
DNSSEC BOGUS 以外にも将来 MTA-STS の policy / MX 不一致や DKIM 鍵長不足等で再利用可能。

### CLI への影響

- 新フラグ `--dnssec-mode {ad-only,validate}` (デフォルト `validate`)
  - `ad-only` で Phase 1.0 互換挙動 (AD ビット + DS のみ)
  - `validate` で dnsdata 経由の chain validation
- 新フラグ `--dnssec-doh-providers google,cloudflare,quad9` (デフォルト 3 つ順次)
- 既存 `--dns-server` 指定時は、dnsdata の権威 NS 直接問い合わせモードへ自動切替

### golden test への影響

`testdata/domains/<name>/golden.json` の `dnssec` Feature 部が変わるため再生成が必要。
dnsdata 側で対応する `testdata/` (chain 検証済みの DNS 応答 fixture) を整備し、
mailsec-probe 側も Mock DNS / Mock DoH で同じ fixture を共有する方針とする。

### スケジュール想定

| 週 | dnsdata 側 | mailsec-probe 側 |
|---|---|---|
| Week 1 | repo 初期化、`types/`, `wire/`, `zone/` の最小構成、テスト | (なし) |
| Week 2 | `dnssec/` 全部 (DNSKEY/RRSIG/DS/NSEC/anchors)、`resolver/doh/` | (なし) |
| Week 3 | `verifier/chain.go` (chain walker)、`v0.1.0` タグ | `--dnssec-mode validate` 実装、`internal/probe/dnssec/` 差し替え、golden 再生成 |

進捗共有とセッション分担は `dnsdata` 側 repo の CLAUDE.md / DESIGN.md を参照。

## 17. Phase 3.x 以降の候補 (未着手)

- **BIMI VMC 検証** — `a=` の URI から VMC を取得し、x509 として鍵を抽出、BIMI Indicator の認証チェーンを検証
- **STARTTLS の暗号スイート評価** — 弱い cipher / TLS 1.0/1.1 許容を `misconfigured` に格下げ
- **MTA-STS report consumer 視点のテスト** — TLS-RPT で実際にレポートを受け取るエンドポイントを提供
- **DKIM 鍵の脆弱性チェック** — 1024-bit RSA や exponent=3 を `misconfigured` 寄りに
- **共有 DNS キャッシュ** — SPF probe と DKIM inference の TXT lookup を重複させない (今は 1 ドメインあたり 2 回 TXT を引いている)
- **CI (GitHub Actions + `golangci-lint`)** — repo 公開と同時に
- **TLSA Usage 0 / 2 (trust-anchor) の厳密検証** — 現在は Usage に関わらず leaf cert の hash 一致のみで判定
