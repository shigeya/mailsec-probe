# mailsec-probe — 設計書

## 1. 概要

指定したドメインに対し、メールセキュリティ関連の DNS レコードおよび
公開ポリシ (MTA-STS) を**外部観測**し、各機能の有無・健全性・確信度を
構造化された結果として返す Go 製 CLI ツール。




- モジュールパス案: `github.com/shigeya/mailsec-probe`
- バイナリ名: `mailsec-probe`
- 言語: Go 1.22+ / 単一バイナリ / CGO 不要

## 2. 設計思想 ( と共通)

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
mailsec-probe <domain>                # 単一ドメインを観測
mailsec-probe <domain1> <domain2> ... # 複数 (各々独立に並行実行)
```

### 主要フラグ

| フラグ | デフォルト | 用途 |
|--------|------------|------|
| `--output, -o` | `human` | `human` / `json` |
| `--dns-server` | システム解決器 | `1.1.1.1:53` のような明示指定 |
| `--dkim-selector` | (なし、複数可) | 試行する selector を追加 |
| `--dkim-selectors-file` | (組み込み YAML) | selector 集合の差し替え |
| `--rules-dir` | (組み込み YAML) | ルールセット差し替え |
| `--respect-robots` | `true` | MTA-STS HTTPS GET 時の robots 尊重 |
| `--timeout` | `10s` | 単一観測のタイムアウト |
| `--concurrency` | `8` | ドメイン横断の並列度 |
| `--include-raw` | `false` | 出力に生 TXT 文字列を含めるか |
| `--active` | `false` | (将来) SMTP STARTTLS 等の能動プローブ |
| `-v`, `-vv` | Warn / Debug | slog レベル |

### 終了コード

- `0` — 全観測が成功 (機能の有無に関わらず)
- `1` — DNS 解決自体が失敗した等、観測不能
- `2` — フラグ解釈エラー

## 6. ディレクトリ構成

```
cmd/mailsec-probe/         エントリポイント (main.go)
internal/cli/              cobra コマンド定義
internal/probe/            観測器
  dns/                       共通 DNS クライアント (miekg/dns)
  spf/                       TXT @ apex を引いて v=spf1 を抽出
  dmarc/                     TXT @ _dmarc.<d>
  dkim/                      selector ループ
  mx/                        MX レコード
  mtasts/                    DNS TXT + HTTPS GET の二段
  tlsrpt/                    TXT @ _smtp._tls.<d>
  bimi/                      TXT @ default._bimi.<d>
  dnssec/                    AD ビット / DS
internal/signals/          中立的な Signal 型
internal/rules/            YAML ローダ + matcher
internal/classifier/       Feature 単位の判定 (present/absent/unknown + confidence)
internal/output/           json / human フォーマッタ
rules/                     埋め込み YAML
  dkim_selectors.yaml
  spf_qualifiers.yaml
  dmarc_health.yaml
testdata/                  fixtures + golden テスト
  domains/<name>/dns.json    モック DNS 応答
  domains/<name>/golden.json 期待される出力
docs/
  ARCHITECTURE.md
  RULE_FORMAT.md
  SIGNALS.md
  DKIM_SELECTORS.md          selector 戦略の根拠
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
    Name       string   // "spf" / "dmarc" / "dkim" / ...
    Status     string   // "present" / "absent" / "unknown" / "misconfigured"
    Confidence float64  // 0.0–1.0
    Reasons    []string // なぜその結論に達したか (人間向け)
    Details    any      // 機能ごとの構造化詳細
}
```

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

## 10. エシカル考慮 ( と同様)

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

## 14. 開発フェーズ

| Phase | スコープ |
|-------|----------|
| **1.0** | SPF / DMARC / DKIM (デフォルト selector) / MX / MTA-STS / TLS-RPT / BIMI / DNSSEC, json/human 出力, ゴールデンテスト |
| **1.5** | SPF → DKIM selector 推定, DMARC `rua=` の到達性 (HTTP HEAD のみ), MTA-STS の DNS/HTTPS 一致性 |
| **2.0** | `--active`: SMTP STARTTLS, 証明書チェーン, DANE/TLSA |
| **2.5** | バッチ処理 (`--input domains.txt`), TSV 出力, 横断統計 |

## 15. 決定事項 (2026-05-17 確認済み)

| # | 項目 | 決定 |
|---|------|------|
| 1 | ツール名 / バイナリ名 | **`mailsec-probe`** |
| 2 | DKIM selector 戦略 | Phase 1.0 では**固定集合のみ**。SPF 由来の推定は Phase 1.5 以降 |
| 3 | DNSSEC | **AD ビットを見るだけ**。自前 DNSKEY/DS 検証は将来課題 |
| 4 | 入力単位 | **ドメインのみ**。`user@domain` 形式の受け付けは不要 |

## 16. 残課題 (実装着手前にもう少し詰めるとよい点)

- モジュールパス: `github.com/shigeya/mailsec-probe` で確定でよいか
- BIMI の深さ: TXT の有無と `l=` / `a=` のパースまでが Phase 1。
  VMC (Verified Mark Certificate) の有効性検証は Phase 2 送りで仮置き
- 出力フォーマット: human/json 以外に TSV を求めるか (Phase 2.5 案として置く)
