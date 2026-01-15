# Design Doc v1.0

（GitHub Actions + Python / NVD CVE API v2 / Slack Incoming Webhook）

---

## 1. 背景と目的

### 目的

* **脆弱性（CVE）を早期に検知**し、チームが迅速に一次判断できる状態を作る。
* **絞り込みは“ゆるく”**し、最終的な「対応が必要か」は **人がSlack上で判断**する。

### 基本方針

* “漏れにくさ（Recall）”を優先しつつ、運用が破綻しない程度にノイズを抑える。
* 絞り込みは

  * **分野：keywordSearch を複数クエリで回す**（watchlist.ymlで管理）
  * **深刻度：API側で High / Critical のみ**（クライアント側で baseScore 閾値は切らない）
* **重複投稿しない**（CVE ID ベース）
* **GitHub Actionsで1日1回**実行し、Slackへ投稿する。

---

## 2. スコープ

### スコープ内

* NVD CVE APIから、直近期間（例：過去24時間）に **Published** されたCVEを収集
* keywordSearch 複数クエリで取得対象を“分野”に寄せる
* APIパラメータで **Severity を High/Critical に限定**
* Slack通知（1件ずつ or バッチ）
* 既投稿管理（CVE ID）

### スコープ外（v1.0ではやらない）

* baseScoreによる最終足切り（やらない）
* lastModified追跡・更新差分通知（将来拡張）
* SBOMや依存関係解析による自動影響判定（将来拡張）
* DB導入（まずはGit管理のJSONで十分）

---

## 3. 要求仕様

### 3.1 実行環境

* GitHub Actions（cron）
* Python スクリプト（単体実行可能）
* シークレット管理：GitHub Actions Secrets

### 3.2 取得仕様（NVD）

* 取得対象期間：

  * デフォルト：**直近24時間**（例：`now-24h`〜`now`）
  * 失敗・遅延に備え、運用上は「**25〜30時間**」などにしてもよい（重複はpostedで排除）
* 分野絞り込み：

  * `keywordSearch` を **watchlist.yml の queries** で複数回実行
* 深刻度粗フィルタ：

  * API側で **High / Critical** のみに限定（例：`cvssV3Severity=HIGH` と `CRITICAL` を別リクエスト、またはAPIが複数指定を許すならまとめる）
* 並び順：

  * 取得後に **Published Date 降順**でソート（クライアント側確実化）

### 3.3 投稿仕様（Slack）

Slackに投稿する情報（1件あたり）：

* **CVE-ID**
* **Published（日時）**
* **CVSS（あれば）**（v3.x を優先、無ければ “N/A”）
* **一行要約**（description先頭を短く整形）
* **tags**（watchlist.yml の tag_rules で付与）
* **references**（上位2〜3件だけ）
* **NVDのURL**（NVD詳細ページへのリンク）

### 3.4 重複排除

* **CVE IDでのみ判定**（まずはこれで十分）
* 既投稿リストは `posted__{YYYYMMDD}_{channel}.json` のように日付付きファイルとしてリポジトリにコミット

  * ※ファイル命名は自由。要件は「Gitに残り、次回以降参照できること」
* 同一CVEが複数クエリで引っかかっても、**1回だけ投稿**

---

## 4. データ設計

## 4.1 watchlist.yml（分野クエリとタグ付け）

### 目的

* 分野を“ゆるく”表現し、クエリ追加/調整をコード変更なしで行えるようにする
* Slack表示用の tags を機械的に付与し、人の判断を早める

### フォーマット（v1.0）

```yaml
# watchlist.yml
queries:
  - "react"
  - "react-dom"
  - "next.js"
  - "vite"
  - "webpack"
  - "babel"
  - "npm"
  - "node.js"

tag_rules:
  react:
    - "react"
    - "react-dom"
  next:
    - "next.js"
  tooling:
    - "vite"
    - "webpack"
    - "babel"
  node:
    - "node"
    - "node.js"
    - "npm"
```

#### 仕様

* `queries`：NVDに投げる keywordSearch の検索語リスト

  * 1語でもよいが、**固有名（react-dom/next.js）を混ぜる**とノイズが減る
* `tag_rules`：タグ名 → そのタグを付けるためのキーワード群

  * description / reference URL / 製品名などから単純に含有判定（ゆるくてOK）

---

## 4.2 posted 既投稿ファイル

### フォーマット案（最小）

```json
{
  "posted_at": "2026-01-15T00:00:00Z",
  "cve_ids": [
    "CVE-2026-0001",
    "CVE-2026-0002"
  ]
}
```

#### 運用

* 実行時に read → 今回候補から差分抽出 → 投稿 → 更新 → commit/push
* “日付ファイル”にする場合でも、読み込み対象は「最新 or N日前まで」を決めておく

  * v1.0の簡単運用：**最新1ファイルのみ**を参照する設計が楽
  * 日付ファイルを残す場合は、参照は “直近N日分のunion” でも良い（N=7など）

---

## 5. アーキテクチャ

### 5.1 構成

* `.github/workflows/cve_watch.yml`

  * cronで起動、Pythonスクリプトを実行
* `scripts/cve_watch.py`

  * watchlist読込 → NVD API呼び出し → 正規化 → マージ/重複排除 → ソート
  * posted読込 → 未投稿抽出 → Slack投稿 → posted更新
* `watchlist.yml`
* `posted/posted__*.json`（または `posted.json` の単一ファイル）

### 5.2 外部I/F

* NVD API（HTTPS GET）
* Slack Incoming Webhook（HTTPS POST）

---

## 6. 処理フロー

1. **watchlist.yml** を読み込む
2. 実行ウィンドウ（`pubStartDate` / `pubEndDate`）を決める
3. `queries` の各キーワードについて NVD API を呼ぶ

   * パラメータ：期間 + keywordSearch + severity（High/Critical）
4. すべてのレスポンスを統合し、**CVE IDで一意化**
5. CVEを正規化（必要情報を抽出）
6. `tag_rules` でタグ付け
7. **Published 降順**でソート
8. postedファイルを読み込み、既投稿CVEを除外
9. 残ったCVEをSlackへ投稿
10. postedファイルを更新し、Gitへコミットしてpush

---

## 7. 正規化仕様（CVE 1件を Slack投稿用に整形）

### 入力（NVD）

* CVEデータには複数のメトリクス（CVSS v3.1/v3.0/v2 等）があり得る
* description は言語別に複数ある（EN優先、無ければ先頭）

### 出力（内部表現例）

```json
{
  "cve_id": "CVE-2026-0001",
  "published": "2026-01-15T01:23:45.000Z",
  "cvss": {
    "version": "3.1",
    "base_score": 9.8,
    "severity": "CRITICAL"
  },
  "summary": "Short description ...",
  "tags": ["react", "tooling"],
  "references": ["https://...", "https://..."],
  "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
}
```

### 抽出ルール（推奨）

* CVSS：v3.1 → v3.0 → v2 の順で採用、無ければ `N/A`
* summary：description先頭を 200〜300文字程度で切る（Slack可読性優先）
* references：最大3件（先頭から、または“ドメイン優先”で選ぶ拡張余地あり）
* nvd_url：固定フォーマットで生成

---

## 8. Slack 投稿フォーマット

### 8.1 1件投稿（シンプル）

* 未投稿が少ない前提なら 1CVE = 1投稿でOK（読みやすい）
* 多い日はスパムになり得る → 将来はバッチ化（v1.1）

### 8.2 推奨表示（例）

* 先頭に優先度のヒント（severity）
* タグを視認しやすく
* URLは NVD + 参考（上位2〜3）

（実装時はBlock Kitでも良いが、v1.0はテキストでも十分）

---

## 9. GitHub Actions 設計

### 9.1 スケジュール

* 1日1回（例：JST 朝9時）
* 失敗時の再実行を考えるなら、同日にもう1回（任意）

### 9.2 Secrets

* `NVD_API_KEY`（任意だが推奨）
* `SLACK_WEBHOOK_URL`（必須）

### 9.3 Git commit/push

* posted更新をコミットするため、Actionsに push 権限が必要
* 競合リスクは低いが、並列実行を避けるため `concurrency` を設定推奨

---

## 10. エラー処理と運用上の注意

### 10.1 NVD API

* レート制限・タイムアウト：リトライ（指数バックオフ）を用意
* 部分失敗：

  * あるクエリが失敗しても他クエリは続行し、最終的に「取得できた分」だけ投稿
  * 失敗したクエリは Slack に “監視失敗” として別通知してもよい（将来拡張）

### 10.2 Slack

* Webhook失敗時：投稿できていないのに posted を更新しない（重要）
* 投稿順：Published降順

### 10.3 postedファイル

* posted更新は “投稿成功後”
* 破損時は空扱い（ただし投稿が増える）

---

## 11. 将来拡張（v1.1+）

* **バッチ投稿**（例：1実行で最大N件、残りは要約1件）
* **lastModified追跡**（スコア付与/更新を拾う）
* **referenceのドメイン優先**（GitHub Advisory / vendor advisory を優先）
* **タグ精度向上**（descriptionだけでなく references や vendor/product 名も利用）
* **チャンネル分割**（high/critical、未評価など）
* **依存関係との照合**（SBOMやパッケージリストと照合して “影響ありそう” をハイライト）

---

## 12. リポジトリ構成案

```
repo/
  .github/
    workflows/
      cve_watch.yml
  scripts/
    cve_watch.py
  watchlist.yml
  posted/
    posted__20260115_main.json
```
