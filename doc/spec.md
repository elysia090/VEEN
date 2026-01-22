# VEEN Specification (SSOT)

この文書は VEEN の単一仕様（SSOT）です。`doc/reference.md` は旧仕様のアーカイブであり、非規範（参考）です。

## 0. 目的・適用範囲

- **目的**: VEEN のコア・オーバーレイ・運用・製品プロファイルを、構造的かつ明瞭に統合する。
- **適用範囲**: v0.0.1 コア、v0.0.1+ / v0.0.1++ オーバーレイ、CLI/運用、製品プロファイル（SDR0/AGB0）。
- **前提**: 本仕様のすべての外部公開 API/CLI は **O(1)/polylog n** を満たし、逐次依存は極小である。

## 1. 用語・命名（明確化・後方互換）

- **Hub**: 受理・順序付け・証明を提供する中継ノード。意味解釈は持たない。
- **StreamID**: アプリが定義する論理ストリーム識別子（32 bytes）。
- **Label**: Hub が順序付けする実ストリーム識別子。`Label = Ht("veen/label", routing_key || StreamID || epoch)`。
- **StreamSeq**: Label ごとの単調増加シーケンス。
- **ClientID**: Ed25519 公開鍵（MSG.sig の検証キー）。
- **ClientSeq**: `(Label, ClientID)` ごとの単調増加シーケンス。
- **ProfileID**: 暗号プロファイル設定のハッシュ。
- **CapToken**: 権限・TTL・レートを表す能力トークン。

**後方互換ルール（規範）**
- CLI: `veen` が正規。`veen-cli` は同等の別名として受け付ける。`veen hub start` が正規。旧 `veen-hub run/start` は同等動作。
- 版数: v0.0.1 が不変コア。v0.0.1+ / v0.0.1++ は追加のみ（上書き禁止）。

## 2. グローバル規約

### 2.1 エンコーディング
- **CBOR は決定的**: フィールド順序固定、最小整数、固定長 bstr、タグ禁止、未知キー拒否。

### 2.2 暗号プロファイル（最低要件）
- H: SHA-256
- HKDF: HKDF-SHA256
- AEAD: XChaCha20-Poly1305（本文）
- 署名: Ed25519
- DH: X25519
- HPKE: RFC9180 base (X25519-HKDF-SHA256 + ChaCha20-Poly1305)

**ProfileID** は上記パラメータの CBOR に対して `Ht("veen/profile", ...)` で計算。

### 2.3 性能規約（O(1)/polylog n）
**すべての外部操作**（送信、読み出し、証明、クエリ、検査、失効、ウォレット/ID など）は **O(1)** もしくは **O(polylog n)** を保証する。線形スキャンや順序再生に依存する運用パスは非準拠。

- **逐次依存の極小化**: フォールドは結合則を持つ `merge(S_left, S_right)` によって木構造で評価可能であること。
- **レンジ要約**: K 件単位の要約を保持し、`fold(range)` を O(polylog n) で構成。
- **ヘッドインデックス**: 各 Label の最新 `(StreamSeq, leaf_hash, checkpoint_ref)` を O(1) で参照可能。

## 3. コア・ワイヤ仕様（v0.0.1）

### 3.1 MSG（送信）
フィールド順序固定:
1. `ver` (uint=1)
2. `profile_id` (bstr32)
3. `label` (bstr32)
4. `client_id` (bstr32)
5. `client_seq` (uint, strictly +1)
6. `prev_ack` (uint)
7. `auth_ref` (bstr32, optional)
8. `ct_hash` (bstr32)
9. `ciphertext` (bstr)
10. `sig` (bstr64) = `Sig(client_id, Ht("veen/sig", CBOR(MSG without sig)))`

### 3.2 Ciphertext 生成（規範）
- `payload_hdr` と `body` は HPKE + AEAD で保護。
- Nonce は `Trunc_24(Ht("veen/nonce", label || prev_ack || client_id || client_seq))`。

### 3.3 RECEIPT（受理）
- Hub が MSG を受理した証明。必ず **署名**・**StreamSeq**・**MMR root** を含む。
- 受理後の状態を第三者が検証できること。

### 3.4 CHECKPOINT（ログ状態スナップショット）
- `log_root`, `per-stream last_seq`, `hub_pk`, `timestamp` を含む。
- MMR に整合すること。

### 3.5 MMR/証明
- MMR により `O(polylog n)` で inclusion proof を生成。
- proof は決定的・再現可能であること。

## 4. Hub の規範動作

### 4.1 受理パス
- `CapToken` 検証（署名/期限/レート/失効）
- `client_seq` の単調増加検証
- `label` に対する `StreamSeq` 付与
- 受理後に RECEIPT を発行

### 4.2 ログ・MMR
- 受理順序に従って append-only で記録。
- MMR root は各受理時点で更新。

### 4.3 エラー
- 受理拒否は決定的エラーコードで返す（例: `E.AUTH`, `E.RATE`, `E.SEQ`, `E.TIME`, `E.FORMAT`）。

## 5. クライアント動作

- **送信**: MSG 構築、署名、送信、RECEIPT 検証。
- **読み出し**: `stream(range)` と `stream(with_proof=1)` を提供。
- **検証**: RECEIPT/PROOF/Checkpoint を使って独立に検証可能。

## 6. オーバーレイ（v0.0.1+ / v0.0.1++）

### 6.1 Identity（ID）
- **主体/デバイス/コンテキスト/組織/グループ/ハンドル**はログ由来状態。
- セッションは **device key + cap_token chain + ID log** で検証可能であること。
- 失効（revocation）は ID ログにより決定的に評価。

### 6.2 Wallet / Paid Operations
- **残高・上限・凍結・調整**はすべてイベントのフォールドから導出。
- Hub は残高を保持しない（運用上の一貫性はオーバーレイ側が保証）。

### 6.3 Query API Overlay
- ログ由来状態に対する **構造化クエリ** を提供。
- すべての検索可能フィールドに **永続インデックス** を必須とし、フルスキャン禁止。

### 6.4 Products Overlay（SDR0 / AGB0）
- **SDR0**: 監査・証拠ログ用途。`record/*` ストリーム、チェックポイント、リプレイ API。
- **AGB0**: エアギャップ・ブリッジ用途。`export/*` → `import/*` の片方向/双方向転送を支援。
- どちらも **CapToken/Revocation/Checkpoint** による統制を必須とする。

### 6.5 補助オーバーレイ（運用系）
- **KEX0**: 鍵交換・共有に関する補助ログ。
- **AUTH1**: 認可/失効の基盤ログ。
- **ANCHOR0**: 外部アンカリング（監査証跡の外部固定）。
- **DR0**: DR/リカバリ補助ログ。
- **OBS0**: 観測性・運用メトリクスのログ。

## 7. CLI（運用 API）

**必須コマンド（規範）**
- `veen hub start|stop|status`（旧 `veen-hub` は互換）
- `veen send` / `veen stream` / `veen inspect`
- `veen bridge`（または `veen-bridge`）
- `veen selftest`（または `veen-selftest`）

**CLI 仕様**
- `--hub` は URL または data directory を受け付ける。
- `--data-dir` が指定された場合は hub 操作の参照先として優先。

## 8. 運用・デプロイ

- **OS**: Linux / WSL2 / Docker / k8s / k3s で同一の意味。
- **データ**: hub data directory は単純なディレクトリ。可搬性を保証。
- **観測性**: 受理遅延、証明生成、fsync を主要メトリクスとして公開。
- **可用性**: Hub は使い捨て可能。ログが真実の唯一の源。

## 9. セキュリティモデル

- **信頼境界**: クライアント鍵・Hub 公開鍵・署名・MMR が信頼の中心。
- **機密性**: ペイロードは AEAD/HPKE により Hub 非可視。
- **完全性**: MSG.sig と Hub 署名で保証。
- **失効/回転**: オーバーレイイベントと CapToken により決定的に評価。

## 10. 拡張・互換性

- 追加フィールド/エラーは **後方互換** が必須。
- 既存ログを再解釈して意味が変わる変更は禁止。

## 11. 非目標

- 汎用計算・スマートコントラクト
- ブロックチェーン型の合意形成
- 深いパケット解析や L7 ルーティング機能

## 12. 実装必須データ構造（抜粋）

- **MMR**: inclusion proof は O(polylog n)。
- **Index**: Label/StreamSeq/ClientSeq/Query-field すべて永続化。
- **Summaries**: chunk summary + merge tree による高速フォールド。
- **Cache**: cap_token/issuer/public key の TTL キャッシュ。

---

**注記**: `doc/reference.md` は旧仕様の完全なテキストを保存する参照資料であり、本 SSOT の規範性に影響しない。
