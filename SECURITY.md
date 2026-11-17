# セキュリティについて / Security Policy

## 脆弱性の報告

脆弱性を見つけた場合は、公開の Issue ではなく、GitHub の **Private vulnerability reporting**(リポジトリの Security タブ → "Report a vulnerability")から報告してください。再現できる pcap(または pcap を生成するスクリプト)を添えていただけると助かります。実データを含む pcap は送らず、必ず合成データにしてください。

個人が運営するプロジェクトのため、対応は best effort です。

## 信頼できない pcap を処理するとき

pcapreasm は外部入力(pcap)を読むライブラリです。0.2.2 では次を確認しています。

- 壊れた入力(バイト列をランダムに書き換えた入力、途中で切れた入力)で想定外の例外を出さないこと(`tests/test_robustness.py`)。
- 細工された入力による CPU の二次計算量が起きないこと(IP フラグメント、FIN 後の TCP。順序が逆のセグメントを含む)。
- `eval` や外部へのネットワークアクセスを一切行わないこと。

それでも、信頼できない pcap を扱うときは次の対策を入れてください。

- メモリ上限を必ず設定する(既定は無制限です)。`max_conversations`、`max_conversation_bytes`、`max_total_bytes`、`idle_timeout`、`max_fragment_sets` を設定してください。`segment_overhead_bytes` の既定(150)は、小さなセグメントが多い入力でも上限が実メモリに近づくための値です(`0` にしないでください)。
- コマンドラインの `--udp` は、UDP フローごとにメモリを使い、`--max-memory-mb` の対象外です。信頼できない入力では付けないか、別プロセスの制限(下記)を併用してください。
- 処理を別プロセスにして、CPU 時間・メモリ・実行時間(`ulimit` / `resource` / コンテナの制限)で制限する。
- 上限に達すると、ストリームが分割されて通知されます。`meta.evict_reason` を確認してください。
- analyzer 側で、受け取った `data` を信頼しない(復号・解凍・デシリアライズ前に長さや形式を検証する)。

## 対象バージョン

最新の 0.2.x のみ修正の対象です。
