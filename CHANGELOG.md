# 変更履歴 / Changelog

形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に準拠し、バージョンは [セマンティック バージョニング](https://semver.org/lang/ja/) に従います。
0.1.x では **公開 API の後方互換を維持**します。バグ修正によって同じ入力に対する出力が変わる場合は、下記の「挙動の変更」に明記します。

## [0.1.0] - 未リリース

### 追加
- **パケットフィルタ**: `PcapStreamProcessor(filter_expr="tcp and port 80")` と `packet_filter=callable`。tcpdump 式の部分集合(`tcp` `udp` `ip` `ip6`、`[src|dst] host/net/port/portrange`、`and` `or` `not`、括弧)に対応。`compile_filter()` と `FilterSyntaxError` も公開。除外したパケットは TCP/UDP の状態を一切作らず、`stats["filtered"]` に数えられる。
- `process_stream(stream, ...)`: 開いたバイナリストリーム(`io.BytesIO`、`gzip.open(path, "rb")` など)から読み込む。
- `process_file` / `process_files` が `pathlib.Path` などの `os.PathLike` を受け付ける。
- `process_files(paths, on_error="skip")`: 読めないファイルを飛ばして続行し、最後に flush する。既定 `"raise"` は従来どおり。
- 例外クラス `PcapFormatError`(`ValueError` のサブクラス)、`AnalyzerError`、`FilterSyntaxError`。
- `raise_on_analyzer_error=True`: analyzer のコールバックで起きた例外をログで握りつぶさず `AnalyzerError` として送出する(既定は従来どおり握りつぶす)。
- `BaseAnalyzer.on_file_start(path)` / `on_file_end(path)`。
- `segment_overhead_bytes`: セグメントごとの管理分をメモリ上限の計算に加算する(既定 `0` = 従来どおりペイロードのみ)。
- snaplen で切り詰められたパケットの検出。`stats["truncated_packets"]` と、`TCPFlowMeta.truncated_segments`(欠損がパケットロスではなく切り詰めによるものか判断できる)。
- `stats` に `tcp_conversations`、`evict_<理由>`、`late_acks`、`failed_files`、`filtered`、`truncated_packets` を追加。
- 警告ログにファイル名を含めるようにした。
- pcapng / gzip / 未対応バージョン / ファイル短小のとき、原因と対処を示すエラーメッセージ。メッセージの先頭 `Invalid pcap global header` は従来のまま。
- `pyproject.toml`(`pip install` 対応)、GitHub Actions の CI、`SECURITY.md`、英語 README(`README.en.md`)、このファイル。

### 修正
- **CPU の二次計算量を解消(DoS になりうる入力)**: IP フラグメントの再構成と、FIN 後に欠損が埋まらない TCP 接続で、パケットごとに全断片を再ソートしていた。処理時間が件数の 2 乗で増え(実測: 8,000 個で約 3 秒、2 倍の件数で約 4 倍)、細工した数 MB の pcap が数分以上の CPU を占有できた(10 万個で約 8 分と外挿)。区間を増分で管理するよう変更した。
- 前の接続の FIN/RST を捕捉できなかったとき、同じ 4 つ組を再利用した新しい接続(特にサーバが先に話す SMTP・SSH など)が前の接続と 1 つに混ざり、データが再送として失われていた問題。新しい SYN の初期シーケンス番号が異なる場合や、反対方向にデータが残っている場合は別接続として扱う。SYN の再送(同じ初期シーケンス番号)は引き続き同じ接続。
- 片方だけが FIN を送った半クローズの接続が、`close_linger` を超えて相手が応答しないと途中で確定され、遅れて届いたデータが別の conversation としてクライアントとサーバが逆に割り当てられていた問題(`fin_timeout` は両方向が閉じた場合のみ)。
- 正常終了の最後の ACK が `late_packets` に数えられていた問題(`late_acks` に分離。データや SYN/FIN/RST を伴うものだけが `late_packets`)。
- 壊れた・途中で切れた gzip を `process_stream` に渡すと `EOFError` などがそのまま飛んでいた問題。切れた pcap と同様に警告を出し、読めた分までを処理して `stats["read_errors"]` に数える。
- mypy `--strict` が報告していた型注釈の不足。

### 挙動の変更(バグ修正に伴うもの)
- フィルタ式: `and` / `or` の連鎖の長さに制限はないが、括弧・`not` の入れ子は 100 段まで(超えると `FilterSyntaxError`)。ポート番号は ASCII の数字のみ。
- 新しい接続の判定: 同じ初期シーケンス番号の SYN は再送とみなすが、その方向がすでにデータを送っていれば新しい接続とする。クライアントの初期シーケンス番号が同じで、サーバ側のデータしか無い再利用は区別できず、再送として扱う。
- 上記の修正により、該当する入力に限り、同じ pcap でも出力が変わる(conversation の数、`evict_reason`、`client_certain`、`stats["late_packets"]`)。
- 半クローズで相手が応答しないまま終わる接続は、`fin_timeout` ではなく、アイドル・上限・flush(`EVICT_FLUSH` など)で確定する。
- `packet_filter` が例外を送出したときは、フィルタの誤動作で通信が黙って落ちるのを避けるため、`raise_on_analyzer_error` の値によらず `AnalyzerError` を送出する。

### 0.2.x へ先送りした項目
- pcapng の本格対応。
- 最低 Python バージョンを 3.9 に引き上げる(0.1.x は 3.7 以上を維持)。
- `segment_overhead_bytes` を既定で有効にする。
- コマンドライン(`python -m pcapreasm`)。

## [0.0.1]
- 初版。
