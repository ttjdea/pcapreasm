# pcapreasm 説明書

PCAP キャプチャから TCP / UDP の通信内容(アプリケーション層のデータ)を取り出す、**標準ライブラリのみ**の Python モジュールです。単一ファイル `pcapreasm.py` で完結し、外部パッケージは不要です。

- ライセンス: MPL-2.0
- バージョン: 0.2.2([変更履歴](CHANGELOG.md))
- 動作環境: Python 3.9 以上(CI は 3.9〜3.13 で実行)
- English: [README.en.md](README.en.md)

---

## 1. できること

| 機能 | 内容 |
|---|---|
| PCAP 読み込み | クラシック PCAP(リトル/ビッグエンディアン、マイクロ秒/ナノ秒精度)に対応。ファイルのほか、開いたストリーム(`gzip.open` など)も読める |
| L2 除去 | Ethernet、802.1Q / QinQ(VLAN)、Linux cooked capture(SLL / SLL2)、RAW IP、Loopback |
| L3 解析 | IPv4 / IPv6(拡張ヘッダ対応)、IP フラグメントの再構成 |
| パケットフィルタ | tcpdump 式の部分集合(`tcp and port 80` など)で、対象外の通信を最初に捨てる(速く、メモリも使わない) |
| TCP 再構成 | 並べ替え、再送の除去、シーケンス番号の一周(wrap-around)対応、欠損区間(gap)の記録 |
| 双方向ペアリング | クライアント側とサーバ側のストリームを 1 つの conversation にまとめて通知 |
| UDP | データグラム単位の即時通知と、フロー単位の一括通知 |
| タイムスタンプ | 64bit 整数のナノ秒(`timestamp_ns`)で保持し、浮動小数点の精度劣化を避ける |
| 切り詰められたファイル | 途中で切れた PCAP は、読めた分を処理して警告を出し、複数ファイル処理を止めない |
| snaplen の検出 | 捕捉長で切り詰められたパケットを検出し、欠損の原因がパケットロスか切り詰めか判断できる |
| メモリ制御 | 同時 conversation 数、conversation ごとのバイト数、全体のバイト数、アイドル時間で上限を設定可能 |

---

## 2. インストール

単一ファイルなので、`pcapreasm.py` を自分のプロジェクトに置くだけで使えます。

```text
your_project/
├── pcapreasm.py
└── your_script.py
```

`pip` でも入れられます(PyPI には公開していないため、GitHub から入れます)。

```text
pip install git+https://github.com/ttjdea/pcapreasm
```

```python
from pcapreasm import PcapStreamProcessor, BaseAnalyzer
```

---

## 3. クイックスタート

### 3.1 TCP の会話(双方向)を表示する

```python
from pcapreasm import PcapStreamProcessor, BaseAnalyzer


class Printer(BaseAnalyzer):
    def on_tcp_conversation(self, conv):
        c, s = conv.client, conv.server
        print(f"{c.flow_id} -> {s.flow_id}")
        print(f"  client {len(c.data)} bytes / server {len(s.data)} bytes ({conv.evict_reason})")


PcapStreamProcessor(analyzers=[Printer()]).process_file("sample.pcap")
```

### 3.2 HTTP のリクエスト行を覗く

```python
from pcapreasm import PcapStreamProcessor, BaseAnalyzer


class HttpPeek(BaseAnalyzer):
    def on_tcp_conversation(self, conv):
        request_line = conv.client.data.split(b"\r\n", 1)[0]
        if request_line.startswith((b"GET ", b"POST ", b"HEAD ")):
            status_line = conv.server.data.split(b"\r\n", 1)[0]
            print(request_line.decode("latin-1"), "->", status_line.decode("latin-1"))


PcapStreamProcessor(analyzers=[HttpPeek()]).process_file("sample.pcap")
```

### 3.3 一方向のストリームをファイルに保存する

```python
import os
from pcapreasm import PcapStreamProcessor, BaseAnalyzer


class Saver(BaseAnalyzer):
    def __init__(self, outdir):
        self.outdir = outdir
        self.count = 0
        os.makedirs(outdir, exist_ok=True)

    def on_tcp_stream(self, flow_id, data, meta):
        self.count += 1
        src, sport, dst, dport = flow_id
        name = f"{self.count:05d}_{src}_{sport}-{dst}_{dport}.bin".replace(":", "-")
        with open(os.path.join(self.outdir, name), "wb") as f:
            f.write(data)


PcapStreamProcessor(analyzers=[Saver("out")]).process_file("sample.pcap")
```

### 3.4 欠損とパケット時刻を調べる

```python
from pcapreasm import PcapStreamProcessor, BaseAnalyzer, ns_to_seconds


class Inspector(BaseAnalyzer):
    def on_tcp_stream(self, flow_id, data, meta):
        print(flow_id, f"{len(data)} bytes", f"再送 {meta.retrans_count}", f"欠損 {meta.gap_count}箇所/{meta.gap_bytes}バイト")
        if meta.truncated_segments:
            print(f"  注意: {meta.truncated_segments} セグメントは snaplen で切り詰められている(欠損はパケットロスとは限らない)")
        pos = 0  # data 内のオフセット
        for ts_ns, chunk in meta.timeline:
            print(f"  offset {pos:>6}  t={ns_to_seconds(ts_ns):.6f}  {len(chunk)} bytes")
            pos += len(chunk)


PcapStreamProcessor(analyzers=[Inspector()]).process_file("sample.pcap")
```

### 3.5 UDP を処理する

```python
from pcapreasm import PcapStreamProcessor, BaseAnalyzer


class UdpAnalyzer(BaseAnalyzer):
    def on_udp_datagram(self, flow_id, payload, timestamp_ns):   # 1 パケットごとに即時
        print("datagram", flow_id, payload[:16].hex(), timestamp_ns)

    def on_udp_flow(self, flow_id, datagrams, meta):             # flush 時にフロー単位で
        print("flow", flow_id, meta.datagram_count, "datagrams")


PcapStreamProcessor(analyzers=[UdpAnalyzer()]).process_file("sample.pcap")
```

### 3.6 複数ファイルを時系列順に処理する

```python
from pcapreasm import PcapStreamProcessor, BaseAnalyzer


class Printer(BaseAnalyzer):
    def on_tcp_stream(self, flow_id, data, meta):
        print(flow_id, len(data), meta.evict_reason)


PcapStreamProcessor(analyzers=[Printer()]).process_files(["part1.pcap", "part2.pcap"])
```

ファイルをまたぐ接続の状態は引き継がれ、最後のファイルの処理後にまとめて flush されます。**ファイルは時系列順に渡してください。**

読めないファイル(pcapng など)が混ざっていても止めたくないときは `on_error="skip"` を指定します。そのファイルは警告ログに出して飛ばし、`stats["failed_files"]` に数えます。

```python
proc = PcapStreamProcessor(analyzers=[Printer()])
proc.process_files(["part1.pcap", "broken.pcap", "part3.pcap"], on_error="skip")
print(proc.stats["failed_files"])
```

### 3.7 巨大な PCAP でメモリを抑える

```python
from pcapreasm import PcapStreamProcessor, BaseAnalyzer


class Printer(BaseAnalyzer):
    def on_tcp_stream(self, flow_id, data, meta):
        print(flow_id, len(data), meta.evict_reason)


proc = PcapStreamProcessor(
    analyzers=[Printer()],
    max_conversations=2000,                 # 同時に保持する conversation 数
    max_conversation_bytes=64 * 1024**2,    # 1 conversation あたり 64 MiB
    max_total_bytes=1024**3,                # 全体で 1 GiB
    idle_timeout=120,                       # 120 秒(キャプチャ時刻基準)無通信で確定
)
proc.process_file("sample.pcap")
print(dict(proc.stats))
```

### 3.8 ポートなどで絞り込む(フィルタ)

```python
from pcapreasm import PcapStreamProcessor, BaseAnalyzer


class Printer(BaseAnalyzer):
    def on_tcp_conversation(self, conv):
        print(conv.client.flow_id, len(conv.client.data), len(conv.server.data))


# tcpdump 式の部分集合(構文は「6. フィルタ式」)
proc = PcapStreamProcessor(analyzers=[Printer()], filter_expr="tcp and (port 80 or port 8080) and not host 10.0.0.9")
proc.process_file("sample.pcap")
print(proc.stats["filtered"], "パケットを除外した")

# 式で書けない条件は、関数で指定する
proc = PcapStreamProcessor(
    analyzers=[Printer()],
    packet_filter=lambda proto, flow_id: flow_id[3] in (80, 443) or flow_id[1] in (80, 443),
)
```

### 3.9 圧縮された PCAP を読む

```python
import gzip
from pcapreasm import PcapStreamProcessor, BaseAnalyzer


class Printer(BaseAnalyzer):
    def on_tcp_stream(self, flow_id, data, meta):
        print(flow_id, len(data))


proc = PcapStreamProcessor(analyzers=[Printer()])
with gzip.open("sample.pcap.gz", "rb") as stream:
    proc.process_stream(stream, name="sample.pcap.gz")   # name は警告やエラーメッセージに出る
```

### 3.10 コマンドラインで使う(0.2.0 で追加)

コードを書かずに、会話の一覧を見たり、フィルタ式を試したりできます。

```text
python -m pcapreasm capture.pcap
python -m pcapreasm a.pcap b.pcap -f "tcp and port 80" --udp
python -m pcapreasm -l files.txt --format jsonl > conversations.jsonl
zcat capture.pcap.gz | python -m pcapreasm -
```

出力は 1 つの TCP 会話(または、`--udp` を付けたときの UDP フロー)につき 1 行です。時刻は UTC です。

```text
2026-11-16T12:34:56.789Z TCP 10.0.0.1:1234 -> 10.0.0.2:80 c2s=18B s2c=11B gaps=0 end=fin
```

| オプション | 説明 |
|---|---|
| `pcap ...` | PCAP ファイル(時刻順)。`-` は標準入力(1 つだけ) |
| `-l`, `--file-list FILE` | 1 行 1 ファイルのリスト(空行は無視)。複数指定可 |
| `-f`, `--filter EXPR` | tcpdump 式のフィルタ(「6. フィルタ式」)。式が誤っていれば終了コード 2 |
| `--udp` | UDP フロー(送信元・宛先ごとのデータグラム数とバイト数)も表示 |
| `--format text\|jsonl` | 出力形式(既定 `text`)。`jsonl` は 1 行 1 JSON |
| `--on-error raise\|skip` | 読めないファイルがあったとき、止める(既定)/ 飛ばして続ける |
| `--idle-timeout SEC` | 無通信の会話を確定するまでの秒数(既定 300、`0` で無効) |
| `--max-memory-mb MB` | 保持するバッファの上限(既定 1024、`0` で無制限) |
| `--max-conversations N` | 同時に保持する TCP 会話数(既定 5000) |
| `--no-fragments` | IP フラグメントを再構成しない |
| `--stats` | 処理統計を標準エラーに出す |
| `-v`, `--verbose` | 詳細ログ |
| `--version` | バージョンを表示 |

結果は標準出力、警告と統計は標準エラーに出ます。終了コードは、正常が `0`、実行時エラー(ファイルが読めない、出力先に書けない、`--on-error skip` で飛ばしたファイルがあった)が `1`、引数やフィルタ式の誤りが `2` です。

注意:
- 表示されるのは、**データ(ペイロード)を含む** TCP 会話だけです。ハンドシェイクだけで終わった接続や、拒否・リセットされた接続は出ません(ライブラリの `on_tcp_conversation` と同じ)。接続数は `--stats` の `tcp_conversations` で分かります。
- TCP の行は、会話が確定した順に出ます(開始時刻順とは限りません)。UDP の行は開始時刻順です。
- `--udp` は、フローごとに 1 件のカウンタをメモリに持ち、`--max-memory-mb` の対象外です。送信元が非常に多い UDP を含む入力では、pcap の数倍のメモリを使うことがあります。
- `-`(標準入力)は、他のファイルとは併用できません。`-l` のリストは UTF-8(BOM 付きも可)で、先頭・末尾の空白や `#` で始まる行もそのままパスとして扱います。`pip install` した環境では `pcapreasm` コマンドでも呼べます。

---

## 4. 処理の流れ

```text
PCAP ファイル
  │ (1) レコードを解析: グローバルヘッダ → [パケットヘッダ + パケット本体]*
  ▼
L2 除去 ........ Ethernet / VLAN / SLL / SLL2 / RAW / Loopback
  ▼
L3 解析 ........ IPv4 / IPv6(IP フラグメントは L4 ペイロードに再構成)
  ▼
フィルタ ....... filter_expr / packet_filter(指定したときだけ。除外したパケットはここで捨てる)
  │
  ├─ UDP ──→ on_udp_datagram を即時呼び出し
  │          (on_udp_flow を実装している場合のみ、flush 時にフロー単位でも通知)
  │
  └─ TCP ──→ 4 つ組と方向ごとにセグメントを蓄積
              │ FIN / RST / アイドル / 上限超過 のいずれかで conversation を確定(evict)
              ▼
            シーケンス番号で整列 → 重複除去 → 欠損記録 → 連続バイト列を生成
              ▼
            on_tcp_stream / on_tcp_conversation を呼び出し
```

### 用語

| 用語 | 意味 |
|---|---|
| `timestamp_ns` | パケットのキャプチャ時刻。UNIX エポックからのナノ秒。秒に直すには `ns_to_seconds()` |
| `flow_id` | 一方向を表す 4 つ組 `(src_ip, src_port, dst_ip, dst_port)` |
| conversation | 4 つ組の双方向をまとめた TCP 接続。メモリ管理と確定(evict)の単位 |
| payload | 1 パケット分のアプリケーション層データ |
| data | 一方向について再構成した連続バイト列 |
| evict | ストリームを確定し、メモリから外して analyzer に通知すること |

---

## 5. API リファレンス

### 5.1 `PcapStreamProcessor`

```python
PcapStreamProcessor(
    analyzers=None,
    evict_on_fin=True,
    max_conversations=5000,
    max_conversation_bytes=None,
    max_total_bytes=None,
    idle_timeout=None,
    close_linger=5.0,
    reassemble_fragments=True,
    fragment_timeout=30.0,
    max_fragment_sets=1024,
    raise_on_analyzer_error=False,   # 0.1.0 で追加
    segment_overhead_bytes=150,      # 0.1.0 で追加(既定は 0.2.0 で 0 から 150 に変更)
    packet_filter=None,              # 0.1.0 で追加
    filter_expr=None,                # 0.1.0 で追加
)
```

0.1.0 で追加した引数は末尾に置いてあり、位置引数で呼んでいた既存のコードもそのまま動きます。

| 引数 | 既定値 | 説明 |
|---|---|---|
| `analyzers` | `None` | `BaseAnalyzer` を継承したインスタンスのリスト |
| `evict_on_fin` | `True` | FIN/RST による接続終了を検出した時点で即座に確定する。`False` の場合はアイドル・上限・flush でのみ確定 |
| `max_conversations` | `5000` | 同時に保持する conversation 数。超えると最も古く使われたものから確定(1 以上必須) |
| `max_conversation_bytes` | `None` | 1 conversation のバッファ上限(バイト)。超えると確定 |
| `max_total_bytes` | `None` | 全 conversation の合計バッファ上限(バイト)。超えると古いものから確定 |
| `idle_timeout` | `None` | 無通信がこの秒数を超えた conversation を確定。**キャプチャ時刻基準**(システム時計ではない) |
| `close_linger` | `5.0` | **両方向が閉じた(FIN/RST)後**に、欠損の到着を待つ最大秒数。確定直後の遅延パケットを無視する期間でもある。片方向だけが閉じた半クローズには適用されない |
| `reassemble_fragments` | `True` | IP フラグメントを再構成する。`False` ではフラグメントを破棄 |
| `fragment_timeout` | `30.0` | 未完成のフラグメント集合を破棄するまでの秒数 |
| `max_fragment_sets` | `1024` | 同時に保持する未完成フラグメント集合の数 |
| `raise_on_analyzer_error` | `False` | `True` にすると、analyzer のコールバックで起きた例外を握りつぶさず `AnalyzerError` として送出する(テストやバッチ処理向け) |
| `segment_overhead_bytes` | `150` | 保持している 1 セグメントごとに、ペイロードに加えて数えるバイト数。小さなセグメントが多いと、ペイロードだけでは実メモリより大幅に少なく見えるため、既定でオブジェクト管理分(実測で 1 セグメントあたり 110〜220 バイト)を加算して、上限が実メモリに近づくようにしている(測定例は「9. 制限事項」のメモリ)。`0` にすると 0.0.x/0.1.x と同じ(ペイロードのみ)。**0.2.0 で既定を `0` から `150` に変更**(同じ上限値でも、古い接続が早く確定される) |
| `packet_filter` | `None` | `f(ip_proto, flow_id) -> bool`。`False` を返したパケットを捨てる。`ip_proto` は TCP が `6`、UDP が `17`。例外を出すと `AnalyzerError` になる |
| `filter_expr` | `None` | tcpdump 式の部分集合(「6. フィルタ式」)。`packet_filter` と同時に指定すると AND |

| メソッド / 属性 | 説明 |
|---|---|
| `process_file(pcap_path, flush_at_end=True)` | 1 ファイルを処理。`str` / `pathlib.Path` のほか名前付きパイプも指定可。pcap でなければ `PcapFormatError` |
| `process_stream(stream, flush_at_end=True, name="<stream>")` | 開いたバイナリストリーム(`io.BytesIO`、`gzip.open(path, "rb")` など)を処理。ストリームは閉じない |
| `process_files(pcap_paths, on_error="raise")` | 複数ファイルを順に処理。接続状態をファイル間で引き継ぎ、最後に flush。`on_error="skip"` で読めないファイルを飛ばして続行 |
| `flush()` | 未確定のストリームをすべて確定し、`on_complete` を呼ぶ |
| `stats` | `collections.Counter`。処理統計(下記) |

`process_files` を既定の `on_error="raise"` で呼んで途中のファイルが失敗した場合、それまでに溜まった未確定のストリームは flush されません。結果が必要なら、例外を受けた後で `flush()` を呼んでください。

#### `stats` のキー

| キー | 意味 |
|---|---|
| `files` | 処理したファイル数 |
| `failed_files` | `process_files(on_error="skip")` で飛ばしたファイル数 |
| `packets` | 読み込んだパケット数 |
| `non_ip` | IP として扱えなかったパケット(非 IP、未対応のリンクタイプなど) |
| `bad_ip` / `bad_tcp` / `bad_udp` | ヘッダが不正・切り詰められていて解析できなかったパケット |
| `truncated_packets` | snaplen で切り詰められていた IP パケットの数(切り詰め後も解析できたもの) |
| `filtered` | `filter_expr` / `packet_filter` で除外したパケット数 |
| `orphan_packets` | 対応する接続がなく、データも SYN も持たないため捨てたパケット |
| `late_packets` | 確定済みの接続に遅れて届いた、データまたは SYN/FIN/RST を持つパケット(無視した) |
| `late_acks` | 確定済みの接続に届いた、データのない ACK(正常終了時の最後の ACK など。無視した) |
| `tcp_conversations` | 確定した TCP conversation の数 |
| `evict_<理由>` | 理由別の確定数(例: `evict_fin`、`evict_idle`。理由は「5.4 確定理由」) |
| `fragments` | 受け取った IP フラグメント数 |
| `fragments_dropped` | `reassemble_fragments=False` により破棄したフラグメント数 |
| `frag_reassembled` | 再構成に成功した数 |
| `frag_expired` / `frag_evicted` | タイムアウト / 件数上限で破棄した未完成集合の数 |
| `frag_too_large` / `frag_conflict` / `frag_too_many_pieces` | サイズ超過 / 長さの矛盾 / 断片の数が多すぎる(1 つの IP データグラムあたり 1,400 個超)ために破棄した数(最後は 0.2.2 で追加) |
| `frag_incomplete_at_flush` | flush 時点で未完成だった集合の数 |
| `read_errors` | ファイル読み込み中の OSError 回数 |

### 5.2 `BaseAnalyzer`

必要なコールバックだけをオーバーライドします。**コールバック内で起きた例外は、既定ではログに記録されて握りつぶされ、処理は継続します**(`raise_on_analyzer_error=True` で送出に変更できます)。

| コールバック | 呼ばれるタイミング |
|---|---|
| `on_file_start(path)` | 1 ファイル(またはストリーム)の読み込み開始前(0.1.0 で追加)。`path` は `process_stream` では `name` |
| `on_file_end(path)` | 1 ファイルの読み込み終了後、flush の前(0.1.0 で追加)。読み込みに失敗したときも呼ばれる |
| `on_tcp_stream(flow_id, data, meta)` | 一方向のストリームが確定したとき(`data` が空のものは呼ばれない) |
| `on_tcp_conversation(conversation)` | 双方向の conversation が確定したとき(どちらかに `data` があるとき) |
| `on_udp_datagram(flow_id, payload, timestamp_ns)` | UDP データグラムを 1 つ解析するたびに即時 |
| `on_udp_flow(flow_id, datagrams, meta)` | `flush()` 時に UDP フローごと。**オーバーライドした場合のみ**、全データグラムを flush までメモリに保持する |
| `on_complete()` | 全ファイルの処理と flush が終わったとき(1 回) |

1 つの conversation が確定すると、`on_tcp_stream` がクライアント方向 → サーバ方向の順に呼ばれ、続いて `on_tcp_conversation` が呼ばれます。

### 5.3 データクラス

#### `TCPFlowMeta`(一方向のメタ情報)

| 属性 | 説明 |
|---|---|
| `first_timestamp_ns` / `last_timestamp_ns` | その方向の最初 / 最後のパケット時刻 |
| `timeline` | `[(timestamp_ns, payload_chunk), ...]`。連結すると `data` に一致する。バイト位置とパケット時刻の対応付けに使える |
| `segment_count` | ペイロードを持つセグメント数(再送を含む) |
| `retrans_count` | 再送・重複として捨てたセグメント数 |
| `gaps` | `[(offset, missing_bytes), ...]`。`offset` は `data` 内の位置 |
| `gap_count` / `gap_bytes` | 欠損区間の数 / 欠損の合計バイト数(プロパティ) |
| `is_closed` | その方向で FIN または RST を観測したか |
| `evict_reason` | 確定理由(下記の `EVICT_*`) |
| `truncated_segments` | snaplen で切り詰められていたセグメントの数(0.1.0 で追加)。0 より大きいとき、`gaps` の一部は切り詰めによるもので、パケットロスとは限らない |

#### `TCPStream`

`flow_id`(`FlowId`)、`data`(`bytes`)、`meta`(`TCPFlowMeta`)

#### `TCPConversation`

| 属性 | 説明 |
|---|---|
| `client` / `server` | それぞれ `TCPStream`。`client` は SYN を送った側 |
| `client_certain` | SYN / SYN-ACK から開始側を確定できたか。`False` の場合は最初に観測したパケットの送信側を `client` とみなした推測 |
| `first_timestamp_ns` / `last_timestamp_ns` | 両方向を通した最初 / 最後の時刻 |
| `evict_reason` | 確定理由 |

#### `UDPDatagram` / `UDPFlowMeta`

`UDPDatagram(payload, timestamp_ns)`、`UDPFlowMeta(first_timestamp_ns, last_timestamp_ns, datagram_count)`

### 5.4 確定理由(`EVICT_*`)

| 定数 | 値 | 意味 |
|---|---|---|
| `EVICT_FIN` | `"fin"` | 両方向の終了を観測し、FIN までのデータが連続して揃った |
| `EVICT_RST` | `"rst"` | RST を観測した |
| `EVICT_NEW_CONNECTION` | `"new_connection"` | 同じ 4 つ組で新しい接続(別の初期シーケンス番号の SYN)を観測した |
| `EVICT_IDLE` | `"idle"` | `idle_timeout` を超えた |
| `EVICT_FIN_TIMEOUT` | `"fin_timeout"` | **両方向が閉じた後**、`close_linger` 秒待っても欠損が埋まらなかった |
| `EVICT_MAX_CONVERSATIONS` | `"max_conversations"` | 同時 conversation 数の上限を超えた |
| `EVICT_MAX_BYTES` | `"max_bytes"` | 1 conversation のバイト上限を超えた |
| `EVICT_MAX_TOTAL_BYTES` | `"max_total_bytes"` | 全体のバイト上限を超えた |
| `EVICT_FLUSH` | `"flush"` | `flush()` により強制確定(ファイル終端など) |

`FIN` 以外の理由で確定したストリームは、途中までのデータである可能性があります。`meta.evict_reason` と `meta.gaps` を確認してください。上限(`max_*`)で確定すると、1 つの長い接続が複数のストリームに分かれて通知されます。

### 5.5 例外クラス

| 例外 | 継承元 | 発生するとき |
|---|---|---|
| `PcapFormatError` | `ValueError` | クラシック PCAP として読めないとき。pcapng・gzip・未対応バージョン・短すぎるファイルは、メッセージに原因と対処が含まれる。`ValueError` を捕まえる 0.0.x のコードはそのまま動く |
| `AnalyzerError` | `Exception` | `raise_on_analyzer_error=True` でコールバックが失敗したとき、または `packet_filter` が例外を出したとき。元の例外は `__cause__` |
| `FilterSyntaxError` | `ValueError` | `filter_expr` が構文として誤っているか、未対応の構文を含むとき(`PcapStreamProcessor(...)` の生成時に送出) |

### 5.6 その他

- `ns_to_seconds(timestamp_ns)`: ナノ秒を秒(`float`)に変換。浮動小数点のため精度が落ちます。表示や概算用です。
- `NS_PER_SEC`: `1_000_000_000`
- `FlowId`: `Tuple[str, int, str, int]` の型エイリアス
- `compile_filter(expression)`: `filter_expr` と同じ式を、内部の判定関数にコンパイルして返します。式の検証や、単体での確認に使えます。

---

## 6. フィルタ式

`filter_expr` には、tcpdump(pcap-filter)の式の**部分集合**を指定できます。BPF にコンパイルするのではなく、解析済みの TCP / UDP パケットに対して判定します。

```python
PcapStreamProcessor(filter_expr="tcp and port 80")
```

### 構文

| 書式 | 意味 |
|---|---|
| `tcp` `udp` `ip` `ip6` | プロトコル(`ip` は IPv4、`ip6` は IPv6) |
| `host 10.0.0.1` | 送信元または宛先が一致 |
| `net 10.0.0.0/8` | 送信元または宛先がそのネットワーク内(**CIDR 形式必須**) |
| `port 80` | 送信元または宛先のポートが一致(プロトコルを省くと TCP と UDP の両方) |
| `portrange 8000-8100` | ポートが範囲内(両端を含む) |
| `src` / `dst` | `src host ...` `dst port ...` のように方向を限定 |
| `src or dst` / `src and dst` | `src and dst port 80` は送信元と宛先の両方が 80 |
| `and` `or` `not`(`&&` `\|\|` `!`) | 論理演算 |
| `( ... )` | 括弧(`not` と合わせて入れ子は 100 段まで。ポート番号は半角数字のみ) |
| プロトコルの前置 | `tcp port 80`、`udp dst port 53`、`ip6 and host 2001:db8::1` |
| 修飾子の省略 | tcpdump と同じく、`port 80 or 443` は `port 80 or port 443` |

大文字小文字は区別しません。空の式は「絞り込まない」と同じです。

### tcpdump との違い(意図したもの)

- ホスト名や `http` のようなサービス名は**解決しません**。IP アドレスとポート番号を書いてください(DNS 参照で遅くなったり、結果が環境で変わったりするのを避けるため)。
- `and` と `or` を括弧なしで混ぜると**エラー**にします(tcpdump は左から順に評価するため、意図と違う結果になりやすい)。括弧を付けてください。
- 未対応の構文(`ether`、`vlan`、`tcp[13] & 2 != 0` のようなバイト位置指定、`less` / `greater`、`icmp` など)は**黙って無視せず** `FilterSyntaxError` にします。誤って全パケットが通るのを防ぐためです。
- IP フラグメントは**再構成した後**に判定します。2 つ目以降のフラグメントにはポート番号がないためです(tcpdump の `port` は 2 つ目以降のフラグメントに一致しません)。
- tcpdump 4.99.4 との突き合わせテスト(`tests/test_filter.py`、tcpdump がある環境のみ実行)で、ランダムな 400 パケットに対する 21 個の式の一致件数が一致することを確認しています。

### 注意

- 片方向だけに一致する式(`src port 80` など)は、**片方向のストリームだけ**が通知されます。この場合 conversation の `client_certain` は `False` になりやすくなります。
- 「ある文字列を含む通信だけ」のような、データの中身に依存する条件は対象外です(analyzer 側で判定してください)。
- 性能(合成データでの目安。この README の作成時に 1 台の環境で測ったもので、環境により変わります): 40 バイトのセグメント 50 万パケットの処理で、フィルタなしを 100% とすると、全パケットが通る単純な式(`tcp`、`port 80`)で約 91%、4 句の複合式で約 75% の速度です。**全パケットを除外する式では約 180% の速度**になり、メモリもほぼ使いません。多くの通信を除外できる式ほど、全体は速くなります。
- ファイルが大きいときは、先に `tcpdump -r in.pcap -w out.pcap '式'` で絞る方がずっと速くなります。内蔵のフィルタは、中間ファイルを作りたくないときや、複数ファイルを続けて処理するとき、tcpdump が使えない環境で便利です。

---

## 7. 対応リンクタイプ

| 種別 | DLT 値 |
|---|---|
| Ethernet(VLAN / QinQ のタグを除去) | 1 |
| BSD Loopback / OpenBSD Loopback | 0 / 108 |
| Raw IP | 12 / 101 |
| Raw IPv4 / Raw IPv6 | 228 / 229 |
| Linux cooked capture v1 / v2 | 113 / 276 |

未対応のリンクタイプは警告を出し、そのファイルのパケットは `non_ip` として数えられます。

---

## 8. ログの出力

警告(切り詰められたファイル、未対応リンクタイプ、コールバック内の例外など)は標準の `logging` で出力されます。**警告にはファイル名が含まれます。**

```python
import logging
logging.basicConfig(level=logging.INFO)   # INFO にするとファイル名も表示される
```

---

## 9. 制限事項と注意点

使う前に把握しておいてほしい点です。

**入力形式**
- クラシック PCAP のみ対応です。**pcapng(Wireshark の既定形式)は読めず**、`PcapFormatError`(`ValueError` の一種)になります。メッセージに pcapng であることと変換方法が出ます。Wireshark で「pcap 形式」として保存し直すか、`editcap -F pcap in.pcapng out.pcap` で変換してください。pcapng への対応は予定していません。
- 圧縮ファイル(`.gz` など)は `process_file` では読めません。`gzip.open(path, "rb")` などで開いて `process_stream` に渡してください(「3.9 圧縮された PCAP を読む」を参照)。

**再構成の挙動**
- 欠損区間(gap)には**詰め物が入りません**。`data` は欠損を飛ばして連結されるため、欠損後のバイト位置は実際のストリーム位置とずれます。正確な位置が必要な場合は `meta.gaps` で補正してください。
- 重複・重なりのあるセグメントは**先に届いた(シーケンス番号が小さい)データを優先**します。OS ごとの再構成ポリシーの違いは再現しません。
- 半クローズ(片方だけが FIN を送った接続)は、相手が長く応答しなくても `fin_timeout` では確定されません。確定されるのは、相手の FIN/RST、`idle_timeout`、各種上限、`flush()` のいずれかです。応答のない接続が多いキャプチャでは、`idle_timeout` を設定しないと、`max_conversations`(既定 5000)の上限に達するまでメモリに残ります。
- snaplen(捕捉長)で切り詰められたパケットのデータは欠けるため、`gaps` に現れます。`meta.truncated_segments` と `stats["truncated_packets"]` で、パケットロスと区別できます。
- 同じ 4 つ組を再利用した接続は、別の接続として扱います。判定は、新しい SYN の送信側がすでに SYN を送っていれば初期シーケンス番号の違い(同じなら SYN の再送)、まだなら前の接続のデータが(どちらの方向にでも)残っているかどうかです。前の接続の FIN/RST が取れていなくても、この判定で分かれます。
- チェックサムは検証しません。

**対象外のもの**
- TLS などの暗号化通信は復号しません。
- VPN / トンネル(GRE、VXLAN、IPsec ESP など)は展開しません。
- TCP / UDP 以外(ICMP、SCTP など)は無視されます。
- 4 つ組が同じなら、異なる VLAN のパケットも同じ接続として扱われます。

**メモリ**
- 既定では `max_conversation_bytes` と `max_total_bytes` が無制限です。大きな PCAP では上記 3.7 のように上限を設定してください。
- 上限は、既定ではペイロードに 1 セグメントあたり 150 バイト(`segment_overhead_bytes`)を加えて数えます。`0` にするとペイロードだけを数え、小さなセグメントが多いときに実メモリを大きく下回ります。測定例(40 バイトのセグメント 50 万個、`max_total_bytes` = 16 MiB): 実メモリの増加は `segment_overhead_bytes=0` で約 89 MiB、`100` で約 27 MiB、`150` で約 21 MiB でした。上限に早く達する分、通知されるストリームは 593 個(`0`)から 2,162 個(`100`)、2,822 個(`150`)に増えます(上限が効いたぶん、1 つの接続が分割されやすくなる)。環境やデータにより変わるため、実際の入力で確かめてください。0.1.x までの既定は `0` でした。
- 上限に達して確定すると、1 つの接続が複数のストリームに分かれて通知されます。
- 確定時には再構成した `data` と `timeline` が同時にメモリ上に存在するため、一時的に追加のメモリが必要になります。
- `on_udp_flow` を実装すると、UDP データグラムを flush まですべて保持します。

**信頼できない入力**
- 外部から受け取った pcap を処理する場合は、メモリ上限の設定と、処理時間・メモリの制限(別プロセスで実行する、など)を入れてください。詳しくは [SECURITY.md](SECURITY.md) を参照してください。

**その他**
- スレッドセーフではありません。1 つの `PcapStreamProcessor` は 1 つのスレッドから使ってください。
- 時間に関する処理(`idle_timeout` など)はすべてキャプチャ時刻に基づきます。時計は「いま処理しているパケットの時刻」に従い、1 秒以上進むたびに掃除します(0.2.1 までは最大値を基準にしていた)。時刻が 1 秒以上戻ったとき(複数のインターフェースを混ぜたキャプチャ、先の時刻のパケットからの復帰、前のファイルより古いファイルなど)も掃除しますが、1,000 パケットに 1 回までです。時刻が大きく先に進んだパケットが 1 つあると、その時点でアイドルの会話がまとめて確定されますが、その後の掃除は正常に続きます。

---

## 10. ライセンス

Mozilla Public License 2.0(MPL-2.0)。詳細はリポジトリ同梱の `LICENSE` と、`pcapreasm.py` 冒頭のヘッダを参照してください。
