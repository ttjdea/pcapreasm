# pcapreasm 説明書

PCAP キャプチャから TCP / UDP の通信内容(アプリケーション層のデータ)を取り出す、**標準ライブラリのみ**の Python モジュールです。単一ファイル `pcapreasm.py` で完結し、外部パッケージは不要です。

- ライセンス: MPL-2.0
- バージョン: 0.0.1
- 動作環境: Python 3.7 以上(コード上の要件による。動作確認は Python 3.13 で実施)

---

## 1. できること

| 機能 | 内容 |
|---|---|
| PCAP 読み込み | クラシック PCAP(リトル/ビッグエンディアン、マイクロ秒/ナノ秒精度)に対応 |
| L2 除去 | Ethernet、802.1Q / QinQ(VLAN)、Linux cooked capture(SLL / SLL2)、RAW IP、Loopback |
| L3 解析 | IPv4 / IPv6(拡張ヘッダ対応)、IP フラグメントの再構成 |
| TCP 再構成 | 並べ替え、再送の除去、シーケンス番号の一周(wrap-around)対応、欠損区間(gap)の記録 |
| 双方向ペアリング | クライアント側とサーバ側のストリームを 1 つの conversation にまとめて通知 |
| UDP | データグラム単位の即時通知と、フロー単位の一括通知 |
| タイムスタンプ | 64bit 整数のナノ秒(`timestamp_ns`)で保持し、浮動小数点の精度劣化を避ける |
| 切り詰められたファイル | 途中で切れた PCAP は、読めた分を処理して警告を出し、複数ファイル処理を止めない |
| メモリ制御 | 同時 conversation 数、conversation ごとのバイト数、全体のバイト数、アイドル時間で上限を設定可能 |

---

## 2. インストール

単一ファイルなので、`pcapreasm.py` を自分のプロジェクトに置くだけで使えます。

```text
your_project/
├── pcapreasm.py
└── your_script.py
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

---

## 4. 処理の流れ

```text
PCAP ファイル
  │ (1) レコードを解析: グローバルヘッダ → [パケットヘッダ + パケット本体]*
  ▼
L2 除去 ........ Ethernet / VLAN / SLL / SLL2 / RAW / Loopback
  ▼
L3 解析 ........ IPv4 / IPv6(IP フラグメントは L4 ペイロードに再構成)
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
)
```

| 引数 | 既定値 | 説明 |
|---|---|---|
| `analyzers` | `None` | `BaseAnalyzer` を継承したインスタンスのリスト |
| `evict_on_fin` | `True` | FIN/RST による接続終了を検出した時点で即座に確定する。`False` の場合はアイドル・上限・flush でのみ確定 |
| `max_conversations` | `5000` | 同時に保持する conversation 数。超えると最も古く使われたものから確定(1 以上必須) |
| `max_conversation_bytes` | `None` | 1 conversation のバッファ上限(バイト)。超えると確定 |
| `max_total_bytes` | `None` | 全 conversation の合計バッファ上限(バイト)。超えると古いものから確定 |
| `idle_timeout` | `None` | 無通信がこの秒数を超えた conversation を確定。**キャプチャ時刻基準**(システム時計ではない) |
| `close_linger` | `5.0` | FIN 後に欠損の到着を待つ最大秒数。確定直後の遅延パケットを無視する期間でもある |
| `reassemble_fragments` | `True` | IP フラグメントを再構成する。`False` ではフラグメントを破棄 |
| `fragment_timeout` | `30.0` | 未完成のフラグメント集合を破棄するまでの秒数 |
| `max_fragment_sets` | `1024` | 同時に保持する未完成フラグメント集合の数 |

| メソッド / 属性 | 説明 |
|---|---|
| `process_file(pcap_path, flush_at_end=True)` | 1 ファイルを処理。通常ファイルのほか名前付きパイプも指定可 |
| `process_files(pcap_paths)` | 複数ファイルを順に処理。接続状態をファイル間で引き継ぎ、最後に flush |
| `flush()` | 未確定のストリームをすべて確定し、`on_complete` を呼ぶ |
| `stats` | `collections.Counter`。処理統計(下記) |

#### `stats` のキー

| キー | 意味 |
|---|---|
| `files` | 処理したファイル数 |
| `packets` | 読み込んだパケット数 |
| `non_ip` | IP として扱えなかったパケット(非 IP、未対応のリンクタイプなど) |
| `bad_ip` / `bad_tcp` / `bad_udp` | ヘッダが不正・切り詰められていて解析できなかったパケット |
| `orphan_packets` | 対応する接続がなく、データも SYN も持たないため捨てたパケット |
| `late_packets` | 確定済みの接続に遅れて届き、無視したパケット(正常終了時の最後の ACK も含まれる) |
| `fragments` | 受け取った IP フラグメント数 |
| `fragments_dropped` | `reassemble_fragments=False` により破棄したフラグメント数 |
| `frag_reassembled` | 再構成に成功した数 |
| `frag_expired` / `frag_evicted` | タイムアウト / 件数上限で破棄した未完成集合の数 |
| `frag_too_large` / `frag_conflict` | サイズ超過 / 長さの矛盾で破棄した数 |
| `frag_incomplete_at_flush` | flush 時点で未完成だった集合の数 |
| `read_errors` | ファイル読み込み中の OSError 回数 |

### 5.2 `BaseAnalyzer`

必要なコールバックだけをオーバーライドします。**コールバック内で起きた例外はログに記録されて握りつぶされ、処理は継続します。**

| コールバック | 呼ばれるタイミング |
|---|---|
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
| `EVICT_NEW_CONNECTION` | `"new_connection"` | 同じ 4 つ組で新しい SYN を観測した |
| `EVICT_IDLE` | `"idle"` | `idle_timeout` を超えた |
| `EVICT_FIN_TIMEOUT` | `"fin_timeout"` | FIN 後に `close_linger` 秒待っても欠損が埋まらなかった |
| `EVICT_MAX_CONVERSATIONS` | `"max_conversations"` | 同時 conversation 数の上限を超えた |
| `EVICT_MAX_BYTES` | `"max_bytes"` | 1 conversation のバイト上限を超えた |
| `EVICT_MAX_TOTAL_BYTES` | `"max_total_bytes"` | 全体のバイト上限を超えた |
| `EVICT_FLUSH` | `"flush"` | `flush()` により強制確定(ファイル終端など) |

`FIN` 以外の理由で確定したストリームは、途中までのデータである可能性があります。`meta.evict_reason` と `meta.gaps` を確認してください。

### 5.5 その他

- `ns_to_seconds(timestamp_ns)`: ナノ秒を秒(`float`)に変換。浮動小数点のため精度が落ちます。表示や概算用です。
- `NS_PER_SEC`: `1_000_000_000`
- `FlowId`: `Tuple[str, int, str, int]` の型エイリアス

---

## 6. 対応リンクタイプ

| 種別 | DLT 値 |
|---|---|
| Ethernet(VLAN / QinQ のタグを除去) | 1 |
| BSD Loopback / OpenBSD Loopback | 0 / 108 |
| Raw IP | 12 / 101 |
| Raw IPv4 / Raw IPv6 | 228 / 229 |
| Linux cooked capture v1 / v2 | 113 / 276 |

未対応のリンクタイプは警告を出し、そのファイルのパケットは `non_ip` として数えられます。

---

## 7. ログの出力

警告(切り詰められたファイル、未対応リンクタイプ、コールバック内の例外など)は標準の `logging` で出力されます。

```python
import logging
logging.basicConfig(level=logging.INFO)   # INFO にするとファイル名も表示される
```

---

## 8. 制限事項と注意点

使う前に把握しておいてほしい点です。

**入力形式**
- クラシック PCAP のみ対応です。**pcapng(Wireshark の既定形式)は読めず**、`ValueError: ... Invalid pcap global header` になります。Wireshark で「pcap 形式」として保存し直すか、`editcap -F pcap in.pcapng out.pcap` で変換してください。
- 圧縮ファイル(`.gz` など)は直接読めません。

**再構成の挙動**
- 欠損区間(gap)には**詰め物が入りません**。`data` は欠損を飛ばして連結されるため、欠損後のバイト位置は実際のストリーム位置とずれます。正確な位置が必要な場合は `meta.gaps` で補正してください。
- 重複・重なりのあるセグメントは**先に届いた(シーケンス番号が小さい)データを優先**します。OS ごとの再構成ポリシーの違いは再現しません。
- **半クローズが長い接続に注意**: 一方が FIN を送った後、相手が `close_linger`(既定 5 秒)を超えて無通信のままだと `fin_timeout` で一旦確定されます。その後に届いたデータは新しい conversation として扱われ、`client_certain=False` で**クライアントとサーバの役割が逆に割り当てられる**ことがあります。応答まで長く待つ通信を扱う場合は、`close_linger` を大きくしてください。
- `late_packets` には、正常終了時の最後の ACK も含まれます。異常の指標としてそのまま使わないでください。
- チェックサムは検証しません。

**対象外のもの**
- TLS などの暗号化通信は復号しません。
- VPN / トンネル(GRE、VXLAN、IPsec ESP など)は展開しません。
- TCP / UDP 以外(ICMP、SCTP など)は無視されます。
- 4 つ組が同じなら、異なる VLAN のパケットも同じ接続として扱われます。

**メモリ**
- 既定では `max_conversation_bytes` と `max_total_bytes` が無制限です。大きな PCAP では上記 3.7 のように上限を設定してください。
- 確定時には再構成した `data` と `timeline` が同時にメモリ上に存在するため、一時的に追加のメモリが必要になります。
- `on_udp_flow` を実装すると、UDP データグラムを flush まですべて保持します。

**その他**
- スレッドセーフではありません。1 つの `PcapStreamProcessor` は 1 つのスレッドから使ってください。
- 時間に関する処理(`idle_timeout` など)はすべてキャプチャ時刻に基づきます。

---

## 9. ライセンス

Mozilla Public License 2.0(MPL-2.0)。詳細はリポジトリ同梱の `LICENSE` と、`pcapreasm.py` 冒頭のヘッダを参照してください。
