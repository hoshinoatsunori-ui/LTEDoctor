"""
pcap_parser.py
Wireshark pcap/pcapng ファイルをパースしてイベントを抽出する。

依存: scapy (pip install scapy)
tshark がインストールされていれば pyshark 経由でより詳細な NAS 解析も可能。

抽出対象:
  - NAS メッセージ (Attach/TAU/Detach/Reject 等) → Layer3/LTE-RRC があれば
  - UDP/TCP フロー (タイムスタンプ・ペイロード長・RTT推定)
  - ICMP
  - パケット間隔異常検出

LINKTYPE_WIRESHARK_UPPER_PDU (252) 対応:
  Sierra Wireless HL78xx モジュール側 Wireshark キャプチャに対応。
  LTE RRC / NAS-EPS Exported PDU 形式を手動デコード。
"""

import logging
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── データクラス ───────────────────────────────────────────────────
@dataclass
class PcapRecord:
    """パース済み1パケット"""
    frame_no:     int
    utc_ts:       datetime        # pcap タイムスタンプ（UTC）
    src_ip:       Optional[str]
    dst_ip:       Optional[str]
    protocol:     str             # "UDP" / "TCP" / "ICMP" / "NAS" / "OTHER"
    length:       int             # パケット長 [bytes]
    summary:      str             # 人間可読サマリー

    # UDP/TCP 詳細
    src_port:     Optional[int]   = None
    dst_port:     Optional[int]   = None
    tcp_flags:    Optional[str]   = None   # "SYN" / "ACK" / "SYN-ACK" 等
    payload_len:  Optional[int]   = None

    # NAS/LTE 詳細 (tshark利用時のみ)
    nas_msg_type: Optional[str]   = None
    emm_cause:    Optional[int]   = None

    # アンカー/イベントフラグ
    is_anchor_candidate: bool     = False
    event_type:   Optional[str]   = None   # EVT_TX / EVT_RX / EVT_NWREJECT 等

    # time_aligner が使う
    utc_ts_est:       Optional[datetime] = None
    align_confidence: str = "HIGH"   # pcap は UTC 源なので原則 HIGH


# ── scapy ベースパーサー ──────────────────────────────────────────
def parse_file_scapy(path: str) -> list[PcapRecord]:
    """
    scapy でパースする軽量実装。
    NAS 詳細は取れないが、UDP/TCP/ICMP のフロー分析に十分。
    """
    try:
        from scapy.all import rdpcap, IP, IPv6, UDP, TCP, ICMP
    except ImportError:
        logger.error("scapy が見つかりません: pip install scapy")
        return []

    try:
        pkts = rdpcap(path)
    except Exception as e:
        logger.error("pcap 読み込みエラー: %s", e)
        return []

    records: list[PcapRecord] = []
    for i, pkt in enumerate(pkts, 1):
        rec = _parse_scapy_pkt(i, pkt, IP, IPv6, UDP, TCP, ICMP)
        if rec:
            records.append(rec)

    logger.info("pcap パース完了 (scapy): %d パケット (%s)", len(records), path)
    return records


def _parse_scapy_pkt(frame_no, pkt, IP, IPv6, UDP, TCP, ICMP) -> Optional[PcapRecord]:
    # タイムスタンプ
    ts = float(pkt.time)
    utc_ts = datetime.fromtimestamp(ts, tz=timezone.utc)

    src_ip = dst_ip = None
    protocol = "OTHER"
    src_port = dst_port = tcp_flags = payload_len = None
    summary_parts = []
    is_anchor = False
    event_type = None

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        summary_parts.append(f"{src_ip} → {dst_ip}")
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        summary_parts.append(f"{src_ip} → {dst_ip}")

    if pkt.haslayer(TCP):
        protocol = "TCP"
        l = pkt[TCP]
        src_port, dst_port = l.sport, l.dport
        flags = l.flags
        flag_str = _tcp_flags(int(flags))
        tcp_flags = flag_str
        payload_len = len(bytes(l.payload))
        summary_parts.append(f"TCP {src_port}→{dst_port} [{flag_str}] len={payload_len}")
        if "SYN" in flag_str:
            is_anchor = True
        event_type = "EVT_TX" if payload_len > 0 else None

    elif pkt.haslayer(UDP):
        protocol = "UDP"
        l = pkt[UDP]
        src_port, dst_port = l.sport, l.dport
        payload_len = len(bytes(l.payload))
        summary_parts.append(f"UDP {src_port}→{dst_port} len={payload_len}")
        if payload_len > 0:
            event_type = "EVT_TX"

    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
        ic = pkt[ICMP]
        summary_parts.append(f"ICMP type={ic.type} code={ic.code}")

    summary = " | ".join(summary_parts) if summary_parts else str(pkt.summary())

    rec = PcapRecord(
        frame_no=frame_no,
        utc_ts=utc_ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        length=len(pkt),
        summary=summary,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        payload_len=payload_len,
        is_anchor_candidate=is_anchor,
        event_type=event_type,
    )
    rec.utc_ts_est = utc_ts  # pcap は UTC 源なのでそのまま
    return rec


def _tcp_flags(flags: int) -> str:
    names = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"),
             (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]
    return "-".join(n for b, n in names if flags & b) or str(flags)


# ── tshark ベースパーサー（NAS解析用） ────────────────────────────
def parse_file_tshark(path: str) -> list[PcapRecord]:
    """
    tshark がインストールされていれば NAS メッセージも抽出できる。
    フォールバックとして parse_file_scapy を呼ぶ。
    """
    import subprocess, json, shutil
    if not shutil.which("tshark"):
        logger.info("tshark が見つかりません。scapy にフォールバック")
        return parse_file_scapy(path)

    fields = [
        "frame.number", "frame.time_epoch",
        "ip.src", "ip.dst",
        "_ws.col.Protocol", "frame.len",
        "udp.srcport", "udp.dstport",
        "tcp.srcport", "tcp.dstport", "tcp.flags",
        "nas_eps.nas_msg_emm_type", "nas_eps.emm.cause",
        "data.len",
    ]
    cmd = ["tshark", "-r", path, "-T", "json"] + \
          [x for f in fields for x in ("-e", f)] + ["-T", "ek"]

    try:
        out = subprocess.check_output(
            ["tshark", "-r", path, "-T", "json"],
            stderr=subprocess.DEVNULL,
        )
        pkts = json.loads(out)
    except Exception as e:
        logger.warning("tshark 実行失敗 (%s), scapy にフォールバック", e)
        return parse_file_scapy(path)

    records = []
    for i, pkt in enumerate(pkts, 1):
        layers = pkt.get("_source", {}).get("layers", {})
        rec = _parse_tshark_layers(i, layers)
        if rec:
            records.append(rec)

    logger.info("pcap パース完了 (tshark): %d パケット", len(records))
    return records


def _parse_tshark_layers(frame_no: int, layers: dict) -> Optional[PcapRecord]:
    def g(key, default=None):
        v = layers.get(key)
        return v[0] if isinstance(v, list) else (v if v is not None else default)

    try:
        ts = float(g("frame.time_epoch", 0))
    except (ValueError, TypeError):
        return None

    utc_ts = datetime.fromtimestamp(ts, tz=timezone.utc)
    src_ip  = g("ip.src")
    dst_ip  = g("ip.dst")
    proto   = g("_ws.col.Protocol", "OTHER").upper()
    length  = int(g("frame.len", 0))

    src_port = _to_int(g("udp.srcport") or g("tcp.srcport"))
    dst_port = _to_int(g("udp.dstport") or g("tcp.dstport"))
    tcp_flags_raw = g("tcp.flags")
    tcp_flags_str = None
    if tcp_flags_raw:
        try:
            tcp_flags_str = _tcp_flags(int(tcp_flags_raw, 16))
        except Exception:
            tcp_flags_str = tcp_flags_raw

    nas_type  = g("nas_eps.nas_msg_emm_type")
    emm_cause_raw = g("nas_eps.emm.cause")
    emm_cause = _to_int(emm_cause_raw)

    is_anchor = bool(tcp_flags_str and "SYN" in tcp_flags_str) or \
                nas_type is not None

    event_type = None
    if nas_type and "reject" in str(nas_type).lower():
        event_type = "EVT_NWREJECT"
    elif proto == "UDP" and _to_int(g("data.len", 0)) > 0:
        event_type = "EVT_TX"

    summary_parts = [f"{src_ip} → {dst_ip}" if src_ip else ""]
    if src_port:
        summary_parts.append(f"{proto} {src_port}→{dst_port}")
    if nas_type:
        summary_parts.append(f"NAS:{nas_type}")
    if emm_cause:
        summary_parts.append(f"EMM_cause={emm_cause}")

    rec = PcapRecord(
        frame_no=frame_no,
        utc_ts=utc_ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        length=length,
        summary=" | ".join(filter(None, summary_parts)),
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags_str,
        nas_msg_type=nas_type,
        emm_cause=emm_cause,
        is_anchor_candidate=is_anchor,
        event_type=event_type,
    )
    rec.utc_ts_est = utc_ts
    return rec


def _to_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ── RTT 推定 ─────────────────────────────────────────────────────
def estimate_rtt(records: list[PcapRecord]) -> list[dict]:
    """
    UDP: 同一 (src_ip, dst_ip, src_port, dst_port) で送受信ペアを探し RTT を推定。
    TCP: SYN → SYN-ACK の時差を RTT とする。
    """
    results = []
    # TCP SYN ペア
    syns = {r.frame_no: r for r in records
            if r.tcp_flags and "SYN" in r.tcp_flags and "ACK" not in r.tcp_flags}
    for fn, syn in syns.items():
        for r in records:
            if (r.frame_no > fn
                    and r.tcp_flags and "SYN" in r.tcp_flags and "ACK" in r.tcp_flags
                    and r.dst_ip == syn.src_ip
                    and r.src_ip == syn.dst_ip):
                rtt_ms = (r.utc_ts - syn.utc_ts).total_seconds() * 1000
                results.append({
                    "type": "TCP_SYN",
                    "frame_req": fn, "frame_resp": r.frame_no,
                    "rtt_ms": round(rtt_ms, 3),
                    "ts": syn.utc_ts.isoformat(),
                })
                break
    return results


# ── サマリー ─────────────────────────────────────────────────────
def summary(records: list[PcapRecord]) -> dict:
    from collections import Counter
    protos = Counter(r.protocol for r in records)
    events = Counter(r.event_type for r in records if r.event_type)
    ts_first = records[0].utc_ts if records else None
    ts_last  = records[-1].utc_ts if records else None
    duration = (ts_last - ts_first).total_seconds() if ts_first and ts_last else None
    return {
        "total_packets": len(records),
        "duration_s": duration,
        "ts_first": ts_first.isoformat() if ts_first else None,
        "ts_last":  ts_last.isoformat()  if ts_last  else None,
        "protocol_dist": dict(protos),
        "event_dist": dict(events),
        "nas_messages": [r.summary for r in records if r.nas_msg_type],
        "anchor_candidates": [
            {"frame": r.frame_no, "ts": r.utc_ts.isoformat(), "summary": r.summary}
            for r in records if r.is_anchor_candidate
        ],
        "rtt_estimates": estimate_rtt(records),
    }


# ── LINKTYPE_WIRESHARK_UPPER_PDU (252) 専用パーサー ──────────────
# Sierra Wireless HL78xx が生成する pcapng（モジュール側キャプチャ）に対応。
# Wireshark Exported PDU 形式: タグ-長さ-値ヘッダー + 生 PDU

_NAS_EMM_TYPES = {
    0x41: "Attach request",     0x42: "Attach accept",
    0x43: "Attach complete",    0x44: "Attach reject",
    0x45: "Detach request",     0x46: "Detach accept",
    0x48: "TAU request",        0x49: "TAU accept",
    0x4A: "TAU complete",       0x4B: "TAU reject",
    0x4C: "Extended service request",
    0x50: "GUTI realloc command",  0x51: "GUTI realloc complete",
    0x52: "Authentication request",  0x53: "Authentication response",
    0x54: "Authentication reject",
    0x55: "Identity request",    0x56: "Identity response",
    0x57: "Authentication failure",
    0x58: "Security mode command",  0x59: "Security mode complete",
    0x5A: "Security mode reject",
    0x60: "EMM status",          0x61: "EMM information",
    0x62: "DL NAS transport",    0x63: "UL NAS transport",
}
_NAS_ESM_TYPES = {
    0xC1: "Activate default EPS bearer context req",
    0xC2: "Activate default EPS bearer context accept",
    0xC9: "PDN connectivity request",
    0xCA: "PDN connectivity reject",
    0xD1: "Modify EPS bearer context req",
    0xE6: "ESM information request",
    0xE7: "ESM information response",
}

_LTE_RRC_CHANNELS = {
    "lte_rrc.bcch_bch":       "BCCH-BCH (MIB)",
    "lte_rrc.bcch_dl_sch_br": "BCCH-DL-SCH (SIB)",
    "lte_rrc.dl_dcch":        "DL-DCCH",
    "lte_rrc.ul_dcch":        "UL-DCCH",
    "lte_rrc.dl_ccch":        "DL-CCCH (RRC Setup)",
    "lte_rrc.ul_ccch":        "UL-CCCH (RRC Request)",
}


def _parse_epd_header(data: bytes) -> tuple[dict, int]:
    """
    Wireshark Exported PDU ヘッダーをパースする。
    返値: (tags dict, payload_offset)
    タグ 12 (EXP_PDU_TAG_PROTO_NAME) がプロトコル名。
    """
    import struct as _s
    pos = 0
    tags: dict[int, bytes] = {}
    while pos + 4 <= len(data):
        tag    = _s.unpack_from(">H", data, pos)[0]
        length = _s.unpack_from(">H", data, pos + 2)[0]
        pos += 4
        if tag == 0 and length == 0:
            break
        tags[tag] = data[pos:pos + length]
        pos += length
    return tags, pos


def _decode_nas(pdu: bytes) -> tuple[Optional[str], Optional[int], str]:
    """
    NAS-EPS バイト列から (nas_msg_type_name, emm_cause, summary) を返す。
    """
    if len(pdu) < 2:
        return None, None, "NAS: too short"

    pd_sec   = pdu[0]
    sec_hdr  = (pd_sec >> 4) & 0x0F
    pd       = pd_sec & 0x0F

    if sec_hdr == 0:
        # Plain (暗号化なし)
        msg_type = pdu[1]
        if pd == 7:   # EPS MM
            name = _NAS_EMM_TYPES.get(msg_type, f"EMM-0x{msg_type:02X}")
        elif pd == 2: # EPS SM
            name = _NAS_ESM_TYPES.get(msg_type, f"ESM-0x{msg_type:02X}")
        else:
            name = f"NAS-PD{pd}-0x{msg_type:02X}"

        emm_cause = None
        if msg_type == 0x44 and len(pdu) >= 3:  # Attach reject
            emm_cause = pdu[2]
        return name, emm_cause, f"NAS plain: {name}"

    elif sec_hdr in (1, 2, 3, 4):
        # 完全性保護（+暗号化）
        # 構造: byte0=sec_hdr|PD, byte1-4=MAC(4B), byte5=SEQ, byte6..=inner NAS
        inner_name = None
        if len(pdu) >= 8:
            inner_pd_sec = pdu[6]
            inner_sh = (inner_pd_sec >> 4) & 0x0F
            inner_pd = inner_pd_sec & 0x0F
            inner_mt = pdu[7]
            if inner_sh == 0:
                if inner_pd == 7:
                    inner_name = _NAS_EMM_TYPES.get(inner_mt, f"EMM-0x{inner_mt:02X}")
                elif inner_pd == 2:
                    inner_name = _NAS_ESM_TYPES.get(inner_mt, f"ESM-0x{inner_mt:02X}")
        label = inner_name or f"protected[{sec_hdr}]"
        return label, None, f"NAS protected: {label}"

    return None, None, f"NAS: sec_hdr={sec_hdr} pd={pd}"


def parse_file_epd(path: str) -> list[PcapRecord]:
    """
    LINKTYPE_WIRESHARK_UPPER_PDU (252) 形式の pcapng をパースする。
    Sierra Wireless HL78xx モジュール側キャプチャ専用。
    """
    import struct as _s

    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        logger.error("pcapng 読み込みエラー: %s", e)
        return []

    def r32(buf: bytes, p: int) -> int:
        return _s.unpack_from("<I", buf, p)[0]

    # pcapng ブロック走査
    records: list[PcapRecord] = []
    pos = 0
    frame_no = 0

    while pos < len(raw):
        if pos + 8 > len(raw):
            break
        bt = r32(raw, pos)
        bl = r32(raw, pos + 4)
        if bl < 12 or bl > len(raw) - pos:
            break

        if bt == 0x00000006:   # Enhanced Packet Block
            ts_hi   = r32(raw, pos + 12)
            ts_lo   = r32(raw, pos + 16)
            cap_len = r32(raw, pos + 20)
            ts64    = (ts_hi << 32) | ts_lo
            utc_ts  = datetime.fromtimestamp(ts64 / 1_000_000.0, tz=timezone.utc)

            pkt_data = raw[pos + 28: pos + 28 + cap_len]
            tags, hdr_end = _parse_epd_header(pkt_data)
            proto = tags.get(12, b"").rstrip(b"\x00").decode("ascii", "ignore")
            pdu   = pkt_data[hdr_end:]

            frame_no += 1
            rec = _build_epd_record(frame_no, utc_ts, proto, pdu, len(pkt_data))
            if rec:
                records.append(rec)

        pos += bl

    logger.info("pcapng パース完了 (EPD): %d パケット (%s)", len(records), path)
    return records


def _build_epd_record(
    frame_no: int,
    utc_ts: datetime,
    proto: str,
    pdu: bytes,
    pkt_len: int,
) -> Optional[PcapRecord]:
    """1パケットを PcapRecord に変換する"""
    nas_msg_type: Optional[str] = None
    emm_cause:    Optional[int] = None
    event_type:   Optional[str] = None
    is_anchor     = False
    summary_parts = [f"[{proto}]"]

    if "nas-eps" in proto:
        nas_msg_type, emm_cause, nas_summary = _decode_nas(pdu)
        summary_parts.append(nas_summary)

        if nas_msg_type:
            low = nas_msg_type.lower()
            if "attach accept" in low or "attach complete" in low:
                event_type = "EVT_ATTACH"
                is_anchor = True
            elif "attach reject" in low:
                event_type = "EVT_NWREJECT"
                is_anchor = True
            elif "detach" in low:
                event_type = "EVT_DETACH"
            elif "tau accept" in low:
                event_type = "EVT_ATTACH"
        if emm_cause:
            summary_parts.append(f"EMM_cause={emm_cause}")

    elif proto in _LTE_RRC_CHANNELS:
        ch_name = _LTE_RRC_CHANNELS[proto]
        summary_parts.append(ch_name)
        if "DL-CCCH" in ch_name or "UL-CCCH" in ch_name:
            is_anchor = True  # RRC Connection Setup

    elif proto == "logcat":
        try:
            txt = pdu.decode("utf-8", "replace").replace("\n", " ")[:80]
        except Exception:
            txt = pdu[:80].hex()
        summary_parts.append(f"logcat: {txt}")

    summary = " | ".join(filter(None, summary_parts))

    rec = PcapRecord(
        frame_no     = frame_no,
        utc_ts       = utc_ts,
        src_ip       = None,
        dst_ip       = None,
        protocol     = proto if proto else "OTHER",
        length       = pkt_len,
        summary      = summary,
        nas_msg_type = nas_msg_type,
        emm_cause    = emm_cause,
        is_anchor_candidate = is_anchor,
        event_type   = event_type,
    )
    rec.utc_ts_est = utc_ts
    return rec


def _detect_epd_linktype(path: str) -> bool:
    """pcapng ファイルが LINKTYPE_WIRESHARK_UPPER_PDU (252) かどうかを確認する"""
    import struct as _s
    try:
        with open(path, "rb") as f:
            raw = f.read(512)
        pos = 0
        while pos + 8 <= len(raw):
            bt = _s.unpack_from("<I", raw, pos)[0]
            bl = _s.unpack_from("<I", raw, pos + 4)[0]
            if bl < 12:
                break
            if bt == 0x00000001:  # IDB
                lt = _s.unpack_from("<H", raw, pos + 8)[0]
                return lt == 252
            pos += bl
    except OSError:
        pass
    return False


# ── エントリポイント ──────────────────────────────────────────────
def parse_file(path: str) -> list[PcapRecord]:
    """
    pcap/pcapng を自動判別してパースする。
    優先順:
      1. LINKTYPE_WIRESHARK_UPPER_PDU (252) → parse_file_epd
      2. tshark あり → parse_file_tshark
      3. scapy fallback → parse_file_scapy
    """
    import shutil
    if _detect_epd_linktype(path):
        logger.info("Link type 252 (Wireshark EPD) を検出: %s", path)
        return parse_file_epd(path)
    if shutil.which("tshark"):
        return parse_file_tshark(path)
    return parse_file_scapy(path)
