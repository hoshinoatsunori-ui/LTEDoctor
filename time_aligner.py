"""
time_aligner.py
複数ログのタイムスタンプを共通UTC軸に展開する。

アンカー内挙法:
  1. UTC源ありログ（pcap）を基準時間軸に設定
  2. 各ログのアンカーイベントとpcap側の導中イベントの差分ΔTを計算
  3. 全レコードに utc_ts_est を付与
  4. アンカー数・信頼度クラスを記録
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from chipset_parser import ChipsetRecord, apply_utc_estimates, estimate_chip_boot_time
from at_parser import AtRecord

logger = logging.getLogger(__name__)


# ── 信頼度クラス ───────────────────────────────────────────────────
class Confidence:
    HIGH   = "HIGH"    # UTC源あり + 複数アンカー一致
    MEDIUM = "MEDIUM"  # UTC源あり + アンカー1点のみ
    LOW    = "LOW"     # UTC源なし / 相対時刻のみ


@dataclass
class AlignResult:
    """整合結果サマリー"""
    log_type: str
    offset_s: Optional[float]         # 推定オフセット [s]（基準軸との差）
    confidence: str
    anchor_count: int
    notes: str = ""


# ── ChipsetLog 整合 ────────────────────────────────────────────────
def align_chipset(
    records: list[ChipsetRecord],
    pcap_boot_utc: Optional[datetime] = None,
) -> AlignResult:
    """
    チップセットログを UTC 軸に展開する。

    pcap_boot_utc が与えられた場合:
      チップ起動アンカー と pcap_boot_utc を突き合わせ、
      全レコードに高精度の utc_ts_est を付与する。
    なければ:
      PC絶対時刻（dbv_abs_ts）を暫定として使い、LOW 信頼度とする。
    """
    boot_time = estimate_chip_boot_time(records)

    if pcap_boot_utc is not None and boot_time is not None:
        # ΔT = pcap_boot_utc - 推定起動時刻
        delta = pcap_boot_utc - boot_time
        offset_s = delta.total_seconds()
        logger.info("Chipset ΔT = %.6f s  (pcap_boot_utc補正)", offset_s)

        # boot_time を補正後の値で再計算
        corrected_boot = boot_time + delta
        apply_utc_estimates(records, corrected_boot)

        # 信頼度: アンカー1点 → MEDIUM、複数あれば HIGH
        anchor_count = sum(1 for r in records if r.is_boot_anchor or r.is_at_corr_anchor)
        conf = Confidence.HIGH if anchor_count >= 2 else Confidence.MEDIUM
        for r in records:
            if r.utc_ts_est is not None:
                r.align_confidence = conf

        return AlignResult(
            log_type="chipset",
            offset_s=offset_s,
            confidence=conf,
            anchor_count=anchor_count,
            notes=f"pcap_boot_utc補正適用 boot_time={corrected_boot.isoformat()}",
        )

    elif boot_time is not None:
        # pcapなし: PC時刻ベースで MEDIUM
        apply_utc_estimates(records, boot_time)
        return AlignResult(
            log_type="chipset",
            offset_s=0.0,
            confidence=Confidence.MEDIUM,
            anchor_count=1,
            notes="PC絶対時刻ベース (pcap未使用)",
        )
    else:
        # 起動アンカーなし: dbv_abs_ts をそのまま使い LOW
        apply_utc_estimates(records, None)
        return AlignResult(
            log_type="chipset",
            offset_s=None,
            confidence=Confidence.LOW,
            anchor_count=0,
            notes="起動アンカー未検出 dbv_abs_ts を暫定使用",
        )


# ── ATLog 整合 ─────────────────────────────────────────────────────
def align_at_log(
    records: list[AtRecord],
    anchor_utc: Optional[datetime] = None,
    anchor_rel_ms: Optional[int] = None,
    anchor_abs_ts: Optional[datetime] = None,
) -> AlignResult:
    """
    ATログを UTC 軸に展開する。

    ケース1: abs_ts あり（フォーマットA）
      → そのまま utc_ts_est に設定（confidence=MEDIUM）
      → anchor_utc が与えられたら差分補正（confidence=HIGH）

    ケース2: rel_ms のみ（フォーマットB）
      → anchor_utc + anchor_rel_ms でオフセット計算
      → anchor がなければ LOW

    ケース3: フォーマットC (DebugView/ttermpro)
      → abs_ts があるのでケース1と同様
    """
    has_abs = any(r.abs_ts is not None for r in records)
    has_rel = any(r.rel_ms is not None for r in records)

    if has_abs:
        if anchor_utc is not None and anchor_abs_ts is not None:
            delta = anchor_utc - anchor_abs_ts
            offset_s = delta.total_seconds()
            for r in records:
                if r.abs_ts is not None:
                    r.utc_ts_est = r.abs_ts + delta
                    r.align_confidence = Confidence.HIGH
            logger.info("ATログ abs_ts 補正: ΔT=%.6f s", offset_s)
            return AlignResult("at_log", offset_s, Confidence.HIGH, 1,
                               f"anchor補正 delta={delta}")
        else:
            for r in records:
                if r.abs_ts is not None:
                    r.utc_ts_est = r.abs_ts
                    r.align_confidence = Confidence.MEDIUM
            return AlignResult("at_log", 0.0, Confidence.MEDIUM, 0,
                               "abs_tsをそのまま使用（アンカー未指定）")

    elif has_rel and anchor_utc is not None and anchor_rel_ms is not None:
        base = anchor_utc - timedelta(milliseconds=anchor_rel_ms)
        for r in records:
            if r.rel_ms is not None:
                r.utc_ts_est = base + timedelta(milliseconds=r.rel_ms)
                r.align_confidence = Confidence.MEDIUM
        logger.info("ATログ rel_ms 展開: base=%s", base.isoformat())
        return AlignResult("at_log", 0.0, Confidence.MEDIUM, 1,
                           f"rel_ms展開 base={base.isoformat()}")

    else:
        for r in records:
            r.align_confidence = Confidence.LOW
        return AlignResult("at_log", None, Confidence.LOW, 0,
                           "タイムスタンプ不足 展開不可")


# ── 結果表示ヘルパー ───────────────────────────────────────────────
def print_align_report(results: list[AlignResult]) -> None:
    print("\n=== タイムスタンプ整合レポート ===")
    for r in results:
        flag = {"HIGH": "✓", "MEDIUM": "△", "LOW": "✗"}.get(r.confidence, "?")
        print(f"  [{flag}] {r.log_type:20s}  confidence={r.confidence:6s}"
              f"  offset={r.offset_s!s:10s}s  anchors={r.anchor_count}  {r.notes}")
