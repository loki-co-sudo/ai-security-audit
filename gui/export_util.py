"""
gui/export_util.py — レポート出力（HTML / PDF）の共通ヘルパー

3パネル（CODE AUDIT / ATTACK / DEFENSE）から共通利用する。
log は文字列を受け取るコールバック（各パネルの進捗ログ）。
"""

from __future__ import annotations
import os
from typing import Callable

from tools import report_generator


def _open(path: str, log: Callable[[str], None]) -> None:
    ap = os.path.abspath(path)
    log(f"レポート保存: {ap}")
    try:
        os.startfile(ap)  # type: ignore[attr-defined]  (Windows)
    except Exception:
        pass


def export_html(
    mode: str, target: str, raw: str, model: str,
    slug: str, log: Callable[[str], None],
) -> None:
    html_content = report_generator.generate(
        mode=mode, target=target, raw_text=raw, model=model,
    )
    _open(report_generator.save(html_content, slug), log)


def export_pdf(
    mode: str, target: str, raw: str, model: str,
    slug: str, log: Callable[[str], None],
) -> None:
    pdf_bytes = report_generator.generate_pdf(
        mode=mode, target=target, raw_text=raw, model=model,
    )
    if pdf_bytes is None:
        log("PDF出力には Pillow が必要です: pip install Pillow")
        return
    _open(report_generator.save_pdf(pdf_bytes, slug), log)
