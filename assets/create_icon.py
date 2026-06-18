#!/usr/bin/env python3
"""
assets/create_icon.py — セキュリティツール用アイコン自動生成スクリプト

使用方法:
    python assets/create_icon.py

生成物:
    assets/icon.png  (256×256 RGBA PNG)
    assets/icon.ico  (16/24/32/48/64/128/256 マルチサイズ ICO)

Pillow が必要: pip install Pillow
"""
from __future__ import annotations
import os

# ── カラーパレット ────────────────────────────────────────
_BG   = (7,   12,  20,  255)  # #070C14  アプリ背景
_DARK = (10,  20,  36,  255)  # シールド内部
_CYAN = (0,   212, 255, 255)  # #00D4FF  主役シアン
_CGLO = (0,   212, 255, 70)   # シアン グロー（半透明）
_GRN  = (0,   255, 136, 210)  # #00FF88  アクセント


def _shield_pts(
    cx: float, cy: float, r: float
) -> list[tuple[int, int]]:
    """
    対称6頂点シールド形のポリゴン座標を返す。
    cx, cy: 中心座標  r: 縦方向の半径
    """
    hw   = r * 0.80          # 横半幅
    yt   = cy - r            # 上辺 y
    arch = r * 0.42          # 上肩の傾き量
    ym   = cy - r * 0.10     # 最大幅 y
    yb   = cy + r            # 下先端 y

    return [
        (int(cx),        int(yt)),           # 上中央
        (int(cx + hw),   int(yt + arch)),    # 右肩
        (int(cx + hw),   int(ym + arch)),    # 右側
        (int(cx),        int(yb)),           # 下先端
        (int(cx - hw),   int(ym + arch)),    # 左側
        (int(cx - hw),   int(yt + arch)),    # 左肩
    ]


def _make_frame(size: int) -> "Image.Image":
    """指定サイズの 1 フレームを生成して返す。"""
    from PIL import Image, ImageDraw, ImageFilter, ImageFont

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    cx  = size / 2
    cy  = size / 2
    pad = size * 0.05
    r   = size / 2 - pad

    # ── 1. 背景円 ─────────────────────────────────────────────
    bg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(bg).ellipse(
        [pad, pad, size - pad, size - pad], fill=_BG
    )
    img = Image.alpha_composite(img, bg)

    # ── 2. シールドグロー（段階的にぼかして重ねる） ───────────
    if size >= 32:
        sr = r * 0.76
        for i in range(3):
            expand = size * 0.016 * (3 - i)
            blur_r = max(1, size // 40 * (3 - i + 1))
            alpha  = 28 + i * 22
            glow   = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            pts    = _shield_pts(cx, cy, sr + expand)
            ImageDraw.Draw(glow).polygon(pts, fill=(*_CYAN[:3], alpha))
            glow   = glow.filter(ImageFilter.GaussianBlur(radius=blur_r))
            img    = Image.alpha_composite(img, glow)

    # ── 3. シールド本体 ──────────────────────────────────────
    sr  = r * 0.76
    pts = _shield_pts(cx, cy, sr)
    lw  = max(1, size // 48)

    sl  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    sd  = ImageDraw.Draw(sl)
    sd.polygon(pts, fill=_DARK)
    sd.polygon(pts, outline=_CYAN, width=lw * 2)
    img = Image.alpha_composite(img, sl)

    # ── 4. "AI" テキスト ─────────────────────────────────────
    if size >= 24:
        font_size = max(6, int(size * 0.290))
        font      = None
        _font_candidates = [
            r"C:\Windows\Fonts\segoeuib.ttf",
            r"C:\Windows\Fonts\arialbd.ttf",
            r"C:\Windows\Fonts\calibrib.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/liberation/LiberationSans-Bold.ttf",
        ]
        for fp in _font_candidates:
            try:
                font = ImageFont.truetype(fp, font_size)
                break
            except Exception:
                continue

        tl = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        td = ImageDraw.Draw(tl)

        if font:
            bb  = td.textbbox((0, 0), "AI", font=font)
            tw  = bb[2] - bb[0]
            th  = bb[3] - bb[1]
            tx  = cx - tw / 2 - bb[0]
            ty  = cy - th / 2 - bb[1] - size * 0.02
            # シャドウ
            td.text((tx + lw, ty + lw), "AI", fill=(*_CYAN[:3], 90), font=font)
            # 本文
            td.text((tx, ty), "AI", fill=_CYAN, font=font)
        else:
            # Pillow デフォルトフォント（サイズ固定）でフォールバック
            td.text((int(cx - size * 0.10), int(cy - size * 0.07)), "AI",
                    fill=_CYAN)

        img = Image.alpha_composite(img, tl)

    # ── 5. 回路ライン（32px 以上のみ） ───────────────────────
    if size >= 48:
        cl  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        cd  = ImageDraw.Draw(cl)
        lc  = (*_CYAN[:3], 55)   # 薄いシアン線
        y1  = int(cy - sr * 0.62)
        y2  = int(cy - sr * 0.32)
        x_l = int(cx - sr * 0.50)
        x_r = int(cx + sr * 0.50)
        # 水平ライン
        cd.line([(x_l, y1), (x_r, y1)], fill=lc, width=1)
        cd.line([(x_l, y2), (x_r, y2)], fill=lc, width=1)
        # ノード
        nr = max(1, int(size * 0.022))
        for nx, ny in [(x_l, y1), (x_r, y1), (x_l, y2), (x_r, y2)]:
            cd.ellipse([nx - nr, ny - nr, nx + nr, ny + nr],
                       fill=(*_CYAN[:3], 100))
        img = Image.alpha_composite(img, cl)

    # ── 6. グリーンアクセントドット ─────────────────────────
    if size >= 32:
        al  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        dr  = max(2, int(size * 0.038))
        dy  = int(cy + sr * 0.68)
        ImageDraw.Draw(al).ellipse(
            [int(cx) - dr, dy - dr, int(cx) + dr, dy + dr],
            fill=_GRN,
        )
        img = Image.alpha_composite(img, al)

    return img


def main() -> None:
    """assets/icon.png と assets/icon.ico を生成する。"""
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        print("[WARN] Pillow が見つかりません: pip install Pillow")
        return

    out_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out_dir, exist_ok=True)

    print("  [icon] 生成中 ...")

    # PNG (256px)
    icon256  = _make_frame(256)
    png_path = os.path.join(out_dir, "icon.png")
    icon256.save(png_path)
    print(f"  [icon] {png_path}")

    # ICO (マルチサイズ)
    ico_sizes = [(s, s) for s in (16, 24, 32, 48, 64, 128, 256)]
    ico_path  = os.path.join(out_dir, "icon.ico")
    icon256.save(ico_path, format="ICO", sizes=ico_sizes)
    print(f"  [icon] {ico_path}  ({len(ico_sizes)} サイズ)")


if __name__ == "__main__":
    main()
