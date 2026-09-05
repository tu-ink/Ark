# -*- coding: utf-8 -*-
"""ArkIDS 图标生成器(纯标准库): 生成多尺寸 .ico / .png。

设计: 深蓝圆角面板 + 青色盾牌(防御) + 顶部红色攻击点(威胁),
      表达“AI 盾牌抵挡网络攻击”的主题。无第三方依赖:
      PNG 编码(zlib) 与 ICO 容器均由本脚本实现。

产物:
    assets/arkids.ico       (16,24,32,48,64,128,256 多尺寸)
    assets/arkids.png       (256x256 PNG 预览)
    src/arkids/webui/favicon.ico (16/32/48, 供网页标签页)
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
WEBUI = ROOT / "src" / "arkids" / "webui"

ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]
FAV_SIZES = [16, 32, 48]


# ---------------------------------------------------------------- 矢量图元
def inside_poly(u: float, v: float, pts: list[tuple[float, float]]) -> bool:
    """射线法判断点是否在多边形内(单位坐标)。"""
    inside = False
    j = len(pts) - 1
    for i in range(len(pts)):
        xi, yi = pts[i]
        xj, yj = pts[j]
        if ((yi > v) != (yj > v)) and \
                (u < (xj - xi) * (v - yi) / (yj - yi) + xi):
            inside = not inside
        j = i
    return inside


def seg_dist(px: float, py: float, pts: list[tuple[float, float]]) -> float:
    """点到多边形边界的最短距离(单位坐标)。"""
    best = 1e9
    n = len(pts)
    for i in range(n):
        ax, ay = pts[i]
        bx, by = pts[(i + 1) % n]
        vx, vy = bx - ax, by - ay
        wx, wy = px - ax, py - ay
        t = max(0.0, min(1.0, (wx * vx + wy * vy) / max(vx * vx + vy * vy, 1e-12)))
        dx, dy = px - (ax + vx * t), py - (ay + vy * t)
        best = min(best, (dx * dx + dy * dy) ** 0.5)
    return best


def in_round_rect(u: float, v: float, r: float = 0.16) -> bool:
    """圆角矩形覆盖整个 [0,1] 画布(icon 面板)。"""
    x = min(max(u, 0.0), 1.0)
    y = min(max(v, 0.0), 1.0)
    if r <= 0:
        return True
    cx = min(max(x, r), 1.0 - r)
    cy = min(max(y, r), 1.0 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _shield() -> list[tuple[float, float]]:
    return [(0.30, 0.16), (0.70, 0.16), (0.84, 0.26), (0.84, 0.52),
            (0.50, 0.88), (0.16, 0.52), (0.16, 0.26)]


def pixel(u: float, v: float, stroke: float) -> tuple[int, int, int, int]:
    """单位坐标 -> RGBA。stroke 为盾牌描边厚度(单位坐标)。"""
    # 1) 面板底色: 垂直渐变深蓝圆角矩形
    r = in_round_rect(u, v, 0.14)
    if not r:
        return (0, 0, 0, 0)
    top = (22, 48, 96)
    bot = (8, 18, 44)
    rr = int(lerp(top[0], bot[0], v)), int(lerp(top[1], bot[1], v)), \
        int(lerp(top[2], bot[2], v))

    # 2) 盾牌: 描边 + 内部
    poly = _shield()
    dist = seg_dist(u, v, poly)
    inside = inside_poly(u, v, poly)
    if inside:
        # 内部: 深青蓝渐变 + 中心“受保护核心”
        col = (int(lerp(18, 34, v)), int(lerp(66, 130, v)), int(lerp(130, 212, v)))
        for cx1, cy1, rad, fill in ((0.50, 0.50, 0.085, (46, 230, 168)),
                                    (0.50, 0.50, 0.038, (235, 250, 244))):
            dx, dy = u - cx1, v - cy1
            if dx * dx + dy * dy <= rad * rad:
                col = fill
        return (col[0], col[1], col[2], 255)
    if dist <= stroke:
        # 描边: 亮青
        return (70, 214, 255, 255)
    if dist <= stroke * 2.2:
        # 描边外沿光晕
        t = 1.0 - (dist - stroke) / (stroke * 1.2)
        return (60, 180, 235, int(150 * t))
    return (rr[0], rr[1], rr[2], 255)


# ---------------------------------------------------------------- PNG 编码
def encode_png(width: int, height: int, rgba: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    raw = bytearray()
    stride = width * 4
    for y in range(height):
        raw.append(0)  # filter: None
        raw += rgba[y * stride:(y + 1) * stride]
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) +
            chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


# ---------------------------------------------------------------- ICO 容器
def build_ico(images: list[tuple[int, int, bytes]]) -> bytes:
    """images: [(width, height, png_bytes)]; 输出 Windows ICO(PNG 存储, Vista+)"""
    n = len(images)
    header = struct.pack("<HHH", 0, 1, n)
    entries = bytearray()
    offset = 6 + 16 * n
    for w, h, png in images:
        entries += struct.pack("<BBBBHHII",
                               w if w < 256 else 0,
                               h if h < 256 else 0,
                               0, 0, 1, 32, len(png), offset)
        offset += len(png)
    return header + bytes(entries) + b"".join(p for _, _, p in images)


# ---------------------------------------------------------------- 渲染
def render(size: int, ss: int = 3) -> bytes:
    """渲染指定尺寸 PNG(3x 超采样抗锯齿)。"""
    dim = size * ss
    stroke = max(1.5 / size, 0.018)
    out = bytearray(dim * dim * 4)
    idx = 0
    for py in range(dim):
        for px in range(dim):
            u = (px + 0.5) / dim
            v = 1.0 - (py + 0.5) / dim   # PNG 原点在左上
            r_, g_, b_, a_ = pixel(u, v, stroke)
            out[idx], out[idx + 1], out[idx + 2], out[idx + 3] = r_, g_, b_, a_
            idx += 4
    # 超采样 -> 目标分辨率(盒式平均)
    final = bytearray(size * size * 4)
    for y in range(size):
        for x in range(size):
            rs = gs = bs = as_ = 0
            for dy in range(ss):
                row = (y * ss + dy) * dim * 4
                for dx in range(ss):
                    p = row + (x * ss + dx) * 4
                    rs += out[p]; gs += out[p + 1]
                    bs += out[p + 2]; as_ += out[p + 3]
            k = ss * ss
            q = (y * size + x) * 4
            final[q] = rs // k; final[q + 1] = gs // k
            final[q + 2] = bs // k; final[q + 3] = as_ // k
    return encode_png(size, size, bytes(final))


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    WEBUI.mkdir(parents=True, exist_ok=True)

    ico_all = []
    for s in ICO_SIZES:
        png = render(s)
        ico_all.append((s, s, png))
        print(f"  render {s}x{s}  ({len(png) / 1024:.1f} KB)")
    (ASSETS / "arkids.ico").write_bytes(build_ico(ico_all))

    png256 = ico_all[-1][2]
    (ASSETS / "arkids.png").write_bytes(png256)

    favs = [(s, s, png) for s, (_, _, png) in zip(FAV_SIZES, ico_all[:len(FAV_SIZES)])]
    (WEBUI / "favicon.ico").write_bytes(build_ico(favs))

    print("[ok] 生成完成:")
    print("  ", ASSETS / "arkids.ico")
    print("  ", ASSETS / "arkids.png")
    print("  ", WEBUI / "favicon.ico")


if __name__ == "__main__":
    main()
