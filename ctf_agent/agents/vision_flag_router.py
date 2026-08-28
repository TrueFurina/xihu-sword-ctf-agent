"""vision_flag_router — 诚实的「图内渲染文字」flag 路由。

背景（能力短板，MY lane，非并行会话）：
- xuanhun_signin：JPEG 尾部嵌入 PNG（FFD9 后接 89504E47），提取 PNG 后 flag 是
  **渲染成文字的图片**——读取它需要 OCR / 视觉模型。本仓无视觉技能，属架构级缺口。
- vnctf_flag：点阵重采样显字类，由 misc_grid_resample 解（非本模块职责，已另有测试锁定）。

设计原则（与并行会话的反注水/诚实主题互补，不冲突）：
1. 只做**可解**的部分：尾部文件 carving（xuanhun 第一步）是确定性的、纯字节操作。
2. 对**不可解**的部分（图内文字需用视觉模型读取）：诚实标记 NEEDS_VISION，
   绝不伪造 flag、绝不谎报「已解」。
3. 若将来接入视觉端点（vision_fn），则走真实 OCR；否则一律降级为诚实待处理。

该模块是纯 stdlib（bytes/str 操作），不依赖 PIL/numpy，可在 managed python 直接跑。
"""

from __future__ import annotations

import re
from typing import Callable, Optional

__all__ = [
    "carve_trailing_file",
    "detect_vision_flag",
    "route_vision_flag",
    "VisionResult",
]

# --- 图内渲染文字的关键词/模式：命中即说明 flag 是「图片里的字」，需视觉模型读取 ---
_VISION_PATTERNS = [
    (r"图内\s*文字", "flag 为图片内渲染文字"),
    (r"即可看到\s*flag", "描述明示提取后图片内含可见 flag 文字"),
    (r"flag\s*文字\s*藏", "flag 文字藏于图像排布"),
    (r"显字", "图像显字类"),
    (r"点阵", "点阵排布显字类"),
    (r"重采样\s*显字", "网格重采样显字类"),
    (r"网格\s*重采样", "网格重采样显字类"),
    (r"渲染", "flag 以渲染方式呈现于图像"),
    (r"提取\s*.{0,6}?png\s*即可", "提取内嵌 PNG 后图片内可见 flag 文字"),
    (r"png\s*尾部", "PNG 尾部嵌入"),
    (r"尾部\s*嵌入", "尾部嵌入文件"),
    (r"jpeg.*png|png.*jpeg", "JPEG/PNG 混合载体，flag 在图内"),
]

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_EOI = b"\xff\xd9"


class VisionResult(dict):
    """诚实结果载体。

    needs_vision=True 时，status 必为 'NEEDS_VISION'，flag 必为 None（不伪造）。
    """

    def __init__(
        self,
        status: str,
        needs_vision: bool,
        reason: str = "",
        carved: Optional[bytes] = None,
        flag: Optional[str] = None,
    ):
        super().__init__(
            status=status,
            needs_vision=needs_vision,
            reason=reason,
            carved=carved,
            flag=flag,
        )


def carve_trailing_file(raw: bytes, magic: bytes, min_len: int = 16) -> Optional[bytes]:
    """从字节流中 carving 出「首个 magic 之后的全部数据」（处理尾部嵌入文件）。

    典型用例：xuanhun_signin —— JPEG(以 FFD9 结尾) 后接 PNG(89504E47...)，
    传 magic=_PNG_MAGIC 即可取出 PNG 字节。magic 不存在或太短返回 None。
    """
    if not raw or not magic:
        return None
    idx = raw.find(magic, 1)  # 从偏移 1 起，避免把文件本身的头部当作「尾部嵌入」
    if idx == -1:
        return None
    trailing = raw[idx:]
    if len(trailing) < min_len:
        return None
    return trailing


def detect_vision_flag(description: str) -> tuple[bool, str]:
    """纯关键词检测：flag 是否为「图内渲染文字」（需视觉模型读取）。

    返回 (needs_vision, reason)。未命中返回 (False, "")。
    注意：这是*启发式*，仅用于诚实路由——命中不代表一定能解，只代表『需视觉模型』。
    """
    if not description:
        return False, ""
    low = description.lower()
    for pattern, reason in _VISION_PATTERNS:
        if re.search(pattern, description, re.IGNORECASE) or re.search(pattern, low):
            return True, reason
    return False, ""


def route_vision_flag(
    description: str,
    attachment: Optional[bytes] = None,
    vision_fn: Optional[Callable[[bytes], str]] = None,
) -> VisionResult:
    """诚实路由入口。

    流程：
    1. 若提供 attachment 且描述暗示尾部嵌入（PNG/JPEG），先做确定性 carving（可解部分）。
    2. 用关键词判定是否需要视觉模型读取 flag 文字。
    3. 若需要视觉且提供了 vision_fn（真实 OCR/视觉端点）→ 调用它取文字再抽 flag；
       否则诚实返回 NEEDS_VISION，flag=None（绝不伪造）。

    vision_fn 约定：接收图像字节，返回识别出的文本字符串。
    """
    carved: Optional[bytes] = None
    # 步骤 1：确定性 carving（仅当描述出现尾部嵌入迹象且 attachment 存在）
    if attachment and re.search(r"尾部|嵌入|png\s*尾部|jpeg.*png", description, re.IGNORECASE):
        carved = carve_trailing_file(attachment, _PNG_MAGIC) or carve_trailing_file(
            attachment, _JPEG_EOI
        )

    # 步骤 2：判定是否需视觉模型
    needs_vision, reason = detect_vision_flag(description)
    if not needs_vision:
        # 非图内渲染文字类——本模块不负责，交回主链路（诚实：不在此处假解题）
        return VisionResult(
            status="NOT_VISION_DOMAIN",
            needs_vision=False,
            reason=reason or "未命中图内渲染文字模式",
            carved=carved,
            flag=None,
        )

    # 步骤 3：需视觉模型
    if vision_fn and carved is not None:
        try:
            text = vision_fn(carved)
            m = re.search(r"flag\{[^}]+\}", text)
            if m:
                return VisionResult(
                    status="SOLVED_VIA_VISION",
                    needs_vision=True,
                    reason=reason,
                    carved=carved,
                    flag=m.group(0),
                )
        except Exception:
            # 视觉端点失败 → 诚实降级，不吞异常造假
            pass

    # 诚实收口：没有可用视觉端点（或调用失败），绝不编造 flag
    return VisionResult(
        status="NEEDS_VISION",
        needs_vision=True,
        reason=reason,
        carved=carved,
        flag=None,
    )
