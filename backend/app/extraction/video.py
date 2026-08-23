from __future__ import annotations

import io
import math
import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

import cv2
cv2.setNumThreads(1)
import numpy as np
from PIL import Image, ImageDraw, ImageFont

from app.core.config import settings
from app.core.enums import FileType


VIDEO_EXTENSIONS = {".mp4", ".mov"}
VIDEO_MEDIA_TYPES = {".mp4": "video/mp4", ".mov": "video/quicktime"}


class VideoError(ValueError):
    pass


@dataclass(frozen=True)
class VideoInfo:
    width: int
    height: int
    fps: float
    total_frames: int
    duration_seconds: float
    sampled_frame_indices: tuple[int, ...]
    has_audio: bool
    source_extension: str

    @property
    def sampled_frames(self) -> int:
        return len(self.sampled_frame_indices)


def _safe_suffix(source_filename: str | None) -> str:
    ext = Path(source_filename or "video.mp4").suffix.lower()
    return ext if ext in VIDEO_EXTENSIONS else ".mp4"


def _looks_like_iso_bmff(data: bytes) -> bool:
    # MP4 / QuickTime-family files normally contain an ftyp box at byte 4.
    return len(data) >= 12 and data[4:8] == b"ftyp"


def _has_audio_track(data: bytes) -> bool:
    # ISO BMFF handler boxes identify audio streams with the fourcc ``soun``.
    # This is deliberately conservative: if the marker exists anywhere in the
    # accepted MP4/MOV container, VeilGraph reports audio as present and the
    # protected export removes it completely.
    return b"soun" in data


def _sample_indices(total_frames: int, fps: float) -> tuple[int, ...]:
    if total_frames <= 0:
        return ()
    target_rate = max(0.25, float(settings.video_evidence_sample_fps))
    stride = max(1, int(round(fps / target_rate))) if fps > 0 else 1
    indices = list(range(0, total_frames, stride))
    if indices[-1] != total_frames - 1:
        indices.append(total_frames - 1)
    cap = max(2, int(settings.max_video_evidence_frames))
    if len(indices) > cap:
        # Deterministic evenly-spaced evidence budget, always including first
        # and last frame. This limits OCR cost while keeping the whole timeline
        # represented in Privacy IR.
        positions = np.linspace(0, len(indices) - 1, cap)
        indices = sorted({indices[int(round(pos))] for pos in positions})
        if indices[0] != 0:
            indices.insert(0, 0)
        if indices[-1] != total_frames - 1:
            indices.append(total_frames - 1)
    return tuple(indices)


def probe_video(data: bytes, source_filename: str | None = None) -> VideoInfo:
    if not data:
        raise VideoError("Video is empty")
    ext = _safe_suffix(source_filename)
    if ext not in VIDEO_EXTENSIONS:
        raise VideoError("Supported video containers are MP4 and MOV")
    if not _looks_like_iso_bmff(data):
        raise VideoError("Video container magic bytes do not match MP4/MOV")

    temp_path: str | None = None
    cap = None
    try:
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as handle:
            handle.write(data)
            temp_path = handle.name
        cap = cv2.VideoCapture(temp_path)
        if not cap.isOpened():
            raise VideoError("OpenCV could not decode the video stream")
        width = int(round(cap.get(cv2.CAP_PROP_FRAME_WIDTH)))
        height = int(round(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)))
        fps = float(cap.get(cv2.CAP_PROP_FPS))
        total_frames = int(round(cap.get(cv2.CAP_PROP_FRAME_COUNT)))
        if width <= 0 or height <= 0:
            raise VideoError("Video has invalid frame dimensions")
        if fps <= 0 or not math.isfinite(fps):
            raise VideoError("Video frame rate is unavailable or invalid")
        if total_frames <= 0:
            raise VideoError("Video contains no decodable frames")
        duration = total_frames / fps
        if width > settings.max_video_width or height > settings.max_video_height:
            raise VideoError(
                f"Video exceeds the {settings.max_video_width}×{settings.max_video_height} frame-size limit"
            )
        if width * height > settings.max_video_frame_pixels:
            raise VideoError("Video frame exceeds the local safe pixel budget")
        if total_frames > settings.max_video_frames:
            raise VideoError(f"Video exceeds the {settings.max_video_frames}-frame limit")
        if duration > settings.max_video_duration_seconds:
            raise VideoError(
                f"Video duration {duration:.1f}s exceeds the {settings.max_video_duration_seconds:.0f}s local-analysis limit"
            )
        return VideoInfo(
            width=width,
            height=height,
            fps=fps,
            total_frames=total_frames,
            duration_seconds=duration,
            sampled_frame_indices=_sample_indices(total_frames, fps),
            has_audio=_has_audio_track(data),
            source_extension=ext,
        )
    finally:
        if cap is not None:
            cap.release()
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


def _frame_at(data: bytes, info: VideoInfo, frame_index: int) -> Image.Image:
    temp_path: str | None = None
    cap = None
    try:
        with tempfile.NamedTemporaryFile(suffix=info.source_extension, delete=False) as handle:
            handle.write(data)
            temp_path = handle.name
        cap = cv2.VideoCapture(temp_path)
        if not cap.isOpened():
            raise VideoError("OpenCV could not decode video evidence frame")
        cap.set(cv2.CAP_PROP_POS_FRAMES, int(frame_index))
        ok, frame = cap.read()
        if not ok or frame is None:
            raise VideoError(f"Could not decode video frame {frame_index}")
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        return Image.fromarray(rgb)
    finally:
        if cap is not None:
            cap.release()
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


def physical_frame(data: bytes, frame_index: int, source_filename: str | None = None) -> tuple[Image.Image, VideoInfo, int]:
    """Decode one physical video frame by its exact source-frame index."""
    info = probe_video(data, source_filename)
    if frame_index < 0 or frame_index >= info.total_frames:
        raise VideoError("Video physical-frame index is out of range")
    return _frame_at(data, info, int(frame_index)), info, int(frame_index)


def evidence_frame(data: bytes, page_index: int, source_filename: str | None = None) -> tuple[Image.Image, VideoInfo, int]:
    """Decode a representative judge-facing evidence frame.

    Stage-2 Safety v2 separately analyses every physical frame. This helper is
    retained only for compact evidence navigation and backwards compatibility.
    """
    info = probe_video(data, source_filename)
    if page_index < 0 or page_index >= len(info.sampled_frame_indices):
        raise VideoError("Video evidence-frame index is out of range")
    source_frame = info.sampled_frame_indices[page_index]
    return _frame_at(data, info, source_frame), info, source_frame


def _security_edge_map(frame: np.ndarray) -> np.ndarray:
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    if gray.shape[1] > 960:
        scale = 960.0 / gray.shape[1]
        gray = cv2.resize(gray, (960, max(1, int(round(gray.shape[0] * scale)))), interpolation=cv2.INTER_AREA)
    return (cv2.Canny(gray, 80, 180) > 0).astype(np.uint8)


def _novelty_fraction(reference: np.ndarray, candidate: np.ndarray) -> float:
    """Measure new edge content after translation alignment.

    Phase correlation estimates global panel/camera translation. Integer-aligned
    edge masks make ordinary motion cheap to ignore while a one-frame text/QR
    insertion remains a clear residual. If alignment is uncertain, the residual
    rises and the frame is conservatively selected for OCR/detection.
    """
    try:
        shift, _response = cv2.phaseCorrelate(reference.astype(np.float32), candidate.astype(np.float32))
        dx, dy = int(round(shift[0])), int(round(shift[1]))
    except cv2.error:
        dx = dy = 0
    scores: list[float] = []
    for sx, sy in ((dx, dy), (-dx, -dy)):
        matrix = np.float32([[1, 0, sx], [0, 1, sy]])
        aligned = cv2.warpAffine(candidate, matrix, (candidate.shape[1], candidate.shape[0]), borderValue=0)
        scores.append(float(np.logical_xor(reference, aligned).mean()))
    return min(scores)


def security_scan_frame_indices(data: bytes, source_filename: str | None = None) -> tuple[VideoInfo, tuple[int, ...], dict[str, object]]:
    """Change-screen every physical frame and select frames needing full OCR.

    Every frame is inspected by a lightweight visual change guard. Representative
    evidence frames are always selected. Any between-evidence frame containing
    material novel pixels after translation alignment is also selected for full
    OCR/detection. This catches transient identifiers without forcing expensive
    OCR on every near-duplicate frame.
    """
    info = probe_video(data, source_filename)
    evidence = list(info.sampled_frame_indices)
    selected = set(evidence)
    novelty_by_frame: dict[int, float] = {}
    temp_path: str | None = None
    cap = None
    try:
        with tempfile.NamedTemporaryFile(suffix=info.source_extension, delete=False) as handle:
            handle.write(data)
            temp_path = handle.name
        cap = cv2.VideoCapture(temp_path)
        if not cap.isOpened():
            raise VideoError("OpenCV could not decode video for full-frame safety scan")

        evidence_pos = 0
        left_idx = evidence[0]
        right_idx = evidence[1] if len(evidence) > 1 else evidence[0]
        left_gray: np.ndarray | None = None
        interior: list[tuple[int, np.ndarray]] = []
        frame_index = 0
        while True:
            ok, frame = cap.read()
            if not ok or frame is None:
                break
            edge_map = _security_edge_map(frame)
            if frame_index == left_idx:
                left_gray = edge_map
            elif frame_index < right_idx:
                interior.append((frame_index, edge_map))
            elif frame_index == right_idx:
                right_gray = edge_map
                if left_gray is None:
                    left_gray = right_gray
                for candidate_index, candidate_gray in interior:
                    novelty = min(
                        _novelty_fraction(left_gray, candidate_gray),
                        _novelty_fraction(right_gray, candidate_gray),
                    )
                    novelty_by_frame[candidate_index] = novelty
                    if novelty >= 0.001:
                        selected.add(candidate_index)
                interior.clear()
                left_idx = right_idx
                left_gray = right_gray
                evidence_pos += 1
                if evidence_pos + 1 < len(evidence):
                    right_idx = evidence[evidence_pos + 1]
            frame_index += 1

        if frame_index != info.total_frames:
            raise VideoError(f"Full-frame safety scan decoded {frame_index}/{info.total_frames} frames")
    finally:
        if cap is not None:
            cap.release()
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

    selected_indices = tuple(sorted(selected))
    return info, selected_indices, {
        "physical_frames_change_screened": info.total_frames,
        "evidence_frames": len(evidence),
        "novel_security_frames": len(set(selected_indices) - set(evidence)),
        "full_ocr_detection_frames": len(selected_indices),
        "novelty_threshold": 0.001,
        "novelty_by_frame": {str(key): round(value, 6) for key, value in novelty_by_frame.items() if key in selected},
    }


def video_to_processed_document(data: bytes, source_filename: str | None = None):
    """Build Video Privacy IR with exhaustive physical-frame change coverage."""
    from app.extraction.document_processor import PageFrame, ProcessedDocument, _ocr_lines

    info, selected_indices, security_stats = security_scan_frame_indices(data, source_filename)
    evidence_set = set(info.sampled_frame_indices)
    selected_set = set(selected_indices)
    temp_path: str | None = None
    cap = None
    pages: list[PageFrame] = []
    try:
        with tempfile.NamedTemporaryFile(suffix=info.source_extension, delete=False) as handle:
            handle.write(data)
            temp_path = handle.name
        cap = cv2.VideoCapture(temp_path)
        if not cap.isOpened():
            raise VideoError("OpenCV could not decode video security frames")
        for frame_index in selected_indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, int(frame_index))
            ok, frame = cap.read()
            if not ok or frame is None:
                raise VideoError(f"Could not decode security-selected frame {frame_index}")
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            image = Image.fromarray(rgb)
            lines = tuple(_ocr_lines(image, frame_index, float(info.width), float(info.height)))
            pages.append(PageFrame(
                page_index=frame_index, width=float(info.width), height=float(info.height),
                image=image, lines=lines, used_ocr=True,
            ))
    finally:
        if cap is not None:
            cap.release()
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

    frame_map = []
    for frame_index in range(info.total_frames):
        seconds = frame_index / info.fps
        frame_map.append({
            "page_index": frame_index,
            "frame_index": frame_index,
            "timestamp_seconds": round(seconds, 3),
            "label": f"{int(seconds // 60):02d}:{seconds % 60:04.1f}",
            "is_evidence": frame_index in evidence_set,
            "security_scanned": True,
            "full_ocr_selected": frame_index in selected_set,
        })

    return ProcessedDocument(
        file_type=FileType.VIDEO, pages=tuple(pages), page_count=len(pages), scanned_pages=len(pages),
        metadata={
            "video_duration_seconds": round(info.duration_seconds, 3),
            "video_fps": round(info.fps, 3), "video_width": info.width, "video_height": info.height,
            "video_total_frames": info.total_frames, "video_sampled_frames": info.sampled_frames,
            "video_evidence_frames": info.sampled_frames,
            "video_security_frames_analyzed": info.total_frames,
            "video_security_coverage_percent": 100.0,
            "video_security_detection_frames": len(selected_indices),
            "video_has_audio": info.has_audio,
            "video_audio_policy": "STRIP_ALL_AUDIO_ON_PROTECTED_EXPORT",
            "video_security_policy": "EVERY_PHYSICAL_FRAME_CHANGE_GUARD + OCR_ON_EVIDENCE_OR_NOVEL_FRAMES + FULL_TIMELINE_RELEASE_RESCAN",
            "video_frame_map": frame_map,
            "video_evidence_frame_indices": list(info.sampled_frame_indices),
            "video_security_selected_frame_indices": list(selected_indices),
            "video_security_scan_stats": security_stats,
        },
    )


def _font(size: int) -> ImageFont.ImageFont:
    for path in (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ):
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def build_demo_video() -> bytes:
    """Return a deterministic fictional short MP4 fixture for browser acceptance.

    The fixture contains only synthetic test data and deliberately moves the
    PII panel by a few pixels so the temporal interpolation path is exercised.
    """
    width, height, fps, total_frames = 960, 540, 6.0, 30
    temp_path = None
    writer = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as handle:
            temp_path = handle.name
        writer = cv2.VideoWriter(
            temp_path,
            cv2.VideoWriter_fourcc(*"mp4v"),
            fps,
            (width, height),
        )
        if not writer.isOpened():
            raise VideoError("Local MP4 encoder is unavailable")
        title_font = _font(30)
        body_font = _font(24)
        for index in range(total_frames):
            image = Image.new("RGB", (width, height), "white")
            draw = ImageDraw.Draw(image)
            x = 70 + int(round(12 * math.sin(index / 5.0)))
            y = 70 + int(round(5 * math.cos(index / 7.0)))
            draw.text((x, y), "Citizen Support Video", font=title_font, fill="black")
            lines = (
                "Subject: Dev Malhotra",
                "Email: dev.malhotra@example.org",
                "Phone: +91 90000 10001",
                "Location: Bengaluru, Karnataka",
                "Case: VG-2026-1042",
            )
            for row, text in enumerate(lines):
                draw.text((x, y + 65 + row * 55), text, font=body_font, fill="black")
            bgr = cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2BGR)
            writer.write(bgr)
        writer.release()
        writer = None
        data = Path(temp_path).read_bytes()
        probe_video(data, "test_video_privacy_demo.mp4")
        return data
    finally:
        if writer is not None:
            writer.release()
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
