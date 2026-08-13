from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VEILGRAPH_", extra="ignore")

    app_name: str = "VeilGraph"
    version: str = "0.6.1-phase2-final-hardening"
    offline_mode: bool = True
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    online_api_token: SecretStr | None = None
    online_require_https: bool = True
    trust_proxy_headers: bool = False
    trusted_proxy_networks: tuple[str, ...] = ()
    max_concurrent_heavy_requests: int = 4
    heavy_request_queue_timeout_seconds: float = 2.0
    ops_metrics_window: int = 2048
    max_proof_package_bytes: int = 120 * 1024 * 1024
    max_proof_zip_entries: int = 96
    max_proof_uncompressed_bytes: int = 300 * 1024 * 1024
    max_proof_entry_compression_ratio: float = 250.0
    database_path: Path = Path("veilgraph-slice-e.db")
    workspace_root: Path = Path("/tmp/veilgraph_jobs_slice_e")
    signing_key_path: Path = Path(".veilgraph/device-ed25519.key")
    max_file_size_bytes: int = 30 * 1024 * 1024
    max_pdf_pages: int = 50
    max_render_pixels_per_page: int = 30_000_000
    max_total_render_pixels: int = 250_000_000
    max_image_pixels: int = 40_000_000
    max_video_duration_seconds: float = 60.0
    max_video_frames: int = 3600
    max_video_width: int = 1920
    max_video_height: int = 1080
    max_video_frame_pixels: int = 2_500_000
    video_evidence_sample_fps: float = 2.0
    max_video_evidence_frames: int = 120
    ocr_language: str = "eng"
    ocr_dpi: int = 220
    ocr_auto_rotate: bool = True
    ocr_min_orientation_confidence: float = 3.0
    ocr_min_short_side_pixels: int = 900
    ocr_max_upscale: float = 3.0
    retention_sweep_seconds: float = 5.0
    retention_worker_enabled: bool = True
    enforce_policy_floors: bool = False
    allowed_origins: tuple[str, ...] = (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    )


settings = Settings()
