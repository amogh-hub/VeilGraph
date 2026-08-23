# VeilGraph Stage-2 Video Redaction

## Scope

VeilGraph accepts local **MP4** and **MOV** video inputs for Levels 1–4. Video is normalized into timestamped `VIDEO_FRAME` units in Universal Privacy IR so the same detector, Identity Exposure Graph, policy compiler, audit and proof path is reused rather than creating a separate privacy engine.

## Analysis

- OpenCV validates and decodes the video locally.
- Evidence frames are sampled deterministically across the full timeline at the configured evidence rate and committed into Privacy IR.
- Each evidence frame receives local Tesseract OCR plus the existing visual detector path.
- A post-holdout video structural adapter recognizes explicit labels such as `Subject:`, `Location:` and `Case:` without modifying frozen Broad PII v3.
- Repeated person evidence across the timeline is temporally linked so one high-confidence human decision protects the canonical identity across all sampled occurrences.

## Transformation

Every approved evidence region becomes a temporal protection track. Boxes from consecutive evidence frames are linearly interpolated across physical frames so protection is applied between sampled screenshots as well as on them. Textual identity regions are irreversibly replaced with the compiled policy alias/generalization; visual identifiers are blurred/boxed.

### Audio policy

The protected Stage-2 video is intentionally **video-only**. Any source audio track is removed on export. This is fail-closed: VeilGraph does not currently claim offline speech-to-text redaction, so spoken identifiers cannot survive through an unverified audio channel.

## Safety limits

Defaults are local-first and configurable through `VEILGRAPH_` settings:

- duration: 60 seconds
- frames: 3,600
- frame size: up to 1920×1080 and 2.5M pixels/frame
- evidence sampling: 2 frames/second, maximum 120 evidence frames
- upload-size guard remains the global 30 MB default

Longer production workloads belong in the later scalable worker/deployment profile rather than silently bypassing local safety budgets.

## Video-specific 13-gate release profile

A Level 1–4 video must pass all thirteen gates:

1. direct identifier detector rescan
2. independent timeline extraction
3. full OCR rescan of security-selected protected frames
4. independent QR payload recovery attack across every protected physical frame
5. audio-track absence
6. temporal region transformation integrity
7. metadata/embedded-content inspection
8. policy coverage
9. relationship consistency
10. raw container/object scan
11. direct-identifier fragment attack
12. signed manifest/output consistency for the raster timeline
13. video structure preservation (resolution, cadence, frame count, duration)

Any FAIL or INCONCLUSIVE gate keeps release locked.

## Competition fixture

`backend/test_video_privacy_demo.mp4` is fictional synthetic test data. It contains a slightly moving identity panel so the demo and regression suite exercise temporal interpolation rather than static screenshot replacement.

Run:

```bash
./scripts/run_video_matrix.sh
```


## Safety v2 — transient-frame coverage

Stage-2 Safety v2 separates judge-facing **evidence frames** from security coverage. Every physical frame is decoded and change-screened. Representative evidence frames are always OCR/detection inputs; any between-evidence frame containing material novel edge content after translation alignment is promoted into the security OCR/detection set. Thus a one-frame identifier cannot hide merely because it occurs between UI evidence timestamps.

The protected timeline is independently change-screened again during release verification. The critical video frame rescan and independent extraction gate OCR every representative/novel safety frame selected from a 100% physical-frame change pass. Any non-PASS result keeps release locked.

Additional acceptance fixtures:

- `backend/test_video_transient_pii.mp4` — email exists only on an unsampled physical frame; it must still be detected, transformed and verified absent.
- `backend/test_video_privacy_demo_with_audio.mp4` — source audio is present; protected export must contain no audio track.
- `backend/test_video_visual_qr_demo.mp4` — decoded QR region exercises the non-text visual-video path.


## Safety v4 — independent visual payload recovery

OCR failure is not evidence that a QR code is unreadable. Safety v4 adds a separate critical release gate that decodes the **protected raster timeline directly**, without consulting the original visual-detector inventory, graph, or transformation manifest. Every protected physical frame is attacked with fresh OpenCV QR decoding across raw, grayscale, contrast-enhanced and thresholded render variants. Any recoverable QR payload causes `FAIL`; decoder or timeline errors are `INCONCLUSIVE`, so release remains fail-closed.

The judge-facing video Red Team therefore reports **13/13** only when this independent all-frame visual recovery attack also passes.
