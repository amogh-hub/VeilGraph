from __future__ import annotations

from app.core.enums import EntityType
from app.detection.pipeline import detect_all
from app.extraction.document_processor import processed_document_from_decoded_text


def test_v3_does_not_fragment_an_established_labelled_full_address():
    """A stronger existing full-address span must own its region.

    Broad-v3 is allowed to decompose previously unseen address structures, but
    it must not create overlapping BUILDING/STREET/LOCALITY fragments inside an
    address already recognized by the established detector. Overlapping spans
    create duplicate transformations and can break proof-manifest consistency.
    """
    document = processed_document_from_decoded_text(
        "Address: 12 Basalt Lane, Indiranagar, Bengaluru\nPIN code: 560038"
    )
    detections = detect_all(document)

    addresses = [item for item in detections if item.entity_type == EntityType.STREET_ADDRESS]
    assert [item.plaintext for item in addresses] == ["12 Basalt Lane, Indiranagar, Bengaluru"]

    assert not any(
        (item.context_label or "").startswith("broad-pii-v3:")
        and item.entity_type in {
            EntityType.BUILDING_NUMBER,
            EntityType.STREET_ADDRESS,
            EntityType.LOCALITY,
        }
        for item in detections
    )
