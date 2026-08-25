from app.browser.models import (
    BrowserAction,
    BrowserActionPlan,
    BrowserPublicElement,
    BrowserPublicPage,
    BrowserReleasePayload,
)
from app.browser.reasoning import (
    _action_confidence_basis_points,
    validate_action_plan,
)


AUTONOMOUS_THRESHOLD_BP = 7_000


def _element(
    element_id: str,
    label: str,
    *,
    role: str = "button",
    disabled: bool = False,
) -> BrowserPublicElement:
    return BrowserPublicElement(
        element_id=element_id,
        role=role,
        label=label,
        text=label,
        disabled=disabled,
    )


def _payload(
    elements: list[BrowserPublicElement],
    *,
    task: str = (
        "Open the available follow-up appointment "
        "options and complete it."
    ),
) -> BrowserReleasePayload:
    return BrowserReleasePayload(
        session_id="session_action_confidence_v2",
        task_id="task_action_confidence_v2",
        task=task,
        page=BrowserPublicPage(
            origin="http://127.0.0.1:8765",
            elements=elements,
        ),
        privacy_level=4,
        network_privacy_floor=4,
        identity_exposure_before=95,
        residual_identity_exposure=15,

        # Deliberately reproduce the live PrismCare values that caused
        # the old false low-confidence decision.
        task_utility_score=82,
        minimization_basis_points=5638,
        terminal_evidence="NONE",
    )


def test_unique_relevant_low_impact_click_crosses_autonomous_threshold():
    target = _element(
        "vg_followup_options",
        "View Follow-Up Options",
    )

    payload = _payload([
        target,
        _element(
            "vg_profile_details",
            "Profile Details",
        ),
        _element(
            "vg_help_center",
            "Help Center",
            role="link",
        ),
    ])

    score = _action_confidence_basis_points(
        payload,
        "CLICK",
        target,
    )

    assert score >= AUTONOMOUS_THRESHOLD_BP

    # Critical regression:
    # privacy minimization must no longer cap execution confidence.
    assert score > payload.minimization_basis_points


def test_high_impact_click_remains_mandatory_confirmation_even_with_high_confidence():
    target = _element(
        "vg_confirm_appointment",
        "Confirm Appointment",
    )

    payload = _payload(
        [target],
        task="Confirm appointment",
    )

    score = _action_confidence_basis_points(
        payload,
        "CLICK",
        target,
    )

    assert score >= AUTONOMOUS_THRESHOLD_BP

    proposed = BrowserAction(
        action="CLICK",
        target_id=target.element_id,
        confidence_basis_points=score,
        reason="Model selected next action",
        requires_confirmation=False,
    )

    normalized = validate_action_plan(
        BrowserActionPlan(
            session_id=payload.session_id,
            task_id=payload.task_id,
            actions=[proposed],
            complete=False,
            summary="",
        ),
        payload,
    )

    assert (
        normalized.actions[0].requires_confirmation
        is True
    )


def test_ambiguous_equal_click_targets_stay_below_autonomous_threshold():
    selected = _element(
        "vg_followup_options_a",
        "View Follow-Up Options",
    )

    competitor = _element(
        "vg_followup_options_b",
        "View Follow-Up Options",
    )

    payload = _payload([
        selected,
        competitor,
    ])

    score = _action_confidence_basis_points(
        payload,
        "CLICK",
        selected,
    )

    assert score < AUTONOMOUS_THRESHOLD_BP


def test_unrelated_model_selected_click_stays_below_autonomous_threshold():
    selected = _element(
        "vg_download_invoice",
        "Download Invoice",
    )

    relevant = _element(
        "vg_followup_options",
        "View Follow-Up Options",
    )

    payload = _payload([
        selected,
        relevant,
    ])

    score = _action_confidence_basis_points(
        payload,
        "CLICK",
        selected,
    )

    assert score < AUTONOMOUS_THRESHOLD_BP


def test_non_click_actions_remain_conservative_in_v2():
    payload = _payload([])

    for action in (
        "TYPE",
        "SELECT",
        "NAVIGATE",
        "SCROLL",
        "READ",
    ):
        assert (
            _action_confidence_basis_points(
                payload,
                action,
                None,
            )
            < AUTONOMOUS_THRESHOLD_BP
        )

    assert (
        _action_confidence_basis_points(
            payload,
            "WAIT",
            None,
        )
        == 0
    )
