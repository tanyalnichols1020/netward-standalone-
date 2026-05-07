from __future__ import annotations

import re
import time

import pytest

from netward.mirror import MirrorSafetyError, fire_mirror
from netward.schema import MirrorResponse, Probe


def _probe(user_agent: str = "curl/8.0") -> Probe:
    return {
        "id": "probe-1",
        "timestamp": time.time(),
        "source_id": "source-1",
        "classification": "probe",
        "request": {
            "method": "GET",
            "path": "/wp-admin",
            "headers": {"User-Agent": user_agent},
        },
    }


def _probe_with_extracted_user_agent(
    extracted: str,
    header: str = "header-ua",
) -> Probe:
    probe = _probe(header)
    probe["request"]["user_agent"] = extracted
    return probe


def _response(template: str, vars_: dict[str, str]) -> MirrorResponse:
    return {
        "id": "mirror-1",
        "matches_pattern_id": "pattern-1",
        "intensity": "moderate",
        "http_status": 200,
        "headers": {"Content-Type": "application/json"},
        "body_template": template,
        "body_template_vars": vars_,
        "description": "test mirror",
        "created_at": time.time(),
    }


def test_generators_render_non_empty_unique_values():
    response = _response(
        (
            "{{uuid}} {{timestamp}} {{fake_id}} {{fake_token}} "
            "{{fake_redirect}} {{random_int}} {{bounded}}"
        ),
        {
            "uuid": "uuid",
            "timestamp": "timestamp",
            "fake_id": "fake_id",
            "fake_token": "fake_token",
            "fake_redirect": "fake_redirect",
            "random_int": "random_int",
            "bounded": "random_int:10:20",
        },
    )

    first = fire_mirror(_probe(), response)["body"]
    second = fire_mirror(_probe(), response)["body"]

    assert first
    assert second
    assert first != second
    assert re.search(r"\b1\d|20\b", first)
    assert first.count(".") >= 2


def test_user_agent_echo_is_sanitized_for_pii():
    response = _response("ua={{ua}}", {"ua": "user_agent_echo"})

    rendered = fire_mirror(_probe("scanner admin@example.com"), response)

    assert rendered["body"] == "ua="


def test_user_agent_echo_prefers_extracted_request_field():
    response = _response("ua={{ua}}", {"ua": "user_agent_echo"})

    rendered = fire_mirror(_probe_with_extracted_user_agent("extracted-ua"), response)

    assert rendered["body"] == "ua=extracted-ua"


@pytest.mark.parametrize(
    "user_agent",
    [
        "<script>alert(1)</script>",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "%3Cscript%3Ealert(1)%3C/script%3E",
    ],
)
def test_user_agent_echo_never_reflects_active_html(user_agent):
    response = _response("<html>{{ua}}</html>", {"ua": "user_agent_echo"})

    rendered = fire_mirror(_probe(user_agent), response)

    assert "<script" not in rendered["body"].lower()
    assert "&lt;script" not in rendered["body"].lower()


def test_user_agent_echo_escapes_passive_text():
    response = _response("<html>{{ua}}</html>", {"ua": "user_agent_echo"})

    rendered = fire_mirror(_probe("scanner <bot>"), response)

    assert "scanner &lt;bot&gt;" in rendered["body"]
    assert "scanner <bot>" not in rendered["body"]


def test_fire_mirror_returns_status_headers_and_body():
    response = _response("ok {{id}}", {"id": "fake_id"})
    response["http_status"] = 202
    response["headers"] = {"Content-Type": "text/plain", "X-Mirror": "netward"}

    rendered = fire_mirror(_probe(), response)

    assert rendered["status"] == 202
    assert rendered["headers"]["X-Mirror"] == "netward"
    assert rendered["body"].startswith("ok ")


def test_header_template_placeholder_is_rendered():
    """X1: header values with {{...}} placeholders must be rendered, not emitted literally."""
    response = _response("body", {"req_id": "uuid"})
    response["headers"] = {"Content-Type": "text/plain", "X-Request-Id": "{{req_id}}"}
    rendered = fire_mirror(_probe(), response)
    assert "{{req_id}}" not in rendered["headers"]["X-Request-Id"], (
        "header placeholder was not substituted"
    )
    assert len(rendered["headers"]["X-Request-Id"]) > 0


def test_header_and_body_share_rendered_var_values():
    """X1: the same generated value for a var appears in both header and body."""
    response = _response("id={{req_id}}", {"req_id": "uuid"})
    response["headers"] = {"X-Req": "{{req_id}}"}
    rendered = fire_mirror(_probe(), response)
    body_id = rendered["body"].split("=", 1)[1]
    assert rendered["headers"]["X-Req"] == body_id


def test_location_header_placeholder_renders_to_real_path():
    """X1: Location: {{honeypot_path}} → a real redirect path, not the literal."""
    response = _response("redirecting", {"honeypot_path": "fake_redirect"})
    response["http_status"] = 302
    response["headers"] = {"Location": "{{honeypot_path}}"}
    rendered = fire_mirror(_probe(), response)
    assert "{{honeypot_path}}" not in rendered["headers"]["Location"]
    assert rendered["headers"]["Location"].startswith("/")


def test_server_header_defaults_to_nginx_when_absent():
    """X2: mirrors without an explicit Server header get Server: nginx injected."""
    response = _response("ok", {})
    rendered = fire_mirror(_probe(), response)
    assert rendered["headers"].get("Server") == "nginx"


def test_explicit_server_header_is_preserved():
    """X2: mirrors with an explicit Server header keep their value unchanged."""
    response = _response("ok", {})
    response["headers"] = {"Content-Type": "text/plain", "Server": "Apache/2.4.51"}
    rendered = fire_mirror(_probe(), response)
    assert rendered["headers"]["Server"] == "Apache/2.4.51"


def test_hostile_payload_is_rejected():
    response = _response("<script>alert(1)</script>", {})

    with pytest.raises(MirrorSafetyError, match="hostile"):
        fire_mirror(_probe(), response)


def test_pii_named_template_variable_is_rejected():
    response = _response("{{email}}", {"email": "user_agent_echo"})

    with pytest.raises(MirrorSafetyError, match="PII-like"):
        fire_mirror(_probe(), response)
