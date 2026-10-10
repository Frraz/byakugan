"""Testes dos marcadores de desserialização insegura (puro, sem rede)."""

from __future__ import annotations

import base64

from apps.scans.web.deserialization import (
    detect_java_serialized_cookie,
    detect_java_serialized_in_body,
    detect_php_serialized_cookie,
    detect_php_serialized_in_body,
    detect_viewstate,
)

#: Base64 de um stream de serialização Java real (header + alguns bytes).
JAVA_SERIALIZED_B64 = base64.b64encode(b"\xac\xed\x00\x05sr\x00\x11java.lang.Integer").decode()

PHP_SERIALIZED = 'O:8:"stdClass":1:{s:4:"name";s:5:"alice";}'


# --- Java ------------------------------------------------------------------


def test_detect_java_serialized_cookie_by_shiro_name():
    finding = detect_java_serialized_cookie([{"name": "rememberMe", "value": "anything"}])
    assert finding is not None
    assert finding["severity"] == "critical"
    assert finding["playbook_key"] == "integrity.java-deserialization"


def test_detect_java_serialized_cookie_case_insensitive_shiro_name():
    assert detect_java_serialized_cookie([{"name": "RememberMe", "value": "x"}]) is not None


def test_detect_java_serialized_cookie_by_magic_bytes():
    finding = detect_java_serialized_cookie(
        [{"name": "session_state", "value": JAVA_SERIALIZED_B64}]
    )
    assert finding is not None
    assert finding["severity"] == "high"
    assert finding["playbook_key"] == "integrity.java-deserialization"


def test_detect_java_serialized_cookie_none_for_normal_cookie():
    assert detect_java_serialized_cookie([{"name": "sessionid", "value": "abc123"}]) is None


def test_detect_java_serialized_cookie_empty_list():
    assert detect_java_serialized_cookie([]) is None


def test_detect_java_serialized_in_body_matches():
    finding = detect_java_serialized_in_body(
        url="https://t/page", body=f"<input type='hidden' value='{JAVA_SERIALIZED_B64}'>"
    )
    assert finding is not None
    assert finding["playbook_key"] == "integrity.java-deserialization"
    assert "URL: https://t/page" in finding["evidence"]


def test_detect_java_serialized_in_body_none_for_clean_body():
    assert detect_java_serialized_in_body(url="https://t/page", body="<html>hello</html>") is None


def test_detect_java_serialized_in_body_rn008_complete():
    finding = detect_java_serialized_in_body(url="https://t/page", body=JAVA_SERIALIZED_B64)
    assert finding["description"].strip()
    assert finding["evidence"].strip()
    assert finding["recommendation"].strip()
    assert finding["category"] == "integrity"


# --- PHP -------------------------------------------------------------------


def test_detect_php_serialized_in_body_matches():
    finding = detect_php_serialized_in_body(
        url="https://t/page", body=f"<!-- debug: {PHP_SERIALIZED} -->"
    )
    assert finding is not None
    assert finding["playbook_key"] == "integrity.php-object-injection"


def test_detect_php_serialized_in_body_none_for_clean_body():
    assert detect_php_serialized_in_body(url="https://t/page", body="<html>hello</html>") is None


def test_detect_php_serialized_cookie_matches():
    finding = detect_php_serialized_cookie([{"name": "prefs", "value": PHP_SERIALIZED}])
    assert finding is not None
    assert finding["playbook_key"] == "integrity.php-object-injection"
    assert "prefs" in finding["evidence"]


def test_detect_php_serialized_cookie_none_for_normal_cookie():
    assert detect_php_serialized_cookie([{"name": "sessionid", "value": "abc123"}]) is None


def test_php_serialized_does_not_match_plain_text():
    # Garante que a regex é estrutural, não um gatilho em qualquer "O:" solto.
    assert detect_php_serialized_in_body(url="x", body="O: the letter, not an object") is None


# --- ASP.NET ViewState ------------------------------------------------------


def test_detect_viewstate_flags_form_without_encrypted_field():
    form = {"action": "https://t/default.aspx", "method": "POST", "inputs": ["__VIEWSTATE", "q"]}
    finding = detect_viewstate(url=form["action"], form=form)
    assert finding is not None
    assert finding["severity"] == "low"
    assert finding["playbook_key"] == "integrity.viewstate-exposed"


def test_detect_viewstate_none_when_encrypted_field_present():
    form = {
        "action": "https://t/default.aspx",
        "method": "POST",
        "inputs": ["__VIEWSTATE", "__VIEWSTATEENCRYPTED"],
    }
    assert detect_viewstate(url=form["action"], form=form) is None


def test_detect_viewstate_none_without_viewstate_field():
    form = {"action": "https://t/search", "method": "GET", "inputs": ["q"]}
    assert detect_viewstate(url=form["action"], form=form) is None


def test_detect_viewstate_case_insensitive():
    form = {"action": "https://t/x", "method": "POST", "inputs": ["__viewstate"]}
    assert detect_viewstate(url=form["action"], form=form) is not None
