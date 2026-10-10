"""Testes do mapeamento MITRE ATT&CK (puro — sem banco)."""

from __future__ import annotations

from apps.scans.mitre import CLASS_TO_MITRE, MITRE_TECHNIQUES, resolve_mitre


def test_resolve_mitre_returns_technique_and_name():
    assert resolve_mitre("injection.sqli-error") == (
        "T1190",
        "Exploit Public-Facing Application",
    )


def test_resolve_mitre_specific_technique_for_command_injection():
    # Mais específico que o T1190 genérico — o que realmente diferencia o
    # mapeamento de só repetir a mesma técnica para as 42 classes.
    assert resolve_mitre("injection.command-injection") == (
        "T1059",
        "Command and Scripting Interpreter",
    )


def test_resolve_mitre_jwt_forgery():
    assert resolve_mitre("auth.jwt-weak") == ("T1606", "Forge Web Credentials")


def test_resolve_mitre_unmapped_class_returns_empty_tuple():
    # misconfig.weak-csp é uma FRAQUEZA de controle, não uma técnica de
    # ataque em si — honestidade por design, igual ao LIMITED_COVERAGE do OWASP.
    assert resolve_mitre("misconfig.weak-csp") == ("", "")


def test_resolve_mitre_unknown_key_returns_empty_tuple():
    assert resolve_mitre("nonexistent.key") == ("", "")


def test_resolve_mitre_empty_key_returns_empty_tuple():
    assert resolve_mitre("") == ("", "")


def test_every_mapped_technique_id_has_a_name():
    # Nenhuma entrada de CLASS_TO_MITRE pode apontar para uma técnica sem
    # nome cadastrado em MITRE_TECHNIQUES — evita um "T-algumacoisa" sem rótulo.
    for playbook_key, technique in CLASS_TO_MITRE.items():
        assert technique in MITRE_TECHNIQUES, f"{playbook_key} -> {technique} sem nome cadastrado"


def test_every_mapped_technique_id_has_valid_format():
    # IDs ATT&CK reais são "T" + 4 dígitos, com sub-técnica opcional ".NNN".
    import re

    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    for technique in MITRE_TECHNIQUES:
        assert pattern.match(technique), f"ID de técnica malformado: {technique}"


def test_coverage_is_intentionally_partial_not_all_42_classes():
    # Honestidade por design: menos da metade das classes está mapeada — as
    # outras não têm uma técnica ATT&CK inequívoca, e isso é deliberado, não
    # uma lacuna escondida. Trava o número para que uma expansão futura seja
    # uma decisão consciente (atualizando este teste), não um acidente.
    assert len(CLASS_TO_MITRE) == 27
