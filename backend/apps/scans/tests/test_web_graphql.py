"""Testes do detector de introspecção GraphQL exposta (puro, sem rede)."""

from __future__ import annotations

from apps.scans.web.graphql_checks import (
    GRAPHQL_PATHS,
    build_introspection_url,
    classify_introspection,
)


def test_build_introspection_url_encodes_query():
    url = build_introspection_url("https://t/", "/graphql")
    assert url.startswith("https://t/graphql?query=")
    assert "__schema" in url


def test_classify_introspection_detects_enabled_schema():
    body = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
    finding = classify_introspection(url="https://t/graphql", status_code=200, body=body)
    assert finding is not None
    assert finding["playbook_key"] == "exposure.graphql-introspection"
    assert finding["category"] == "exposure"


def test_classify_introspection_none_when_disabled():
    body = '{"errors":[{"message":"introspection is disabled"}]}'
    assert classify_introspection(url="https://t/graphql", status_code=200, body=body) is None


def test_classify_introspection_none_on_non_200():
    body = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
    assert classify_introspection(url="https://t/graphql", status_code=404, body=body) is None


def test_graphql_paths_are_relative():
    assert all(path.startswith("/") for path in GRAPHQL_PATHS)
