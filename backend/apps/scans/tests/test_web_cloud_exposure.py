"""Testes do detector de referências a cloud storage (puro, sem rede)."""

from __future__ import annotations

from apps.scans.web.cloud_exposure import (
    classify_cloud_storage_reference,
    find_cloud_storage_urls,
)


def test_finds_s3_virtual_hosted_url():
    text = '<img src="https://my-assets-bucket.s3.amazonaws.com/logo.png">'
    found = find_cloud_storage_urls(text)
    assert found == ["https://my-assets-bucket.s3.amazonaws.com"]


def test_finds_s3_virtual_hosted_url_with_region():
    text = 'src="https://my-bucket.s3.us-east-1.amazonaws.com/file.pdf"'
    assert find_cloud_storage_urls(text) == ["https://my-bucket.s3.us-east-1.amazonaws.com"]


def test_finds_s3_path_style_url():
    text = 'href="https://s3.amazonaws.com/legacy-bucket/report.pdf"'
    assert find_cloud_storage_urls(text) == ["https://s3.amazonaws.com/legacy-bucket"]


def test_finds_gcs_virtual_hosted_and_path_style():
    text = (
        '<script src="https://my-bucket.storage.googleapis.com/app.js"></script>'
        '<a href="https://storage.googleapis.com/other-bucket/file">x</a>'
    )
    found = find_cloud_storage_urls(text)
    assert "https://my-bucket.storage.googleapis.com" in found
    assert "https://storage.googleapis.com/other-bucket" in found


def test_finds_azure_blob_url():
    text = 'src="https://myaccount.blob.core.windows.net/mycontainer/file.jpg"'
    assert find_cloud_storage_urls(text) == ["https://myaccount.blob.core.windows.net/mycontainer"]


def test_finds_nothing_in_plain_page():
    assert find_cloud_storage_urls("<html>Nothing here, just regular content.</html>") == []


def test_deduplicates_repeated_references():
    text = (
        '<img src="https://bucket.s3.amazonaws.com/a.png">'
        '<img src="https://bucket.s3.amazonaws.com/b.png">'
    )
    assert find_cloud_storage_urls(text) == ["https://bucket.s3.amazonaws.com"]


def test_classify_cloud_storage_reference_is_rn008_complete_and_low_severity():
    finding = classify_cloud_storage_reference("https://bucket.s3.amazonaws.com")
    assert finding["description"].strip()
    assert finding["evidence"].strip()
    assert finding["recommendation"].strip()
    assert finding["severity"] == "low"
    assert finding["category"] == "exposure"
    assert finding["playbook_key"] == "exposure.cloud-storage-reference"
    assert "https://bucket.s3.amazonaws.com" in finding["evidence"]
