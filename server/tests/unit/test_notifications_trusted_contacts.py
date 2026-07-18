import pytest

from app.services.notifications.trusted_contacts import TrustedContactRegistry


@pytest.mark.unit
def test_starts_empty_with_no_seed():
    registry = TrustedContactRegistry()

    assert registry.emails() == []


@pytest.mark.unit
def test_seed_emails_are_deduped_and_stripped():
    registry = TrustedContactRegistry(seed_emails=[" a@example.com", "b@example.com", "a@example.com", " "])

    assert registry.emails() == ["a@example.com", "b@example.com"]


@pytest.mark.unit
def test_add_appends_a_new_email():
    registry = TrustedContactRegistry()

    registry.add("boss@example.com")

    assert registry.emails() == ["boss@example.com"]


@pytest.mark.unit
def test_add_is_idempotent():
    registry = TrustedContactRegistry(seed_emails=["boss@example.com"])

    registry.add("boss@example.com")

    assert registry.emails() == ["boss@example.com"]


@pytest.mark.unit
def test_add_ignores_blank_input():
    registry = TrustedContactRegistry()

    registry.add("   ")

    assert registry.emails() == []


@pytest.mark.unit
def test_remove_drops_just_that_email():
    registry = TrustedContactRegistry(seed_emails=["a@example.com", "b@example.com"])

    registry.remove("a@example.com")

    assert registry.emails() == ["b@example.com"]


@pytest.mark.unit
def test_set_all_replaces_the_whole_list():
    registry = TrustedContactRegistry(seed_emails=["a@example.com"])

    registry.set_all(["c@example.com", "d@example.com", "c@example.com"])

    assert registry.emails() == ["c@example.com", "d@example.com"]
