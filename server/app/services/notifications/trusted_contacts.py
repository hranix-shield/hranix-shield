from __future__ import annotations

from collections.abc import Iterable

from fastapi import Request


class TrustedContactRegistry:
    """The people who get escalations and channel-5 (email) notifications
    (§5.4 of the analytical plan: "доверенные лица — адресаты эскалаций и
    переадресаций").

    Judgment call (Phase 0, see A-13 task report): in-process memory, not a
    DB table — same precedent as `SecurityConsoleRegistry`'s console
    toggles (A-10). A dedicated `trusted_contacts` table + CRUD + migration
    is a reasonable amount of extra surface for what is, in Phase 0, a
    short list of email addresses with no per-contact behavior beyond "is
    it in the list" — genuinely proportionate to defer to a later phase if
    it grows richer (per-contact channel preference, phone numbers once the
    phone-terminal exists, etc). Seeded from `Settings.trusted_contact_emails`
    at `create_app()` time so a real deployment's `.env` still survives a
    restart; edits made through the settings UI at runtime do not persist
    across a restart, same accepted limitation as the console toggles.

    One instance per `create_app()` call, same non-singleton reasoning as
    every other registry in this codebase.
    """

    def __init__(self, *, seed_emails: Iterable[str] = ()) -> None:
        self._emails: list[str] = _dedupe(seed_emails)

    def emails(self) -> list[str]:
        return list(self._emails)

    def set_all(self, emails: Iterable[str]) -> None:
        self._emails = _dedupe(emails)

    def add(self, email: str) -> None:
        email = email.strip()
        if email and email not in self._emails:
            self._emails.append(email)

    def remove(self, email: str) -> None:
        self._emails = [existing for existing in self._emails if existing != email]


def _dedupe(emails: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(email.strip() for email in emails if email and email.strip()))


def get_trusted_contact_registry(request: Request) -> TrustedContactRegistry:
    """FastAPI dependency: the registry instance attached to this app (see
    app_factory.create_app -> app.state.trusted_contact_registry)."""
    return request.app.state.trusted_contact_registry
