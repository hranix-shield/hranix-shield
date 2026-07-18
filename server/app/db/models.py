from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    topic: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )


class BackupJob(Base):
    __tablename__ = "backup_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(50), nullable=False)


class Notification(Base):
    """A-13: one delivery attempt of an event-bus event through the
    notification channel matrix (see services/notifications/).

    `channels` is the JSON list of channel ids the matrix had enabled for
    `topic` at the moment this row was created (post quiet-hours filtering
    below) — an empty list on a `suppressed_quiet_hours=True` row means
    "matched channels existed, but none were actually used", not "no
    channels were configured".

    `read_at`/`acknowledged_at` are distinct: `read_at` is the lightweight
    "seen in the panel" mark used by the topbar's unread badge (channel 4);
    `acknowledged_at` is the explicit "someone dealt with this" action that
    stops the escalation sweep (services/notifications/escalation.py) from
    treating a critical notification as still outstanding. A row can be
    read without being acknowledged (glanced at the bell, didn't act yet).
    """

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    topic: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    critical: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    channels: Mapped[list | None] = mapped_column(JSON, nullable=True)
    suppressed_quiet_hours: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    email_sent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
