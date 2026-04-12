from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from intel.models import IngestionRun


class TeeWriter:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, message):
        for stream in self.streams:
            stream.write(message)
        return len(message)

    def flush(self):
        for stream in self.streams:
            flush = getattr(stream, "flush", None)
            if flush:
                flush()

    def isatty(self):
        return any(getattr(stream, "isatty", lambda: False)() for stream in self.streams)


class Command(BaseCommand):
    help = (
        "Run refresh_intel for external schedulers with a logfile and lockfile "
        "to prevent overlapping runs."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--provider",
            type=str,
            help="Run only one provider by key, such as threatfox or virustotal.",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            help="HTTP timeout in seconds to pass to provider requests.",
        )
        parser.add_argument(
            "--since",
            type=str,
            help="ISO datetime or relative window like 24h or 7d.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Fetch and evaluate work without writing database changes.",
        )
        parser.add_argument(
            "--no-feed-refresh",
            action="store_true",
            help="Skip the post-ingestion dashboard/feed refresh snapshot step.",
        )
        parser.add_argument(
            "--log-file",
            type=str,
            default=settings.INTEL_REFRESH_LOG_FILE,
            help="File to append scheduled refresh output to.",
        )
        parser.add_argument(
            "--lock-file",
            type=str,
            default=settings.INTEL_REFRESH_LOCK_FILE,
            help="Advisory lockfile used to prevent overlapping scheduled runs.",
        )

    def handle(self, *args, **options):
        log_path = Path(options["log_file"]).expanduser()
        lock_path = Path(options["lock_file"]).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        with log_path.open("a", encoding="utf-8") as log_file:
            writer = TeeWriter(self.stdout, log_file)
            timestamp = timezone.now().isoformat()
            self._write_log_line(
                writer,
                f"[{timestamp}] scheduled refresh starting "
                f"(log_file={log_path}, lock_file={lock_path})",
            )

            with self._try_lock(lock_path, writer) as acquired:
                if not acquired:
                    return

                try:
                    call_started_at = timezone.now()
                    call_command(
                        "refresh_intel",
                        provider=options.get("provider"),
                        timeout=options.get("timeout"),
                        since=options.get("since"),
                        dry_run=options.get("dry_run", False),
                        no_feed_refresh=options.get("no_feed_refresh", False),
                        trigger="scheduled",
                        stdout=writer,
                        stderr=writer,
                    )
                except CommandError as exc:
                    self._write_log_line(
                        writer,
                        f"[{timezone.now().isoformat()}] scheduled refresh failed: {exc}",
                    )
                    raise
                except Exception as exc:
                    self._write_log_line(
                        writer,
                        f"[{timezone.now().isoformat()}] scheduled refresh crashed: {exc}",
                    )
                    raise

                run = (
                    IngestionRun.objects.filter(
                        trigger="scheduled",
                        started_at__gte=call_started_at,
                    )
                    .order_by("-started_at", "-id")
                    .first()
                )
                outcome = "finished successfully"
                if getattr(run, "status", "") == "partial":
                    outcome = "finished with partial provider failures"
                self._write_log_line(
                    writer,
                    f"[{timezone.now().isoformat()}] scheduled refresh {outcome}",
                )

    @contextmanager
    def _try_lock(self, lock_path: Path, writer: TeeWriter):
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                lock_file.seek(0)
                active_holder = lock_file.read().strip()
                message = f"[{timezone.now().isoformat()}] scheduled refresh skipped; another run holds {lock_path}"
                if active_holder:
                    message = f"{message} ({active_holder})"
                self._write_log_line(writer, message)
                yield False
                return

            lock_file.seek(0)
            lock_file.truncate()
            lock_file.write(
                f"pid={os.getpid()} started_at={timezone.now().isoformat()}"
            )
            lock_file.flush()

            try:
                yield True
            finally:
                lock_file.seek(0)
                lock_file.truncate()
                lock_file.write(
                    f"released_at={timezone.now().isoformat()} pid={os.getpid()}"
                )
                lock_file.flush()
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _write_log_line(self, writer: TeeWriter, message: str) -> None:
        writer.write(f"{message}\n")
        writer.flush()
