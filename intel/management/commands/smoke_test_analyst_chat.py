import json
from contextlib import contextmanager

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from intel.services.chatbot import ChatbotServiceError, build_chat_response


class Command(BaseCommand):
    help = (
        "Smoke-test analyst chatbot integration using the production chat service "
        "path, including optional n8n webhook routing."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--prompt",
            type=str,
            default="What do we know about 1.2.3.4?",
            help="Analyst prompt to send through the chatbot service.",
        )
        parser.add_argument(
            "--summary-mode",
            type=str,
            default="analyst",
            choices=["auto", "analyst", "executive", "technical", "brief"],
            help="Requested summary mode.",
        )
        parser.add_argument(
            "--provider-mode",
            type=str,
            choices=["local", "hybrid", "n8n"],
            help=(
                "Temporarily override INTEL_CHAT_PROVIDER for this command run "
                "(local, hybrid, or n8n)."
            ),
        )
        parser.add_argument(
            "--n8n-webhook-url",
            type=str,
            help="Temporarily override INTEL_CHAT_N8N_WEBHOOK_URL for this command run.",
        )
        parser.add_argument(
            "--n8n-bearer-token",
            type=str,
            help="Temporarily override INTEL_CHAT_N8N_BEARER_TOKEN for this command run.",
        )
        parser.add_argument(
            "--n8n-timeout",
            type=int,
            help="Temporarily override INTEL_CHAT_N8N_TIMEOUT for this command run.",
        )
        parser.add_argument(
            "--require-n8n",
            action="store_true",
            help=(
                "Fail if response provider is not n8n (useful to verify hybrid mode "
                "did not silently fall back to local)."
            ),
        )
        parser.add_argument(
            "--search",
            type=str,
            default="",
            help="Optional dashboard search filter for scoped chatbot context.",
        )
        parser.add_argument(
            "--tag",
            type=str,
            default="",
            help="Optional dashboard tag filter for scoped chatbot context.",
        )
        parser.add_argument(
            "--value-type",
            type=str,
            default="",
            help="Optional IOC value type filter for scoped chatbot context.",
        )
        parser.add_argument(
            "--threat-type",
            type=str,
            default="",
            help="Optional threat type filter for scoped chatbot context.",
        )
        parser.add_argument(
            "--malware-family",
            type=str,
            default="",
            help="Optional malware family filter for scoped chatbot context.",
        )
        parser.add_argument(
            "--confidence-band",
            type=str,
            default="",
            help="Optional confidence band filter for scoped chatbot context.",
        )
        parser.add_argument(
            "--start-date",
            type=str,
            default="",
            help="Optional ISO date (YYYY-MM-DD) for filter scope start.",
        )
        parser.add_argument(
            "--end-date",
            type=str,
            default="",
            help="Optional ISO date (YYYY-MM-DD) for filter scope end.",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            help="Print full response payload as JSON.",
        )

    def handle(self, *args, **options):
        prompt = str(options.get("prompt") or "").strip()
        if not prompt:
            raise CommandError("--prompt must not be empty.")
        if len(prompt) > 2500:
            raise CommandError("--prompt must be 2500 characters or fewer.")

        filters_payload = {
            "start_date": options.get("start_date") or "",
            "end_date": options.get("end_date") or "",
            "value_type": options.get("value_type") or "",
            "malware_family": options.get("malware_family") or "",
            "threat_type": options.get("threat_type") or "",
            "confidence_band": options.get("confidence_band") or "",
            "search": options.get("search") or "",
            "tag": options.get("tag") or "",
            "sort": "ingested",
            "direction": "desc",
            "page": 1,
            "page_size": 25,
        }

        with self._temporary_chat_settings(options):
            try:
                response = build_chat_response(
                    user_prompt=prompt,
                    summary_mode=options.get("summary_mode"),
                    filters_payload=filters_payload,
                )
            except ChatbotServiceError as exc:
                raise CommandError(str(exc)) from exc
            except Exception as exc:  # pragma: no cover - defensive surface
                raise CommandError(f"Unexpected chatbot error: {exc}") from exc

        provider = str(response.get("provider") or "").strip().lower()
        if options.get("require_n8n") and provider != "n8n":
            raise CommandError(
                "Smoke test did not use n8n provider. "
                f"Received provider={response.get('provider')!r}."
            )

        self.stdout.write(self.style.SUCCESS("analyst_chat smoke test succeeded"))
        self.stdout.write(f"provider: {response.get('provider')}")
        self.stdout.write(f"summary_mode: {response.get('summary_mode')}")
        self.stdout.write(f"source_of_truth: {response.get('source_of_truth')}")
        self.stdout.write(f"answer: {response.get('answer')}")

        key_findings = response.get("key_findings") or []
        if key_findings:
            self.stdout.write("key_findings:")
            for item in key_findings:
                self.stdout.write(f"- {item}")

        if options.get("json"):
            self.stdout.write(json.dumps(response, indent=2, default=str))

    @contextmanager
    def _temporary_chat_settings(self, options):
        keys = [
            "INTEL_CHAT_PROVIDER",
            "INTEL_CHAT_N8N_WEBHOOK_URL",
            "INTEL_CHAT_N8N_BEARER_TOKEN",
            "INTEL_CHAT_N8N_TIMEOUT",
        ]
        original = {key: getattr(settings, key, None) for key in keys}

        try:
            if options.get("provider_mode"):
                settings.INTEL_CHAT_PROVIDER = options["provider_mode"]
            if options.get("n8n_webhook_url"):
                settings.INTEL_CHAT_N8N_WEBHOOK_URL = options["n8n_webhook_url"]
            if options.get("n8n_bearer_token") is not None:
                settings.INTEL_CHAT_N8N_BEARER_TOKEN = options["n8n_bearer_token"]
            if options.get("n8n_timeout") is not None:
                settings.INTEL_CHAT_N8N_TIMEOUT = options["n8n_timeout"]
            yield
        finally:
            for key, value in original.items():
                setattr(settings, key, value)
