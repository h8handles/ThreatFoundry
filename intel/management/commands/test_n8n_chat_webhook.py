from contextlib import contextmanager

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from intel.services.chatbot import (
    ChatbotServiceError,
    get_n8n_webhook_config,
    send_n8n_webhook_payload,
)


class Command(BaseCommand):
    help = "Send a minimal JSON payload to the configured n8n analyst chat webhook."

    def add_arguments(self, parser):
        parser.add_argument(
            "--webhook-url",
            type=str,
            help="Temporarily override INTEL_CHAT_N8N_WEBHOOK_URL.",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            help="Temporarily override INTEL_CHAT_N8N_TIMEOUT.",
        )
        parser.add_argument(
            "--bearer-token",
            type=str,
            help="Temporarily override INTEL_CHAT_N8N_BEARER_TOKEN.",
        )
        parser.add_argument(
            "--allow-local-n8n",
            action="store_true",
            help="Temporarily allow localhost/private n8n webhook URLs.",
        )
        parser.add_argument(
            "--show-body",
            action="store_true",
            help="Print the full response body instead of a short preview.",
        )

    def handle(self, *args, **options):
        with self._temporary_chat_settings(options):
            try:
                config = get_n8n_webhook_config()
                payload = {
                    "request_id": "connectivity-test",
                    "workflow": {
                        "name": "threatfoundry_analyst_chat",
                        "contract_version": "connectivity-test",
                    },
                    "analyst_question": "Connectivity test from ThreatFoundry.",
                    "user_query": "Connectivity test from ThreatFoundry.",
                    "summary_mode": "brief",
                    "dashboard_filters": {},
                    "context": {"filters": {}, "ioc": {}},
                    "ioc_context": {},
                }
                response = send_n8n_webhook_payload(payload, config=config)
            except ChatbotServiceError as exc:
                raise CommandError(str(exc)) from exc

        body = response.text if options.get("show_body") else _preview(response.text)
        self.stdout.write(self.style.SUCCESS("n8n webhook connectivity request completed"))
        self.stdout.write(f"url: {config.url}")
        self.stdout.write(f"method: {config.method}")
        self.stdout.write(f"webhook_mode: {config.webhook_mode}")
        self.stdout.write(f"status_code: {response.status_code}")
        self.stdout.write(f"response_body: {body}")

    @contextmanager
    def _temporary_chat_settings(self, options):
        keys = [
            "INTEL_CHAT_N8N_WEBHOOK_URL",
            "INTEL_CHAT_N8N_BEARER_TOKEN",
            "INTEL_CHAT_N8N_TIMEOUT",
            "INTEL_CHAT_N8N_ALLOW_LOCAL",
        ]
        original = {key: getattr(settings, key, None) for key in keys}

        try:
            if options.get("webhook_url"):
                settings.INTEL_CHAT_N8N_WEBHOOK_URL = options["webhook_url"]
            if options.get("bearer_token") is not None:
                settings.INTEL_CHAT_N8N_BEARER_TOKEN = options["bearer_token"]
            if options.get("timeout") is not None:
                settings.INTEL_CHAT_N8N_TIMEOUT = options["timeout"]
            if options.get("allow_local_n8n"):
                settings.INTEL_CHAT_N8N_ALLOW_LOCAL = True
            yield
        finally:
            for key, value in original.items():
                setattr(settings, key, value)


def _preview(value, limit: int = 800) -> str:
    text = str(value or "").replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > limit:
        return f"{text[:limit]}..."
    return text
