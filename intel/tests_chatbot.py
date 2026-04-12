import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from django.test import TestCase, override_settings
from django.urls import reverse

from intel.models import IntelIOC


class AnalystChatViewTests(TestCase):
    def setUp(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="chat-ip-1",
            value="1.2.3.4",
            value_type="ip",
            threat_type="c2",
            malware_family="AsyncRAT",
            confidence_level=95,
            first_seen=datetime(2026, 4, 11, 9, 0, tzinfo=timezone.utc),
            last_seen=datetime(2026, 4, 11, 13, 0, tzinfo=timezone.utc),
            enrichment_payloads={"virustotal": {"summary": {"analysis_score": 88}}},
        )
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="chat-domain-2",
            value="example.com",
            value_type="domain",
            threat_type="phishing",
            malware_family="ClearFake",
            confidence_level=82,
            first_seen=datetime(2026, 4, 11, 10, 0, tzinfo=timezone.utc),
            last_seen=datetime(2026, 4, 11, 16, 0, tzinfo=timezone.utc),
        )
        IntelIOC.objects.create(
            source_name="urlhaus",
            source_record_id="chat-url-3",
            value="https://cdn.bad.example/payload.zip",
            value_type="url",
            threat_type="malware_distribution",
            confidence_level=72,
            first_seen=datetime(2026, 4, 10, 14, 0, tzinfo=timezone.utc),
            last_seen=datetime(2026, 4, 10, 15, 0, tzinfo=timezone.utc),
        )

    def test_analyst_chat_page_renders(self):
        response = self.client.get(reverse("intel:analyst_chat"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intel/analyst_chat.html")
        self.assertContains(response, "IOC Analyst Chat")
        self.assertContains(response, "analyst-chat-bootstrap")

    @override_settings(INTEL_CHAT_PROVIDER="local")
    def test_analyst_chat_api_answers_specific_ioc_question(self):
        response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps(
                {
                    "prompt": "What do we know about 1.2.3.4?",
                    "summary_mode": "analyst",
                    "dashboard_filters": {},
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()["response"]
        self.assertEqual(payload["provider"], "local-database")
        self.assertTrue(payload["lookup"]["found_any"])
        self.assertIn("1.2.3.4 is present", payload["answer"])
        self.assertGreaterEqual(len(payload["supporting_records"]), 1)

    @override_settings(INTEL_CHAT_PROVIDER="local")
    def test_analyst_chat_api_answers_source_question(self):
        response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps(
                {
                    "prompt": "Which source looks most suspicious right now?",
                    "summary_mode": "technical",
                    "dashboard_filters": {},
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()["response"]
        self.assertEqual(payload["summary_mode"], "technical")
        self.assertGreaterEqual(len(payload["supporting_data"]["source_breakdown"]), 1)
        self.assertIn("Threatfox", payload["answer"])

    @override_settings(
        INTEL_CHAT_PROVIDER="hybrid",
        INTEL_CHAT_N8N_WEBHOOK_URL="https://example.test/webhook",
        INTEL_CHAT_N8N_TIMEOUT=10,
        INTEL_CHAT_N8N_BEARER_TOKEN="token-value",
    )
    @patch("intel.services.chatbot.requests.post")
    def test_analyst_chat_api_uses_n8n_response_when_available(self, mock_post):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "response": {
                "answer": "n8n analyst response",
                "key_findings": ["Finding 1"],
                "recommended_actions": ["Action 1"],
            }
        }
        mock_post.return_value = response

        api_response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps(
                {
                    "prompt": "Give me an executive summary.",
                    "summary_mode": "executive",
                    "dashboard_filters": {},
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(api_response.status_code, 200)
        payload = api_response.json()["response"]
        self.assertEqual(payload["provider"], "n8n")
        self.assertEqual(payload["answer"], "n8n analyst response")
        mock_post.assert_called_once()
