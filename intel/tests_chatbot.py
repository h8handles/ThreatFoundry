import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse

from intel.access import ANALYST_GROUP
from intel.models import IntelIOC
from intel.services.chatbot import ChatbotServiceError, build_chat_response, build_response_guidance, get_n8n_webhook_config


class AnalystChatViewTests(TestCase):
    def setUp(self):
        analyst_group = Group.objects.get(name=ANALYST_GROUP)
        user_model = get_user_model()
        self.analyst_user = user_model.objects.create_user(
            username="chat-analyst",
            password="test-pass-123",
        )
        self.analyst_user.groups.add(analyst_group)
        self.client.force_login(self.analyst_user)

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
        self.assertContains(response, "Analyst Assistant")
        self.assertContains(response, "analyst-chat-bootstrap")
        self.assertContains(response, 'id="assistant-popout-button"')

    def test_analyst_chat_bootstrap_preserves_dashboard_filter_scope(self):
        response = self.client.get(f"{reverse('intel:analyst_chat')}?malware_family=Cobalt+Strike")

        self.assertEqual(response.status_code, 200)
        bootstrap = response.context["chat_bootstrap"]
        self.assertEqual(bootstrap["filters"]["malware_family"], "Cobalt Strike")
        self.assertIn("malware_family=Cobalt+Strike", bootstrap["popout_url"])
        self.assertContains(response, "Malware: Cobalt Strike")

    def test_analyst_chat_popout_page_reuses_chat_template(self):
        response = self.client.get(f"{reverse('intel:analyst_chat')}?popout=1")

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intel/analyst_chat.html")
        self.assertContains(response, "analyst-chat-bootstrap")
        self.assertContains(response, "assistant-workspace-popout")
        self.assertContains(response, "Open Full Assistant")
        self.assertNotContains(response, 'id="assistant-popout-button"')

    @override_settings(INTEL_CHAT_PROVIDER="local")
    def test_analyst_chat_response_respects_malware_family_filter_scope(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="chat-cobalt-1",
            value="cobalt.example",
            value_type="domain",
            threat_type="c2",
            malware_family="Cobalt Strike",
            confidence_level=90,
        )

        response = build_chat_response(
            user_prompt="Give me the analyst view and leadership summary of the current scope.",
            summary_mode="analyst",
            filters_payload={"malware_family": "Cobalt Strike"},
        )

        self.assertEqual(response["provider"], "local-database")
        self.assertEqual(response["context_meta"]["total_iocs"], 1)
        self.assertEqual(response["supporting_data"]["cluster_breakdown"], [{"cluster": "Cobalt Strike", "count": 1}])
        self.assertEqual(response["supporting_data"]["source_breakdown"][0]["count"], 1)

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
        INTEL_ALLOWED_WEBHOOK_HOSTS=["example.test"],
    )
    @patch("intel.services.chatbot.log.info")
    @patch("intel.services.chatbot.requests.post")
    def test_analyst_chat_api_uses_n8n_response_when_available(self, mock_post, mock_log_info):
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
                    "conversation_context": [{"role": "user", "content": "Focus on current dashboard scope."}],
                    "chat_turn": 2,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(api_response.status_code, 200)
        payload = api_response.json()["response"]
        self.assertEqual(payload["provider"], "n8n")
        self.assertEqual(payload["answer"], "n8n analyst response")
        self.assertEqual(payload["supporting_records"], [])
        sent_payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(sent_payload["workflow"]["name"], "threatfoundry_analyst_chat")
        self.assertEqual(sent_payload["analyst_question"], "Give me an executive summary.")
        self.assertEqual(sent_payload["latest_user_question"], "Give me an executive summary.")
        self.assertEqual(sent_payload["conversation_context"][0]["content"], "Focus on current dashboard scope.")
        self.assertEqual(sent_payload["conversation_meta"]["turn_sequence"], 2)
        self.assertTrue(sent_payload["conversation_meta"]["history_included"])
        self.assertIn("response_guidance", sent_payload)
        self.assertIn("summary", sent_payload["response_guidance"]["intents"])
        self.assertEqual(sent_payload["response_guidance"]["depth"], "full_when_useful")
        self.assertIn("context", sent_payload)
        self.assertIn("ioc", sent_payload["context"])
        self.assertIn("focused_records", sent_payload["context"]["ioc"])
        self.assertEqual(mock_post.call_args.kwargs["timeout"], 10)
        self.assertEqual(mock_post.call_args.kwargs["headers"]["Authorization"], "Bearer token-value")
        log_messages = [call.args[0] for call in mock_log_info.call_args_list]
        self.assertTrue(any("webhook request" in message for message in log_messages))
        self.assertTrue(any("webhook response" in message for message in log_messages))
        mock_post.assert_called_once()

    @override_settings(
        INTEL_CHAT_N8N_WEBHOOK_URL="https://example.test/webhook-test/threatfoundry-analyst-chat",
        INTEL_CHAT_N8N_TIMEOUT=7,
        INTEL_ALLOWED_WEBHOOK_HOSTS=["example.test"],
    )
    def test_n8n_webhook_config_identifies_test_webhook(self):
        config = get_n8n_webhook_config()

        self.assertEqual(config.method, "POST")
        self.assertEqual(config.timeout, 7)
        self.assertEqual(config.webhook_mode, "test")

    @override_settings(
        INTEL_CHAT_N8N_WEBHOOK_URL="https://<your-workspace>.app.n8n.cloud/webhook/soc-analyst-bot",
        INTEL_CHAT_N8N_TIMEOUT=10,
    )
    def test_n8n_webhook_config_rejects_placeholder_url(self):
        with self.assertRaisesMessage(ChatbotServiceError, "placeholder"):
            get_n8n_webhook_config()

    @override_settings(
        INTEL_CHAT_PROVIDER="n8n",
        INTEL_CHAT_N8N_WEBHOOK_URL="https://example.test/webhook/threatfoundry-analyst-chat",
        INTEL_ALLOWED_WEBHOOK_HOSTS=["example.test"],
    )
    @patch("intel.services.chatbot.requests.post")
    def test_follow_up_chat_message_triggers_fresh_n8n_request(self, mock_post):
        first_response = Mock()
        first_response.raise_for_status.return_value = None
        first_response.json.return_value = {"answer": "first n8n response"}
        second_response = Mock()
        second_response.raise_for_status.return_value = None
        second_response.json.return_value = {"answer": "follow-up n8n response"}
        mock_post.side_effect = [first_response, second_response]

        first_api_response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps(
                {
                    "prompt": "Give me the analyst view.",
                    "summary_mode": "analyst",
                    "dashboard_filters": {},
                    "chat_turn": 1,
                }
            ),
            content_type="application/json",
        )
        second_api_response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps(
                {
                    "prompt": "What should I investigate next?",
                    "summary_mode": "analyst",
                    "dashboard_filters": {},
                    "conversation_context": [
                        {"role": "user", "content": "Give me the analyst view."},
                        {"role": "assistant", "content": first_api_response.json()["response"]["answer"]},
                    ],
                    "chat_turn": 2,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(first_api_response.status_code, 200)
        self.assertEqual(second_api_response.status_code, 200)
        self.assertEqual(mock_post.call_count, 2)
        second_payload = mock_post.call_args_list[1].kwargs["json"]
        self.assertEqual(second_payload["analyst_question"], "What should I investigate next?")
        self.assertEqual(second_payload["conversation_meta"]["turn_sequence"], 2)
        self.assertEqual(len(second_payload["conversation_context"]), 2)

    @override_settings(
        INTEL_CHAT_PROVIDER="hybrid",
        INTEL_CHAT_N8N_WEBHOOK_URL="http://127.0.0.1:5678/webhook/threatfoundry-analyst-chat",
        INTEL_CHAT_N8N_ALLOW_LOCAL=True,
    )
    @patch("intel.services.chatbot.requests.post")
    def test_analyst_chat_allows_local_n8n_webhook(self, mock_post):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = [{"json": {"answer": "local n8n response", "confidence": "medium"}}]
        mock_post.return_value = response

        api_response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps(
                {
                    "prompt": "What should I hunt next?",
                    "summary_mode": "auto",
                    "dashboard_filters": {},
                    "conversation_context": [{"role": "user", "content": "Focus on AsyncRAT"}],
                    "chat_turn": 2,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(api_response.status_code, 200)
        payload = api_response.json()["response"]
        self.assertEqual(payload["answer"], "local n8n response")
        self.assertEqual(payload["confidence"], "medium")
        sent_payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(sent_payload["conversation_context"][0]["content"], "Focus on AsyncRAT")
        self.assertEqual(sent_payload["conversation_meta"]["turn_sequence"], 2)

    def test_response_guidance_allows_fuller_non_brief_answers(self):
        guidance = build_response_guidance({"intents": ["summary", "prioritization"]}, "analyst")

        self.assertFalse(guidance["allow_sparse_optional_fields"])
        self.assertEqual(guidance["depth"], "full_when_useful")
        self.assertTrue(any("complete analyst answer" in item for item in guidance["instructions"]))

    @override_settings(INTEL_CHAT_PROVIDER="local")
    def test_analyst_chat_local_answer_handles_open_hunt_question(self):
        response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps(
                {
                    "prompt": "Build me a hunting hypothesis from this scope and explain what uncertainty remains.",
                    "summary_mode": "auto",
                    "dashboard_filters": {},
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()["response"]
        self.assertEqual(payload["provider"], "local-database")
        self.assertIn(payload["confidence"], {"medium-high", "medium", "low-medium"})
        self.assertTrue(payload["reasoning_summary"])
        self.assertGreaterEqual(len(payload["recommended_actions"]), 1)

    @override_settings(INTEL_CHAT_PROVIDER="local")
    def test_analyst_chat_summary_question_does_not_force_supporting_records(self):
        response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps(
                {
                    "prompt": "Summarize the current scope for me.",
                    "summary_mode": "auto",
                    "dashboard_filters": {},
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()["response"]
        self.assertEqual(payload["summary_mode"], "analyst")
        self.assertEqual(payload["supporting_records"], [])
        self.assertIn("summary", payload["answer"].lower())
