from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

import main  # noqa: E402


class WorkspaceIntentTests(unittest.TestCase):
    def assert_intent(
        self,
        text: str,
        name: str,
        query: str | None = None,
        mode: str | None = None,
    ) -> None:
        intent = main.detect_workspace_intent(text)
        self.assertIsNotNone(intent)
        assert intent is not None
        self.assertEqual(intent.name, name)
        self.assertEqual(intent.query, query)
        self.assertEqual(intent.mode, mode)

    def test_user_list_natural_language(self) -> None:
        self.assert_intent("show me suspended users", "list_users", mode="suspended")
        self.assert_intent("list admins", "list_users", mode="admins")
        self.assert_intent("show all users", "list_users", mode="all")

    def test_user_lookup_natural_language(self) -> None:
        self.assert_intent("is Adam Schembri suspended?", "lookup_user", "Adam Schembri")
        self.assert_intent(
            "does aschembri@example.com have admin access?",
            "lookup_user",
            "aschembri@example.com",
        )
        self.assert_intent("find the account for Bruce", "lookup_user", "Bruce")

    def test_group_natural_language(self) -> None:
        self.assert_intent("what groups is Adam in?", "groups_for_user", "Adam")
        self.assert_intent(
            "who are the members of testgroup@example.com?",
            "group_members",
            "testgroup@example.com",
        )
        self.assert_intent("find group IT Security", "lookup_group", "IT Security")

    def test_device_and_role_intents(self) -> None:
        self.assert_intent("list devices", "list_devices", mode="all")
        self.assert_intent("show chromebooks", "list_devices", mode="chromeos")
        self.assert_intent("find device ABC123", "lookup_devices", "ABC123")
        self.assert_intent("what devices does Adam have?", "lookup_devices", "Adam")
        self.assert_intent("list admin roles", "list_roles")
        self.assert_intent(
            "admin roles for aschembri@example.com",
            "role_assignments_for_user",
            "aschembri@example.com",
        )
        self.assert_intent(
            "what are the admin roles for Adam Schembri",
            "role_assignments_for_user",
            "Adam Schembri",
        )

    def test_expanded_readonly_tool_intents(self) -> None:
        self.assert_intent("admin scope check", "admin_scope_check")
        self.assert_intent("show meeting rooms", "list_calendar_resources")
        self.assert_intent("custom user fields", "list_user_schemas")
        self.assert_intent("show chrome printers", "list_printers")
        self.assert_intent("list data transfers", "list_data_transfers")
        self.assert_intent("data transfer apps", "list_transfer_apps")
        self.assert_intent("recent login audit", "recent_login_activity")
        self.assert_intent("workspace usage report", "customer_usage_report")
        self.assert_intent(
            "what are our current org wide 2mfa settings?",
            "list_security_policies",
        )
        self.assert_intent("show sso settings", "list_sso_settings")
        self.assert_intent("chrome versions", "chrome_versions")
        self.assert_intent("chrome extensions", "chrome_apps")
        self.assert_intent("managed chrome profiles", "chrome_profiles")
        self.assert_intent("chrome telemetry", "chrome_telemetry")
        self.assert_intent("chrome policies", "chrome_policy_schemas")

    def test_slack_user_allowlist_defaults_open(self) -> None:
        old_value = os.environ.pop("SLACK_ALLOWED_USER_IDS", None)
        try:
            self.assertTrue(main.slack_user_allowed("U123"))
        finally:
            if old_value is not None:
                os.environ["SLACK_ALLOWED_USER_IDS"] = old_value

    def test_slack_user_allowlist_blocks_unknown_users(self) -> None:
        old_value = os.environ.get("SLACK_ALLOWED_USER_IDS")
        os.environ["SLACK_ALLOWED_USER_IDS"] = "U123,U456"
        try:
            self.assertTrue(main.slack_user_allowed("U123"))
            self.assertFalse(main.slack_user_allowed("U999"))
            self.assertFalse(main.slack_user_allowed(None))
        finally:
            if old_value is None:
                os.environ.pop("SLACK_ALLOWED_USER_IDS", None)
            else:
                os.environ["SLACK_ALLOWED_USER_IDS"] = old_value

    def test_ai_payload_maps_to_workspace_intent(self) -> None:
        intent = main.workspace_intent_from_ai_payload(
            {
                "intent": "role_assignments_for_user",
                "query": "Adam Schembri",
                "mode": None,
                "confidence": 0.91,
            }
        )
        self.assertEqual(
            intent,
            main.WorkspaceIntent(
                "role_assignments_for_user",
                query="Adam Schembri",
            ),
        )

    def test_ai_payload_rejects_invalid_or_low_confidence_intents(self) -> None:
        self.assertIsNone(
            main.workspace_intent_from_ai_payload(
                {"intent": "delete_user", "query": "Adam", "confidence": 1.0}
            )
        )
        self.assertIsNone(
            main.workspace_intent_from_ai_payload(
                {"intent": "lookup_user", "query": "Adam", "confidence": 0.2}
            )
        )
        self.assertIsNone(
            main.workspace_intent_from_ai_payload(
                {"intent": "lookup_user", "query": "", "confidence": 1.0}
            )
        )

    def test_parse_json_object_accepts_fenced_json(self) -> None:
        parsed = main.parse_json_object(
            '```json\n{"intent":"list_users","mode":"suspended","confidence":0.9}\n```'
        )
        self.assertEqual(
            parsed,
            {"intent": "list_users", "mode": "suspended", "confidence": 0.9},
        )

    def test_conversation_memory_keeps_recent_turns(self) -> None:
        key = "test-memory"
        main.CONVERSATION_HISTORY.pop(key, None)
        try:
            for index in range(6):
                main.remember_conversation_turn(
                    key,
                    f"user {index}",
                    f"assistant {index}",
                )

            history = main.recent_conversation_context(key)
            self.assertNotIn("user 0", history)
            self.assertIn("User: user 2", history)
            self.assertIn("Assistant: assistant 5", history)
        finally:
            main.CONVERSATION_HISTORY.pop(key, None)

    def test_gpt_input_includes_recent_context(self) -> None:
        messages = main.build_gpt_input(
            {"user": "U123"},
            "2",
            "Assistant: Which billing option?\nUser: subscription status",
        )
        user_message = messages[-1]["content"]
        self.assertIn("Recent Slack context:", user_message)
        self.assertIn("Assistant: Which billing option?", user_message)
        self.assertIn("Message:\n2", user_message)

    def test_short_context_followup_detection(self) -> None:
        self.assertTrue(main.is_short_context_followup("2"))
        self.assertTrue(main.is_short_context_followup("#1"))
        self.assertTrue(main.is_short_context_followup("all 3"))
        self.assertTrue(main.is_short_context_followup("both"))
        self.assertTrue(main.is_short_context_followup("that one"))
        self.assertTrue(main.is_short_context_followup("subscription status"))
        self.assertFalse(main.is_short_context_followup("what groups is Adam in?"))

    def test_org_mfa_policy_question_routes_to_policy_tool(self) -> None:
        self.assert_intent(
            "what are our current org wide 2mfa settings?",
            "list_security_policies",
        )

    def test_google_workspace_scope_pack_is_read_only_only(self) -> None:
        self.assertEqual(
            len(main.GOOGLE_WORKSPACE_READONLY_SCOPES),
            len(set(main.GOOGLE_WORKSPACE_READONLY_SCOPES)),
        )

        forbidden_scopes = {
            "https://www.googleapis.com/auth/admin.directory.user",
            "https://www.googleapis.com/auth/admin.directory.user.security",
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.member",
            "https://www.googleapis.com/auth/admin.directory.orgunit",
            "https://www.googleapis.com/auth/admin.directory.rolemanagement",
            "https://www.googleapis.com/auth/apps.alerts",
            "https://www.googleapis.com/auth/apps.groups.settings",
            "https://www.googleapis.com/auth/apps.licensing",
            "https://www.googleapis.com/auth/gmail.settings.basic",
            "https://www.googleapis.com/auth/gmail.settings.sharing",
        }

        for scope in main.GOOGLE_WORKSPACE_READONLY_SCOPES:
            self.assertTrue(
                scope.endswith(".readonly") or scope.endswith(".read-only"),
                scope,
            )
            self.assertNotIn(scope, forbidden_scopes)

    def test_google_http_error_summary_extracts_message(self) -> None:
        class Response:
            status = 403
            reason = "Forbidden"

        exc = main.HttpError(
            Response(),
            b'{"error":{"message":"Caller does not have permission."}}',
        )

        summary = main.google_http_error_summary(exc)
        self.assertIn("Google API status 403", summary)
        self.assertIn("Forbidden", summary)
        self.assertIn("Caller does not have permission.", summary)


if __name__ == "__main__":
    unittest.main()
