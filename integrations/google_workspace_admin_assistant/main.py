from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from functools import lru_cache
from typing import Any

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


ADMIN_DIRECTORY_USER_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/admin.directory.user.readonly"
)
REQUEST_TOLERANCE_SECONDS = 60 * 5
SLACK_POST_MESSAGE_URL = "https://slack.com/api/chat.postMessage"
TRUE_VALUES = {"1", "true", "yes", "on"}

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("google_workspace_admin_assistant")

app = FastAPI()


def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


async def verified_slack_body(
    request: Request,
    timestamp: str | None,
    signature: str | None,
) -> bytes:
    body = await request.body()
    signing_secret = os.getenv("SLACK_SIGNING_SECRET", "")

    if not signing_secret:
        if env_flag("ALLOW_UNVERIFIED_SLACK_REQUESTS"):
            logger.warning("Slack signature verification is disabled.")
            return body
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SLACK_SIGNING_SECRET is not configured.",
        )

    if not timestamp or not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Slack signature headers.",
        )

    try:
        request_time = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Slack timestamp header.",
        ) from exc

    if abs(time.time() - request_time) > REQUEST_TOLERANCE_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Stale Slack request.",
        )

    base_string = f"v0:{timestamp}:".encode("utf-8") + body
    expected_signature = "v0=" + hmac.new(
        signing_secret.encode("utf-8"),
        base_string,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Slack signature.",
        )

    return body


def decode_json_payload(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload.",
        ) from exc

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Expected a JSON object payload.",
        )

    return payload


def should_reply_to_event(event: dict[str, Any]) -> bool:
    if event.get("bot_id") or event.get("subtype") == "bot_message":
        return False
    return event.get("type") in {"message", "app_mention"}


def is_admin_test_message(text: str) -> bool:
    return "admin test" in text.lower()


def reply_thread_ts(event: dict[str, Any]) -> str | None:
    thread_ts = event.get("thread_ts")
    if isinstance(thread_ts, str):
        return thread_ts

    if event.get("channel_type") == "im":
        return None

    ts = event.get("ts")
    return ts if isinstance(ts, str) else None


def build_test_reply(event: dict[str, Any]) -> str:
    user_id = event.get("user")
    greeting = f"<@{user_id}> " if isinstance(user_id, str) else ""
    return (
        f"{greeting}I can hear you. Slack -> Cloud Run is working, and GPT "
        "plus Google Workspace lookups are the next pieces to wire in."
    )


@lru_cache(maxsize=1)
def workspace_directory_service():
    start = time.perf_counter()
    admin_email = os.getenv("GOOGLE_WORKSPACE_ADMIN_EMAIL", "").strip()
    service_account_json = os.getenv(
        "GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON",
        "",
    ).strip()

    if not admin_email:
        raise RuntimeError("GOOGLE_WORKSPACE_ADMIN_EMAIL is not configured.")

    if not service_account_json:
        raise RuntimeError("GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON is not configured.")

    try:
        service_account_info = json.loads(service_account_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON is not valid JSON."
        ) from exc

    credentials = service_account.Credentials.from_service_account_info(
        service_account_info,
        scopes=[ADMIN_DIRECTORY_USER_READONLY_SCOPE],
    ).with_subject(admin_email)

    directory = build(
        "admin",
        "directory_v1",
        credentials=credentials,
        cache_discovery=False,
    )
    logger.info(
        "Workspace Directory client built in %.0f ms",
        (time.perf_counter() - start) * 1000,
    )
    return directory


def fetch_workspace_user_sample(max_results: int = 5) -> list[dict[str, Any]]:
    start = time.perf_counter()
    directory = workspace_directory_service()
    client_ready_ms = (time.perf_counter() - start) * 1000

    request_start = time.perf_counter()
    response = (
        directory.users()
        .list(
            customer="my_customer",
            maxResults=max_results,
            orderBy="email",
        )
        .execute()
    )
    request_ms = (time.perf_counter() - request_start) * 1000
    users = response.get("users", [])
    user_list = users if isinstance(users, list) else []

    logger.info(
        "Workspace users.list completed in %.0f ms; client ready in %.0f ms; users=%s",
        request_ms,
        client_ready_ms,
        len(user_list),
    )
    return user_list


def build_admin_test_reply() -> str:
    users = fetch_workspace_user_sample()

    if not users:
        return "Google Workspace Admin SDK is connected, but I did not find any users."

    lines = [
        "Google Workspace Admin SDK is connected. I can list users.",
        f"Sample users returned: {len(users)}",
    ]

    for user in users:
        if not isinstance(user, dict):
            continue

        primary_email = user.get("primaryEmail", "unknown email")
        name = user.get("name", {})
        full_name = name.get("fullName") if isinstance(name, dict) else None
        label = f"{primary_email} ({full_name})" if full_name else str(primary_email)
        lines.append(f"- {label}")

    return "\n".join(lines)


async def build_admin_test_reply_safely() -> str:
    start = time.perf_counter()
    try:
        return await asyncio.to_thread(build_admin_test_reply)
    except HttpError:
        logger.exception("Google Workspace Admin SDK request failed.")
        return (
            "I reached the Google Workspace Admin SDK path, but the API call "
            "failed. Check the delegated scope, admin email, and Cloud Run logs."
        )
    except Exception:
        logger.exception("Google Workspace Admin SDK setup failed.")
        return (
            "I tried the Google Workspace Admin SDK smoke test, but the setup "
            "is not quite right yet. Check the service account secret and "
            "admin email environment variable."
        )
    finally:
        logger.info(
            "Admin test reply built in %.0f ms",
            (time.perf_counter() - start) * 1000,
        )


async def post_slack_message(
    channel: str,
    text: str,
    thread_ts: str | None = None,
) -> None:
    start = time.perf_counter()
    bot_token = os.getenv("SLACK_BOT_TOKEN", "")

    if not bot_token:
        logger.error("SLACK_BOT_TOKEN is not configured.")
        return

    payload: dict[str, str] = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts

    headers = {
        "Authorization": f"Bearer {bot_token}",
        "Content-Type": "application/json; charset=utf-8",
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            SLACK_POST_MESSAGE_URL,
            headers=headers,
            json=payload,
        )

    try:
        response_payload = response.json()
    except json.JSONDecodeError:
        logger.error(
            "Slack API returned non-JSON response: status=%s body=%s",
            response.status_code,
            response.text,
        )
        return

    if not response_payload.get("ok"):
        logger.error("Slack API error: %s", response_payload)
    else:
        logger.info(
            "Slack message posted in %.0f ms",
            (time.perf_counter() - start) * 1000,
        )


async def handle_slack_event_reply(event: dict[str, Any]) -> None:
    start = time.perf_counter()
    channel = event.get("channel")
    if not isinstance(channel, str):
        logger.warning("Slack event is missing a channel: %s", event)
        return

    text = event.get("text", "")
    thread_ts = reply_thread_ts(event)

    if isinstance(text, str) and is_admin_test_message(text):
        lookup_task = asyncio.create_task(build_admin_test_reply_safely())

        await post_slack_message(
            channel,
            "Checking Google Workspace Admin SDK access...",
            thread_ts,
        )

        reply = await lookup_task
        await post_slack_message(channel, reply, thread_ts)
        logger.info(
            "Admin test Slack flow completed in %.0f ms",
            (time.perf_counter() - start) * 1000,
        )
        return

    await post_slack_message(channel, build_test_reply(event), thread_ts)


@app.get("/")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/slack/events")
async def slack_events(
    request: Request,
    background_tasks: BackgroundTasks,
    x_slack_request_timestamp: str | None = Header(default=None),
    x_slack_signature: str | None = Header(default=None),
    x_slack_retry_num: str | None = Header(default=None),
) -> Response:
    body = await verified_slack_body(
        request,
        timestamp=x_slack_request_timestamp,
        signature=x_slack_signature,
    )

    if x_slack_retry_num:
        return JSONResponse({"ok": True})

    payload = decode_json_payload(body)

    if payload.get("type") == "url_verification":
        challenge = payload.get("challenge")
        if not isinstance(challenge, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing Slack challenge.",
            )
        return PlainTextResponse(challenge)

    if payload.get("type") == "event_callback":
        event = payload.get("event") or {}
        if not isinstance(event, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Slack event payload.",
            )

        logger.info(
            "Slack event received: event_id=%s team_id=%s event_type=%s user=%s",
            payload.get("event_id"),
            payload.get("team_id"),
            event.get("type"),
            event.get("user"),
        )

        if should_reply_to_event(event):
            background_tasks.add_task(handle_slack_event_reply, event)

    return JSONResponse({"ok": True})
