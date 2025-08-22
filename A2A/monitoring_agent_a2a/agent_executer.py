import logging
from typing import Any, AsyncIterator, Dict, Optional

import httpx

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import (
    InternalError,
    Part,
    TaskState,
    TextPart,
    UnsupportedOperationError,
)
from a2a.utils.errors import ServerError

from utils import get_token  # reuses your existing token helper

logger = logging.getLogger(__name__)


class _OAuthTokenCache:
    """Simple in-process bearer token cache."""
    def __init__(self) -> None:
        self.token: Optional[str] = None
        self.expire_epoch: float = 0.0

    def valid(self, now_ts: float) -> bool:
        # refresh 30s before expiry
        return self.token is not None and now_ts < (self.expire_epoch - 30)

    def set(self, token: str, expires_in: int, now_ts: float) -> None:
        import time
        base = now_ts or time.time()
        self.token = token
        self.expire_epoch = base + max(1, int(expires_in))


class MonitoringAgentCoreExecutor(AgentExecutor):
    """
    A2A executor that fronts a Bedrock AgentCore Runtime (Monitoring agent)
    via an AgentCore Gateway protected by a Cognito-backed custom JWT authorizer.

    It mirrors the life-cycle behavior of your Kaitlyn executor:
    - submit/start_work
    - stream or single-shot invoke
    - update working/input_required/complete
    - attach final artifact
    """

    def __init__(
        self,
        *,
        base_url: str,
        agent_arn: str,
        agent_session_id: str,
        user_pool_id: str,
        client_id: str,
        client_secret: str,
        scope: str,
        stream: bool = True,
        request_timeout_s: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_arn = agent_arn
        self.agent_session_id = agent_session_id

        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope

        self.stream = stream
        self.http = httpx.AsyncClient(timeout=httpx.Timeout(request_timeout_s))
        self._token_cache = _OAuthTokenCache()

    async def _bearer(self) -> str:
        import time
        now_ts = time.time()
        if self._token_cache.valid(now_ts):
            return self._token_cache.token  # type: ignore

        tok = get_token(self.user_pool_id, self.client_id, self.client_secret, self.scope)
        if "access_token" not in tok:
            logger.error("Token fetch failed: %s", {k: tok.get(k) for k in ("error", "error_description")})
            raise ServerError(error=InternalError())
        self._token_cache.set(tok["access_token"], int(tok.get("expires_in", 1800)), now_ts)
        return tok["access_token"]

    async def _invoke_json(self, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        resp = await self.http.post(f"{self.base_url}/invocations", json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()

    async def _invoke_stream(self, payload: Dict[str, Any], headers: Dict[str, str]) -> AsyncIterator[Dict[str, Any]]:
        # Expects text/event-stream with lines like: "data: {json}\n\n"
        sse_headers = dict(headers)
        sse_headers["Accept"] = "text/event-stream"
        async with self.http.stream("POST", f"{self.base_url}/invocations", json=payload, headers=sse_headers) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                raw = line[len("data:"):].strip()
                try:
                    obj = httpx._models.jsonlib.loads(raw)  # uses stdlib json
                except Exception:  # malformed line, ignore
                    continue

                # Normalize to the triplet used by your Kaitlyn executor
                yield {
                    "content": obj.get("text") or obj.get("delta") or "",
                    "is_task_complete": bool(obj.get("final") or obj.get("done")),
                    "require_user_input": bool(obj.get("requires_user_input", False)),
                }

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        if not context.task_id or not context.context_id:
            raise ValueError("RequestContext must have task_id and context_id")
        if not context.message:
            raise ValueError("RequestContext must have a message")

        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        if not context.current_task:
            await updater.submit()
        await updater.start_work()

        user_text = context.get_user_input()
        payload: Dict[str, Any] = {
            "agentArn": self.agent_arn,
            "sessionId": self.agent_session_id,
            "input": {"text": user_text},
        }

        try:
            bearer = await self._bearer()
            headers = {
                "Authorization": f"Bearer {bearer}",
                # helpful for cross-system trace joins:
                "x-correlation-id": f"{context.task_id}:{context.context_id}",
                "x-a2a-context-id": context.context_id,
            }

            if self.stream:
                # Mirror streaming behavior to A2A task updates
                async for chunk in self._invoke_stream(payload, headers):
                    parts = [Part(root=TextPart(text=chunk["content"]))]
                    if not chunk["is_task_complete"] and not chunk["require_user_input"]:
                        await updater.update_status(
                            TaskState.working,
                            message=updater.new_agent_message(parts),
                        )
                    elif chunk["require_user_input"]:
                        await updater.update_status(
                            TaskState.input_required,
                            message=updater.new_agent_message(parts),
                        )
                        break
                    else:
                        await updater.add_artifact(parts, name="monitoring_result")
                        await updater.complete()
                        break
                else:
                    # Stream ended without explicit final marker
                    await updater.complete()
            else:
                # Single-shot call
                resp = await self._invoke_json(payload, headers)
                content = resp.get("text", "")
                final = bool(resp.get("final", True))
                need_input = bool(resp.get("requires_user_input", False))

                parts = [Part(root=TextPart(text=content))]
                if need_input:
                    await updater.update_status(
                        TaskState.input_required,
                        message=updater.new_agent_message(parts),
                    )
                elif final:
                    await updater.add_artifact(parts, name="monitoring_result")
                    await updater.complete()
                else:
                    await updater.update_status(
                        TaskState.working,
                        message=updater.new_agent_message(parts),
                    )

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            body_preview = e.response.text[:512]
            logger.error("AgentCore HTTP %s: %s", status, body_preview)
            if 400 <= status < 500:
                raise ServerError(error=UnsupportedOperationError()) from e
            raise ServerError(error=InternalError()) from e
        except Exception as e:
            logger.exception("MonitoringAgentCoreExecutor failed")
            raise ServerError(error=InternalError()) from e

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise ServerError(error=UnsupportedOperationError())
