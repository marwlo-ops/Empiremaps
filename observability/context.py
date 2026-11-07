"""
Correlation context linking a command to everything it triggers
"""

import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass
class CommandContext:
    trace_id: str
    command: str = ""
    command_root: str = ""
    cog: str = ""
    interaction_id: int = 0
    interaction_type: str = "application_command"
    user_id: int = 0
    user_name: str = ""
    is_owner: bool = False
    guild_id: int = 0
    guild_name: str = ""
    channel_id: int = 0
    is_dm: bool = False
    lang: str = ""
    discord_locale: str = ""
    gge_server: str = ""
    server_featured: bool = False
    params: dict = field(default_factory=dict)
    has_vote_shield: bool = False

    started_at: float = field(default_factory=time.monotonic)
    # Counters fed by the HTTP tracer
    api_calls: int = 0
    api_time_ms: int = 0
    cache_hit: bool = False
    result_rows: int = 0
    finalized: bool = False

    def elapsed_ms(self) -> int:
        return max(0, int((time.monotonic() - self.started_at) * 1000))


_trace_id: ContextVar[str] = ContextVar("gge_trace_id", default="")
_command_ctx: ContextVar[CommandContext | None] = ContextVar("gge_command_ctx", default=None)
# Background tasks (radar, scan, calendar) have no interaction to key on
_task_name: ContextVar[str] = ContextVar("gge_task_name", default="")


def new_trace_id() -> str:
    return uuid.uuid4().hex[:16]


def set_command_context(context: CommandContext) -> None:
    _trace_id.set(context.trace_id)
    _command_ctx.set(context)


def get_command_context() -> CommandContext | None:
    return _command_ctx.get()


def get_trace_id() -> str:
    return _trace_id.get()


def set_trace_id(trace_id: str) -> None:
    _trace_id.set(trace_id)


def set_task_name(name: str) -> str:
    """Name the current background task and give it a trace_id"""
    _task_name.set(name)
    trace_id = new_trace_id()
    _trace_id.set(trace_id)
    return trace_id


def get_task_name() -> str:
    return _task_name.get()


def record_api_call(duration_ms: int) -> None:
    """Increment the API counters of the command currently running"""
    context = _command_ctx.get()
    if context is not None:
        context.api_calls += 1
        context.api_time_ms += max(0, duration_ms)
