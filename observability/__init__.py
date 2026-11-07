"""
ClickHouse telemetry for the GGE Assistant Bot
Note: the database and its tables must already exist (see database/schema.sql)
"""

from .client import ch_datetime, ch_datetime64
from .config import ClickHouseSettings
from .context import (
    CommandContext,
    get_command_context,
    get_trace_id,
    new_trace_id,
    set_task_name,
    set_trace_id,
)
from .recorders import (
    complete_command,
    deny_command,
    is_active,
    record_alert,
    record_bot_status,
    record_error,
    record_guild_event,
    record_scan_run,
    record_vote,
    start_command,
    sweep_pending,
    upsert_guild,
    upsert_user,
)
from .runtime import collect_status, get_client, get_settings, setup, start, stop

__all__ = [
    "ClickHouseSettings",
    "CommandContext",
    "ch_datetime",
    "ch_datetime64",
    "collect_status",
    "complete_command",
    "deny_command",
    "get_client",
    "get_command_context",
    "get_settings",
    "get_trace_id",
    "is_active",
    "new_trace_id",
    "record_alert",
    "record_bot_status",
    "record_error",
    "record_guild_event",
    "record_scan_run",
    "record_vote",
    "set_task_name",
    "set_trace_id",
    "setup",
    "start",
    "start_command",
    "stop",
    "sweep_pending",
    "upsert_guild",
    "upsert_user",
]
