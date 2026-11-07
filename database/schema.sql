CREATE DATABASE IF NOT EXISTS gge_assistant_bot;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.logs
(
    ts              DateTime64(3, 'Europe/Paris') CODEC(Delta(8), ZSTD(1)),
    level           LowCardinality(String)  DEFAULT '',
    logger_name     LowCardinality(String)  DEFAULT 'GGE_Bot',
    module          LowCardinality(String)  DEFAULT '',
    func            LowCardinality(String)  DEFAULT '',
    line            UInt32                  DEFAULT 0,
    category        LowCardinality(String)  DEFAULT '',
    message         String                  CODEC(ZSTD(3)),
    trace_id        String                  DEFAULT '',
    user_id         UInt64                  DEFAULT 0,
    guild_id        UInt64                  DEFAULT 0,
    gge_server      LowCardinality(String)  DEFAULT '',
    bot_version     LowCardinality(String)  DEFAULT '',
    instance        LowCardinality(String)  DEFAULT '',
    shard_id        UInt8                   DEFAULT 0,
    extra           Map(String, String),

    INDEX idx_trace   trace_id  TYPE bloom_filter(0.01)      GRANULARITY 4,
    INDEX idx_user    user_id   TYPE bloom_filter(0.01)      GRANULARITY 4,
    INDEX idx_message message   TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (level, category, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.command_logs
(
    ts                  DateTime64(3, 'Europe/Paris') CODEC(Delta(8), ZSTD(1)),
    trace_id            String                  DEFAULT '',
    interaction_id      UInt64                  DEFAULT 0,
    interaction_type    LowCardinality(String)  DEFAULT 'application_command',

    command             LowCardinality(String),
    command_root        LowCardinality(String)  DEFAULT '',
    cog                 LowCardinality(String)  DEFAULT '',

    user_id             UInt64                  DEFAULT 0,
    user_name           String                  DEFAULT '',
    is_owner            UInt8                   DEFAULT 0,
    guild_id            UInt64                  DEFAULT 0,
    guild_name          String                  DEFAULT '',
    channel_id          UInt64                  DEFAULT 0,
    is_dm               UInt8                   DEFAULT 0,

    lang                LowCardinality(String)  DEFAULT '',
    discord_locale      LowCardinality(String)  DEFAULT '',
    gge_server          LowCardinality(String)  DEFAULT '',
    server_featured     UInt8                   DEFAULT 0,

    params              Map(String, String),

    allowed             UInt8                   DEFAULT 1,
    deny_reason         LowCardinality(String)  DEFAULT '',
    status              LowCardinality(String)  DEFAULT 'ok',
    error_type          LowCardinality(String)  DEFAULT '',
    error_message       String                  DEFAULT '',

    deferred            UInt8                   DEFAULT 0,
    ephemeral           UInt8                   DEFAULT 0,
    duration_ms         UInt32                  DEFAULT 0,
    api_calls           UInt16                  DEFAULT 0,
    api_time_ms         UInt32                  DEFAULT 0,
    cache_hit           UInt8                   DEFAULT 0,
    result_rows         UInt32                  DEFAULT 0,

    has_vote_shield     UInt8                   DEFAULT 0,
    bot_version         LowCardinality(String)  DEFAULT '',
    instance            LowCardinality(String)  DEFAULT '',
    shard_id            UInt8                   DEFAULT 0,

    INDEX idx_user  user_id  TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_guild guild_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_trace trace_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (command, ts)
TTL toDateTime(ts) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.api_requests
(
    ts                  DateTime64(3, 'Europe/Paris') CODEC(Delta(8), ZSTD(1)),
    trace_id            String                  DEFAULT '',
    direction           LowCardinality(String)  DEFAULT 'outbound',

    service             LowCardinality(String),
    method              LowCardinality(String)  DEFAULT 'GET',
    host                LowCardinality(String)  DEFAULT '',
    endpoint            LowCardinality(String)  DEFAULT '',
    path_params         Map(String, String),
    query               Map(String, String),
    gge_server          LowCardinality(String)  DEFAULT '',

    status_code         UInt16                  DEFAULT 0,
    status_class        LowCardinality(String)  DEFAULT '',
    ok                  UInt8                   DEFAULT 0,
    duration_ms         UInt32                  DEFAULT 0,
    timeout_s           UInt16                  DEFAULT 0,
    attempt             UInt8                   DEFAULT 1,
    retries             UInt8                   DEFAULT 0,
    rate_limited        UInt8                   DEFAULT 0,
    backoff_ms          UInt32                  DEFAULT 0,
    not_modified        UInt8                   DEFAULT 0,
    etag_sent           UInt8                   DEFAULT 0,
    poll_interval_s     UInt16                  DEFAULT 0,

    request_bytes       UInt32                  DEFAULT 0,
    response_bytes      UInt32                  DEFAULT 0,
    rows_returned       UInt32                  DEFAULT 0,
    page                UInt16                  DEFAULT 0,
    total_pages         UInt16                  DEFAULT 0,

    error_class         LowCardinality(String)  DEFAULT '',
    error_message       String                  DEFAULT '',

    origin              LowCardinality(String)  DEFAULT '',
    command             LowCardinality(String)  DEFAULT '',
    cog                 LowCardinality(String)  DEFAULT '',
    task_name           LowCardinality(String)  DEFAULT '',
    user_id             UInt64                  DEFAULT 0,
    guild_id            UInt64                  DEFAULT 0,

    bot_version         LowCardinality(String)  DEFAULT '',
    instance            LowCardinality(String)  DEFAULT '',

    INDEX idx_trace  trace_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_user   user_id  TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_status status_code TYPE set(64)          GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (service, endpoint, ts)
TTL toDateTime(ts) + INTERVAL 60 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.errors
(
    ts              DateTime64(3, 'Europe/Paris') CODEC(Delta(8), ZSTD(1)),
    trace_id        String                  DEFAULT '',
    source          LowCardinality(String),
    scope           LowCardinality(String)  DEFAULT '',
    cog             LowCardinality(String)  DEFAULT '',
    module          LowCardinality(String)  DEFAULT '',
    severity        LowCardinality(String)  DEFAULT 'error',

    exc_type        LowCardinality(String)  DEFAULT '',
    exc_message     String                  DEFAULT '',
    traceback       String                  DEFAULT '' CODEC(ZSTD(3)),
    fingerprint     String                  DEFAULT '',

    user_id         UInt64                  DEFAULT 0,
    guild_id        UInt64                  DEFAULT 0,
    command         LowCardinality(String)  DEFAULT '',
    gge_server      LowCardinality(String)  DEFAULT '',
    params          Map(String, String),

    notified        UInt8                   DEFAULT 0,
    bot_version     LowCardinality(String)  DEFAULT '',
    instance        LowCardinality(String)  DEFAULT '',

    INDEX idx_fp    fingerprint TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_trace trace_id    TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (exc_type, source, ts)
TTL toDateTime(ts) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.bot_status
(
    ts                  DateTime64(3, 'Europe/Paris') CODEC(Delta(8), ZSTD(1)),
    instance            LowCardinality(String)  DEFAULT '',
    bot_version         LowCardinality(String)  DEFAULT '',
    shard_id            UInt8                   DEFAULT 0,

    state               LowCardinality(String)  DEFAULT 'online',
    maintenance         UInt8                   DEFAULT 0,
    activity            String                  DEFAULT '',
    ready               UInt8                   DEFAULT 1,

    guild_count         UInt32                  DEFAULT 0,
    user_count          UInt64                  DEFAULT 0,
    channel_count       UInt32                  DEFAULT 0,
    gateway_latency_ms  Float32                 DEFAULT 0,
    uptime_s            UInt32                  DEFAULT 0,

    cpu_pct             Float32                 DEFAULT 0,
    mem_rss_mb          Float32                 DEFAULT 0,
    event_loop_lag_ms   Float32                 DEFAULT 0,
    open_connections    UInt16                  DEFAULT 0,

    cogs_loaded         UInt8                   DEFAULT 0,
    tasks_running       Map(String, UInt8),
    cache_servers       UInt16                  DEFAULT 0,
    cache_players       UInt32                  DEFAULT 0,
    radar_players       UInt32                  DEFAULT 0,
    radar_alliances     UInt32                  DEFAULT 0,
    fortress_sessions   UInt32                  DEFAULT 0,
    active_shields      UInt32                  DEFAULT 0,
    scan_flag_active    UInt8                   DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (instance, ts)
TTL toDateTime(ts) + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.scan_runs
(
    ts_start        DateTime64(3, 'Europe/Paris') CODEC(Delta(8), ZSTD(1)),
    ts_end          DateTime64(3, 'Europe/Paris') DEFAULT toDateTime64(0, 3, 'Europe/Paris'),
    run_id          String                  DEFAULT '',
    trace_id        String                  DEFAULT '',
    kind            LowCardinality(String)  DEFAULT 'daily',
    triggered_by    UInt64                  DEFAULT 0,

    gge_server      LowCardinality(String),
    server_index    UInt16                  DEFAULT 0,
    servers_total   UInt16                  DEFAULT 0,

    status          LowCardinality(String)  DEFAULT 'success',
    duration_s      Float32                 DEFAULT 0,
    pages_total     UInt16                  DEFAULT 0,
    pages_ok        UInt16                  DEFAULT 0,
    pages_failed    UInt16                  DEFAULT 0,
    http_429        UInt16                  DEFAULT 0,
    http_errors     UInt16                  DEFAULT 0,
    backoff_total_s UInt32                  DEFAULT 0,

    players_total   UInt32                  DEFAULT 0,
    alliances_total UInt32                  DEFAULT 0,
    players_delta   Int32                   DEFAULT 0,
    output_file     String                  DEFAULT '',
    output_bytes    UInt64                  DEFAULT 0,

    error_message   String                  DEFAULT '',
    bot_version     LowCardinality(String)  DEFAULT '',
    instance        LowCardinality(String)  DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts_start)
ORDER BY (gge_server, ts_start)
TTL toDateTime(ts_start) + INTERVAL 730 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.alerts
(
    ts                  DateTime64(3, 'Europe/Paris') CODEC(Delta(8), ZSTD(1)),
    trace_id            String                  DEFAULT '',
    source              LowCardinality(String),
    alert_type          LowCardinality(String)  DEFAULT '',
    gge_server          LowCardinality(String)  DEFAULT '',

    target_type         LowCardinality(String)  DEFAULT '',
    target_id           String                  DEFAULT '',
    target_name         String                  DEFAULT '',
    changes             Map(String, String),

    channel             LowCardinality(String)  DEFAULT 'dm',
    guild_id            UInt64                  DEFAULT 0,
    recipients          UInt16                  DEFAULT 0,
    delivered           UInt16                  DEFAULT 0,
    failed              UInt16                  DEFAULT 0,
    dm_blocked          UInt16                  DEFAULT 0,

    detection_lag_ms    UInt32                  DEFAULT 0,
    poll_interval_s     UInt16                  DEFAULT 0,
    etag_hit            UInt8                   DEFAULT 0,
    error_message       String                  DEFAULT '',

    bot_version         LowCardinality(String)  DEFAULT '',
    instance            LowCardinality(String)  DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (source, alert_type, ts)
TTL toDateTime(ts) + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.guild_events
(
    ts              DateTime64(3, 'Europe/Paris') CODEC(Delta(8), ZSTD(1)),
    trace_id        String                  DEFAULT '',
    event           LowCardinality(String),

    guild_id        UInt64                  DEFAULT 0,
    guild_name      String                  DEFAULT '',
    owner_id        UInt64                  DEFAULT 0,
    member_count    UInt32                  DEFAULT 0,

    user_id         UInt64                  DEFAULT 0,
    actor_id        UInt64                  DEFAULT 0,
    target          String                  DEFAULT '',
    old_value       String                  DEFAULT '',
    new_value       String                  DEFAULT '',
    reason          String                  DEFAULT '',

    lang            LowCardinality(String)  DEFAULT '',
    gge_server      LowCardinality(String)  DEFAULT '',
    guild_total     UInt32                  DEFAULT 0,
    bot_version     LowCardinality(String)  DEFAULT '',
    instance        LowCardinality(String)  DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (event, ts)
TTL toDateTime(ts) + INTERVAL 730 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.votes
(
    ts                  DateTime64(3, 'Europe/Paris') CODEC(Delta(8), ZSTD(1)),
    trace_id            String                  DEFAULT '',
    source              LowCardinality(String)  DEFAULT 'webhook',
    event_type          LowCardinality(String)  DEFAULT 'upvote',
    user_id             UInt64                  DEFAULT 0,

    accepted            UInt8                   DEFAULT 1,
    reject_reason       LowCardinality(String)  DEFAULT '',
    signature_version   LowCardinality(String)  DEFAULT '',
    is_weekend          UInt8                   DEFAULT 0,
    shield_until        DateTime('Europe/Paris') DEFAULT toDateTime(0, 'Europe/Paris'),
    dm_sent             UInt8                   DEFAULT 0,
    lang                LowCardinality(String)  DEFAULT '',
    total_active_shields UInt32                 DEFAULT 0,

    bot_version         LowCardinality(String)  DEFAULT '',
    instance            LowCardinality(String)  DEFAULT '',

    INDEX idx_user user_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, user_id)
TTL toDateTime(ts) + INTERVAL 730 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.dim_users
(
    user_id         UInt64,
    user_name       String                  DEFAULT '',
    lang            LowCardinality(String)  DEFAULT '',
    gge_server      LowCardinality(String)  DEFAULT '',
    gge_player_name String                  DEFAULT '',
    gge_player_id   UInt64                  DEFAULT 0,
    first_seen      DateTime('Europe/Paris') DEFAULT now(),
    last_seen       DateTime('Europe/Paris') DEFAULT now(),
    commands_total  UInt64                  DEFAULT 0,
    is_blocked      UInt8                   DEFAULT 0,
    block_reason    String                  DEFAULT '',
    shield_until    DateTime('Europe/Paris') DEFAULT toDateTime(0, 'Europe/Paris'),
    updated_at      DateTime64(3, 'Europe/Paris') DEFAULT now64(3, 'Europe/Paris'),
    deleted         UInt8                   DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at, deleted)
ORDER BY user_id
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.dim_guilds
(
    guild_id        UInt64,
    guild_name      String                  DEFAULT '',
    owner_id        UInt64                  DEFAULT 0,
    member_count    UInt32                  DEFAULT 0,
    lang            LowCardinality(String)  DEFAULT '',
    gge_server      LowCardinality(String)  DEFAULT '',
    calendar_channel_id UInt64              DEFAULT 0,
    tracked_alliances Array(String),
    joined_at       DateTime('Europe/Paris') DEFAULT now(),
    left_at         DateTime('Europe/Paris') DEFAULT toDateTime(0, 'Europe/Paris'),
    is_active       UInt8                   DEFAULT 1,
    updated_at      DateTime64(3, 'Europe/Paris') DEFAULT now64(3, 'Europe/Paris'),
    deleted         UInt8                   DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at, deleted)
ORDER BY guild_id
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.command_stats_daily
(
    date            Date,
    command         LowCardinality(String),
    gge_server      LowCardinality(String),
    lang            LowCardinality(String),
    calls           SimpleAggregateFunction(sum, UInt64),
    errors          SimpleAggregateFunction(sum, UInt64),
    denied          SimpleAggregateFunction(sum, UInt64),
    users           AggregateFunction(uniq, UInt64),
    guilds          AggregateFunction(uniq, UInt64),
    duration_avg    AggregateFunction(avg, UInt32),
    duration_q      AggregateFunction(quantiles(0.5, 0.9, 0.99), UInt32)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(date)
ORDER BY (date, command, gge_server, lang)
TTL date + INTERVAL 3 YEAR DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS gge_assistant_bot.command_stats_daily_mv
TO gge_assistant_bot.command_stats_daily AS
SELECT
    toDate(ts)                                  AS date,
    command,
    gge_server,
    lang,
    count()                                     AS calls,
    countIf(status = 'error')                   AS errors,
    countIf(status = 'denied')                  AS denied,
    uniqState(user_id)                          AS users,
    uniqState(guild_id)                         AS guilds,
    avgState(duration_ms)                       AS duration_avg,
    quantilesState(0.5, 0.9, 0.99)(duration_ms) AS duration_q
FROM gge_assistant_bot.command_logs
GROUP BY date, command, gge_server, lang;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.api_stats_5m
(
    bucket          DateTime('Europe/Paris'),
    service         LowCardinality(String),
    endpoint        LowCardinality(String),
    method          LowCardinality(String),
    gge_server      LowCardinality(String),
    requests        SimpleAggregateFunction(sum, UInt64),
    ok_2xx          SimpleAggregateFunction(sum, UInt64),
    not_modified    SimpleAggregateFunction(sum, UInt64),
    client_4xx      SimpleAggregateFunction(sum, UInt64),
    server_5xx      SimpleAggregateFunction(sum, UInt64),
    rate_limited    SimpleAggregateFunction(sum, UInt64),
    network_errors  SimpleAggregateFunction(sum, UInt64),
    retries         SimpleAggregateFunction(sum, UInt64),
    bytes_in        SimpleAggregateFunction(sum, UInt64),
    duration_avg    AggregateFunction(avg, UInt32),
    duration_q      AggregateFunction(quantiles(0.5, 0.9, 0.99), UInt32),
    duration_max    SimpleAggregateFunction(max, UInt32)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, service, endpoint, method, gge_server)
TTL bucket + INTERVAL 3 YEAR DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS gge_assistant_bot.api_stats_5m_mv
TO gge_assistant_bot.api_stats_5m AS
SELECT
    toStartOfFiveMinute(ts)                     AS bucket,
    service,
    endpoint,
    method,
    gge_server,
    count()                                     AS requests,
    countIf(status_code BETWEEN 200 AND 299)    AS ok_2xx,
    countIf(status_code = 304)                  AS not_modified,
    countIf(status_code BETWEEN 400 AND 499)    AS client_4xx,
    countIf(status_code >= 500)                 AS server_5xx,
    countIf(status_code = 429)                  AS rate_limited,
    countIf(status_code = 0)                    AS network_errors,
    sum(retries)                                AS retries,
    sum(response_bytes)                         AS bytes_in,
    avgState(duration_ms)                       AS duration_avg,
    quantilesState(0.5, 0.9, 0.99)(duration_ms) AS duration_q,
    max(duration_ms)                            AS duration_max
FROM gge_assistant_bot.api_requests
GROUP BY bucket, service, endpoint, method, gge_server;

CREATE TABLE IF NOT EXISTS gge_assistant_bot.errors_daily
(
    date            Date,
    source          LowCardinality(String),
    scope           LowCardinality(String),
    exc_type        LowCardinality(String),
    fingerprint     String,
    occurrences     SimpleAggregateFunction(sum, UInt64),
    users           AggregateFunction(uniq, UInt64),
    guilds          AggregateFunction(uniq, UInt64),
    first_seen      SimpleAggregateFunction(min, DateTime64(3, 'Europe/Paris')),
    last_seen       SimpleAggregateFunction(max, DateTime64(3, 'Europe/Paris')),
    sample_message  SimpleAggregateFunction(any, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(date)
ORDER BY (date, fingerprint, exc_type, source, scope)
TTL date + INTERVAL 3 YEAR DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS gge_assistant_bot.errors_daily_mv
TO gge_assistant_bot.errors_daily AS
SELECT
    toDate(ts)          AS date,
    source,
    scope,
    exc_type,
    fingerprint,
    count()             AS occurrences,
    uniqState(user_id)  AS users,
    uniqState(guild_id) AS guilds,
    min(ts)             AS first_seen,
    max(ts)             AS last_seen,
    any(exc_message)    AS sample_message
FROM gge_assistant_bot.errors
GROUP BY date, source, scope, exc_type, fingerprint;

CREATE OR REPLACE VIEW gge_assistant_bot.v_commands_daily AS
SELECT
    date,
    command,
    gge_server,
    lang,
    sum(calls)                          AS calls,
    sum(errors)                         AS errors,
    sum(denied)                         AS denied,
    round(100 * errors / greatest(calls, 1), 2) AS error_pct,
    uniqMerge(users)                    AS unique_users,
    uniqMerge(guilds)                   AS unique_guilds,
    round(avgMerge(duration_avg))       AS avg_ms,
    quantilesMerge(0.5, 0.9, 0.99)(duration_q) AS p50_p90_p99_ms
FROM gge_assistant_bot.command_stats_daily
GROUP BY date, command, gge_server, lang;

CREATE OR REPLACE VIEW gge_assistant_bot.v_api_health AS
SELECT
    bucket,
    service,
    endpoint,
    sum(requests)                       AS requests,
    sum(ok_2xx)                         AS ok,
    sum(not_modified)                   AS cached_304,
    sum(client_4xx)                     AS errors_4xx,
    sum(server_5xx)                     AS errors_5xx,
    sum(rate_limited)                   AS http_429,
    sum(network_errors)                 AS network_errors,
    round(100 * (errors_4xx + errors_5xx + network_errors) / greatest(requests, 1), 2) AS failure_pct,
    round(avgMerge(duration_avg))       AS avg_ms,
    quantilesMerge(0.5, 0.9, 0.99)(duration_q) AS p50_p90_p99_ms
FROM gge_assistant_bot.api_stats_5m
GROUP BY bucket, service, endpoint;

CREATE OR REPLACE VIEW gge_assistant_bot.v_top_errors AS
SELECT
    fingerprint,
    any(exc_type)       AS exc_type,
    any(source)         AS source,
    any(scope)          AS scope,
    sum(occurrences)    AS occurrences,
    uniqMerge(users)    AS affected_users,
    min(first_seen)     AS first_seen,
    max(last_seen)      AS last_seen,
    any(sample_message) AS sample_message
FROM gge_assistant_bot.errors_daily
WHERE date >= today() - 30
GROUP BY fingerprint
ORDER BY occurrences DESC;

CREATE OR REPLACE VIEW gge_assistant_bot.v_scan_health AS
SELECT
    toDate(ts_start)    AS date,
    gge_server,
    argMax(status, ts_start)        AS last_status,
    max(ts_start)                   AS last_run,
    round(avg(duration_s), 1)       AS avg_duration_s,
    max(players_total)              AS players,
    sum(http_429)                   AS http_429,
    sum(pages_failed)               AS pages_failed
FROM gge_assistant_bot.scan_runs
GROUP BY date, gge_server;

CREATE OR REPLACE VIEW gge_assistant_bot.v_users_current AS
SELECT * FROM gge_assistant_bot.dim_users FINAL WHERE deleted = 0;

CREATE OR REPLACE VIEW gge_assistant_bot.v_guilds_current AS
SELECT * FROM gge_assistant_bot.dim_guilds FINAL WHERE deleted = 0;