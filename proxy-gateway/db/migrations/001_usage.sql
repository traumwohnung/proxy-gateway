CREATE TABLE IF NOT EXISTS usage (
    id              BIGSERIAL   PRIMARY KEY,
    hour_ts         TIMESTAMPTZ NOT NULL,
    proxyset        TEXT        NOT NULL,
    affinity_params JSONB       NOT NULL DEFAULT '{}',
    upload_bytes    BIGINT      NOT NULL DEFAULT 0,
    download_bytes  BIGINT      NOT NULL DEFAULT 0,
    CONSTRAINT usage_bucket_unique UNIQUE (hour_ts, proxyset, affinity_params)
);
