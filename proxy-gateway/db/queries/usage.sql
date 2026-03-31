-- name: UpsertUsageBucket :exec
INSERT INTO usage (hour_ts, proxyset, affinity_params, upload_bytes, download_bytes)
VALUES (@hour_ts, @proxyset, @affinity_params, @upload_bytes, @download_bytes)
ON CONFLICT (hour_ts, proxyset, affinity_params)
DO UPDATE SET
    upload_bytes   = usage.upload_bytes   + EXCLUDED.upload_bytes,
    download_bytes = usage.download_bytes + EXCLUDED.download_bytes;
