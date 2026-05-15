CREATE TABLE `usage` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`ts` integer NOT NULL,
	`proxyset` text NOT NULL,
	`session_params` text DEFAULT '{}' NOT NULL,
	`session_duration_minutes` integer DEFAULT 0 NOT NULL,
	`upload_bytes` integer DEFAULT 0 NOT NULL,
	`download_bytes` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE INDEX `usage_ts_idx` ON `usage` (`ts`);--> statement-breakpoint
CREATE INDEX `usage_proxyset_ts_idx` ON `usage` (`proxyset`,`ts`);