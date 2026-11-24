CREATE TABLE `passkey_challenges` (
	`token` text PRIMARY KEY NOT NULL,
	`purpose` text NOT NULL,
	`session` text,
	`challenge` text NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `passkeys` (
	`user_id` text NOT NULL,
	`credential_id` text PRIMARY KEY NOT NULL,
	`public_key` blob NOT NULL,
	`sign_count` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
