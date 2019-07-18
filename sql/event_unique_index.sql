CREATE UNIQUE INDEX `event_timestamp_eventType_content_computer_ipAddress_pid_username_uniq` ON `event` (
	`timestamp`,
	`eventType`,
	`content`,
	`computer`,
	`ipAddress`,
	`pid`,
	`username`
);