CREATE TABLE `event` (
	`id`	integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	`timestamp`	datetime NOT NULL,
	`eventType`	varchar ( 100 ) NOT NULL,
	`content`	text NOT NULL,
	`computer`	varchar ( 200 ) NOT NULL,
	`ipAddress`	varchar ( 50 ) NOT NULL,
	`pid`	varchar ( 10 ) NOT NULL,
	`username`	varchar ( 100 ) NOT NULL,
	`project_id`	integer NOT NULL,
	FOREIGN KEY(`project_id`) REFERENCES `main_project`(`id`) DEFERRABLE INITIALLY DEFERRED
);