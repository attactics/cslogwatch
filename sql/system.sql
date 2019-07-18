CREATE TABLE `system` (
	`id`	integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	`name`	varchar ( 200 ) NOT NULL UNIQUE,
	`project_id`	integer NOT NULL,
	FOREIGN KEY(`project_id`) REFERENCES `project`(`id`) DEFERRABLE INITIALLY DEFERRED
);