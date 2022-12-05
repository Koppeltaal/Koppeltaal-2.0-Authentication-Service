ALTER TABLE `oauth2_token`
CHANGE COLUMN `scope` `scope` TEXT NULL DEFAULT NULL;

ALTER TABLE `oauth2_token`
CHANGE COLUMN `access_token` `access_token` TEXT NULL DEFAULT NULL;

ALTER TABLE `oauth2_token`
CHANGE COLUMN `refresh_token` `refresh_token` TEXT NULL DEFAULT NULL;

ALTER TABLE `oauth2_session`
CHANGE COLUMN `scope` `scope` TEXT NULL DEFAULT NULL;

ALTER TABLE `oauth2_session`
CHANGE COLUMN `code_challenge` `code_challenge` TEXT NULL DEFAULT NULL;

ALTER TABLE `oauth2_session`
CHANGE COLUMN `state` `state` TEXT NULL DEFAULT NULL;
