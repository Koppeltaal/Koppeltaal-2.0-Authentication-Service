/**
  oauth2_client_credentials.id
 */
ALTER table oauth2_client_credentials
MODIFY id CHAR(36);

UPDATE oauth2_client_credentials
SET id = LOWER(CONCAT(
    SUBSTR(id, 1, 8), '-',
    SUBSTR(id, 9, 4), '-',
    SUBSTR(id, 13, 4), '-',
    SUBSTR(id, 17, 4), '-',
    SUBSTR(id, 21)
  )) where CHAR_LENGTH(id) = 32;;

/**
 * oauth2_session.id with incoming constraint oauth2_token.session_id
 */
ALTER TABLE oauth2_token
DROP CONSTRAINT oauth2_token_ibfk_1;

ALTER table oauth2_session
MODIFY id CHAR(36);

ALTER table oauth2_token
MODIFY session_id CHAR(36);

UPDATE oauth2_session
SET id = LOWER(CONCAT(
    SUBSTR(id, 1, 8), '-',
    SUBSTR(id, 9, 4), '-',
    SUBSTR(id, 13, 4), '-',
    SUBSTR(id, 17, 4), '-',
    SUBSTR(id, 21)
  )) where CHAR_LENGTH(id) = 32;

update oauth2_token
SET session_id = LOWER(CONCAT(
    SUBSTR(session_id, 1, 8), '-',
    SUBSTR(session_id, 9, 4), '-',
    SUBSTR(session_id, 13, 4), '-',
    SUBSTR(session_id, 17, 4), '-',
    SUBSTR(session_id, 21)
  )) where CHAR_LENGTH(session_id) = 32;

ALTER TABLE oauth2_token
ADD CONSTRAINT `oauth2_token_ibfk_1` FOREIGN KEY (`session_id`) REFERENCES `oauth2_session` (`id`);

/**
 * oauth2_token.id
 */
ALTER table oauth2_token
MODIFY id CHAR(36);

UPDATE oauth2_token
SET id = LOWER(CONCAT(
    SUBSTR(id, 1, 8), '-',
    SUBSTR(id, 9, 4), '-',
    SUBSTR(id, 13, 4), '-',
    SUBSTR(id, 17, 4), '-',
    SUBSTR(id, 21)
  )) where CHAR_LENGTH(id) = 32;

