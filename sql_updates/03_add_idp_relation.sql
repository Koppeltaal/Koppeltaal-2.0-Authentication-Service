ALTER TABLE oauth2_session
    ADD COLUMN identity_provider uuid,
    ADD CONSTRAINT oauth2_session_idp_1 FOREIGN KEY (identity_provider) REFERENCES identity_provider (id);
