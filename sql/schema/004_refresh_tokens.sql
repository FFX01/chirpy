-- +goose Up
CREATE TABLE refresh_tokens (
    token TEXT PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    user_id UUID references users(id) ON DELETE CASCADE NOT NULL,
    expires_AT TIMESTAMP NOT NULL,
    revoked_AT TIMESTAMP
);

-- +goose Down
DROP TABLE refresh_tokens;
