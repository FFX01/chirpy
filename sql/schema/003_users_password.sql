-- +goose Up
ALTER TABLE users
ADD hashed_password TEXT NOT NULL DEFAULT 'unset'; -- This is a terrible idea, but it's what the course says to do for now.

-- +goose Down
ALTER TABLE users
DROP COLUMN hashed_password;
