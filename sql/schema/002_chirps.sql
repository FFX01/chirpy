-- +goose Up
CREATE TABLE chirps (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    body TEXT NOT NULL,
    user_id UUID references users(id) ON DELETE CASCADE NOT NULL
);

-- +goose Down
DROP TABLE chirps;
