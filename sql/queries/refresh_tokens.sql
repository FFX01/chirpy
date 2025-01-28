-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
)
RETURNING *;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET
    updated_at = $1,
    revoked_at = $2
WHERE
    refresh_tokens.token = $3;
