-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1,
    $2
)
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE email = $1;

-- name: GetUserByRefreshToken :one
SELECT users.*
FROM users
JOIN refresh_tokens
    ON refresh_tokens.user_id = users.id
WHERE
    refresh_tokens.token = $1
    AND refresh_tokens.revoked_at IS NULL;

-- name: UpdateUser :one
UPDATE users
SET
    email = $1,
    hashed_password = $2
WHERE
    id = $3
RETURNING *;

-- name: UpgradeUserToRed :one
UPDATE users
SET
    is_chirpy_red = true,
    updated_at = timezone('utc', now())
WHERE
    id = $1
RETURNING *;
