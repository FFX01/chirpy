// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: chirps.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const createChirp = `-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1,
    $2
)
RETURNING id, created_at, updated_at, body, user_id
`

type CreateChirpParams struct {
	Body   string    `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

func (q *Queries) CreateChirp(ctx context.Context, arg CreateChirpParams) (Chirp, error) {
	row := q.db.QueryRowContext(ctx, createChirp, arg.Body, arg.UserID)
	var i Chirp
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Body,
		&i.UserID,
	)
	return i, err
}

const deleteChirp = `-- name: DeleteChirp :exec
DELETE FROM chirps
WHERE id = $1
`

func (q *Queries) DeleteChirp(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteChirp, id)
	return err
}

const getChirpByID = `-- name: GetChirpByID :one
SELECT
    id, created_at, updated_at, body, user_id
FROM chirps
WHERE
    id = $1
`

func (q *Queries) GetChirpByID(ctx context.Context, id uuid.UUID) (Chirp, error) {
	row := q.db.QueryRowContext(ctx, getChirpByID, id)
	var i Chirp
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Body,
		&i.UserID,
	)
	return i, err
}

const getChirps = `-- name: GetChirps :many
SELECT
    id, created_at, updated_at, body, user_id
FROM chirps
ORDER BY created_at ASC
`

func (q *Queries) GetChirps(ctx context.Context) ([]Chirp, error) {
	rows, err := q.db.QueryContext(ctx, getChirps)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Chirp
	for rows.Next() {
		var i Chirp
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Body,
			&i.UserID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getChirpsForUser = `-- name: GetChirpsForUser :many
SELECT id, created_at, updated_at, body, user_id
FROM chirps
WHERE
    user_id = $1
ORDER BY created_at ASC
`

func (q *Queries) GetChirpsForUser(ctx context.Context, userID uuid.UUID) ([]Chirp, error) {
	rows, err := q.db.QueryContext(ctx, getChirpsForUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Chirp
	for rows.Next() {
		var i Chirp
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Body,
			&i.UserID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
