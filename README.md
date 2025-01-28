# Chirpy
Chirpy is aTwitter-esque API that allows for users to create chirps. This project was 
built as part of a boot.dev course. 

# Installation

## Requirements
- Go version <= 1.23.x
- Postgres running locally or in a container.
- [goose](https://github.com/pressly/goose) for migrations.

## Configuration
- Clone this repository
- Create a `.env` file in the project root directory.
    - Should have the following keys:
        - `DB_URL` postgres database url
        - `ENVIRONMENT` should be `dev`
        - `SECRET_KEY` key used to hash and verify passwords.
        - `POLKA_KEY` api key for a fake payment processing service.
- Create a new table in your postgres db called `chirpy` and set the owner role 
according to your db url.
- Navigate to `sql/schema` and run `goose postgres "<your db url<" up

## Run the application
- `go build && ./chirpy` or `go run .` to start the server.

# Tests
To run the tests, navigate to the root of the project and run `go test ./...`

# API Documentation

## Auth Details
Chirpy uses JWT authentication with a refresh token. If an endpoint is marked as (auth
required), that means you will need to send a header with the following format:
`Authorization: Bearer <jwt>`. In addition, users can only edit chirps that they
created and can only update themselves and not other users.

## `/api/healthz`
- `GET`: Check server health.

## `/admin/metrics`
- `GET`: Return how many times the `/app` path was accessed.

## `/admin/reset`
- `POST`: Drop all rows from all tables in the DB.

## `/api/users`
- `POST`: Create a new user.
    - Request body:
    ```json
    {"email": "example@email.com", "password": "password"}
    ```
    - Response body:
    ```json
    {
        "id": <uuid>,
        "email": <string>, 
        "created_at": <timestamp>, 
        "updated_at": <timestamp>,
        "is_chirpy_red": <bool>
    }
    ```
- `PUT` (auth required): Same as `POST`

## `/api/chirps` 
- `POST` (auth required): Create a chirp.
    - Request body:
    ```json
    {
        "body": <string>,
    }
    ```
    - Response body:
    ```json
    {
        "id": <uuid>,
        "body": <string>,
        "created_at": <timestamp>,
        "updated_at": <timestamp>,
        "user_id": <uuid>
    }
    ```
- `GET`:
    - query parameters:
        - `sort`: `asc` or `desc` by `created_at`
        - `author_id`: author id
    - Response body:
    ```json
    [
        <chirp(same as post response)>,
        ...
    ]
    ```

## `/api/chirps/<chirp id>`
- `GET`: Get a single chirp
    - Response body: Same as `/api/chirps` post response.
- `DELETE` (auth required): Delete a chirp

## `/api/login`
- `POST`: Log in and get a JWT and refresh token.
    - Request body:
    ```json
    {
        "email": <string>,
        "password": <string>
    }
    ```
    - Response body:
    ```json
    {
        "id": <uuid>,
        "email": <string>,
        "created_at": <timestamp>,
        "updated_at": <timestamp>,
        "is_chirpy_red": <bool>,
        "token": <string>,
        "refresh_token": <string>
    }
    ```

## `/api/revoke` (auth required)
- `POST`: Revoke a refresh token. Refresh token must be provided in auth header.

## `/api/refresh` (auth required)
- `POST`: Refresh a JWT. Requires refresh token in auth header.
