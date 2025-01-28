package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/FFX01/chirpy/internal/auth"
	"github.com/FFX01/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

func main() {
	godotenv.Load()
	dbUrl := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		slog.Error("Could not connect to database", "error", err)
		os.Exit(1)
	}
	queries := database.New(db)

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		panic("SECRET_KEY env var nopt available")
	}

	polkaKey := os.Getenv("POLKA_KEY")
	if polkaKey == "" {
		panic("POLKA_KEY env var not defined")
	}

	config := apiConfig{
		DB:          queries,
		Environment: os.Getenv("ENVIRONMENT"),
		SecretKey:   secretKey,
		PolkaKey:    polkaKey,
	}
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(".")))

	serverMux := http.NewServeMux()
	serverMux.Handle("/app/", config.middlewareMetricIncrement(fileServer))
	serverMux.HandleFunc("GET /api/healthz", handlerHealth)
	serverMux.HandleFunc("GET /admin/metrics", config.handlerHitCount)
	serverMux.HandleFunc("POST /admin/reset", config.handlerReset)
	serverMux.HandleFunc("POST /api/users", config.handlerCreateUser)
	serverMux.HandleFunc("POST /api/chirps", config.handlerCreateChirp)
	serverMux.HandleFunc("GET /api/chirps", config.handlerChirpsList)
	serverMux.HandleFunc("GET /api/chirps/{chirpID}", config.handlerChirpDetail)
	serverMux.HandleFunc("POST /api/login", config.handlerLogin)
	serverMux.HandleFunc("POST /api/refresh", config.handlerRefreshToken)
	serverMux.HandleFunc("POST /api/revoke", config.handlerRevokeRefreshToken)
	serverMux.HandleFunc("PUT /api/users", config.handlerUpdateUser)
	serverMux.HandleFunc("DELETE /api/chirps/{chirpID}", config.handlerDeleteChirp)
	serverMux.HandleFunc("POST /api/polka/webhooks", config.handlerUpgradeUserToRed)

	server := &http.Server{
		Addr:    ":8080",
		Handler: serverMux,
	}

	server.ListenAndServe()
}

var profanities = []string{"kerfuffle", "sharbert", "fornax"}

type ErrorSchema struct {
	Error string `json:"error"`
}

func errorResponse(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	resp := ErrorSchema{
		Error: msg,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		slog.Error("Unable to marshal error response", "error", err)
		panic("Unrecoverable state")
	}
	w.WriteHeader(status)
	w.Write(data)
	return
}

func JsonResponse(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(payload)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}
	w.WriteHeader(status)
	w.Write(data)
	return
}

func sanitizeProfanity(body string) (string, error) {
	words := strings.Split(body, " ")

	for idx, word := range words {
		if slices.Contains(profanities, strings.ToLower(word)) {
			words[idx] = "****"
		}
	}

	output := strings.Join(words, " ")
	return output, nil
}

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	Environment    string
	SecretKey      string
	PolkaKey       string
}

func (cfg *apiConfig) middlewareMetricIncrement(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerHitCount(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	html := "<html>" +
		"<body>" +
		"<h1>Welcome, Chirpy Admin</h1>" +
		"<p>Chirpy has been visited %d times!</p>" +
		"</body>" +
		"</html>"
	msg := fmt.Sprintf(html, cfg.fileserverHits.Load())
	w.Write([]byte(msg))
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	if cfg.Environment != "dev" {
		errorResponse(w, 403, "Forbidden")
		return
	}

	err := cfg.DB.DeleteAllUsers(r.Context())
	if err != nil {
		errorResponse(w, 500, err.Error())
	}

	cfg.fileserverHits.Store(0)
	w.Write([]byte("OK"))
}

func handlerHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func validateChirp(body string) (isValid bool, message string) {
	if len(body) > 140 {
		return false, "Chirp is too long"
	}
	return true, ""
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	params := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}
	if params.Password == "" {
		errorResponse(w, 400, "Password is required")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		errorResponse(w, 500, "Unable to create user")
		return
	}

	createUserParams := database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	}
	user, err := cfg.DB.CreateUser(r.Context(), createUserParams)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}

	output := struct {
		ID           uuid.UUID `json:"id"`
		Email        string    `json:"email"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
	}{
		ID:          user.ID,
		Email:       user.Email,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		IsChirpyRed: user.IsChirpyRed.Bool,
	}

	JsonResponse(w, 201, output)
}

func (cfg *apiConfig) handlerCreateChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.SecretKey)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}

	params := struct {
		Body string `json:"body"`
	}{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}

	isValid, msg := validateChirp(params.Body)
	if !isValid {
		errorResponse(w, 400, msg)
		return
	}

	sanitizedBody, err := sanitizeProfanity(params.Body)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}

	createChirpParams := database.CreateChirpParams{
		Body:   sanitizedBody,
		UserID: userID,
	}
	chirp, err := cfg.DB.CreateChirp(r.Context(), createChirpParams)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}

	JsonResponse(w, 201, chirp)
}

func (cfg *apiConfig) handlerChirpsList(w http.ResponseWriter, r *http.Request) {
	authorID := r.URL.Query().Get("author_id")
	orderBy := r.URL.Query().Get("sort")
	var chirps []database.Chirp
	var chirpsErr error
	if authorID == "" {
		chirps, chirpsErr = cfg.DB.GetChirps(r.Context())
	} else {
		authorUUID, err := uuid.Parse(authorID)
		if err != nil {
			slog.Error(err.Error())
			errorResponse(w, 400, "Malformed author_id parameter value")
			return
		}
		chirps, chirpsErr = cfg.DB.GetChirpsForUser(r.Context(), authorUUID)
	}

	if chirpsErr != nil {
		errorResponse(w, 500, chirpsErr.Error())
		return
	}

	if orderBy == "desc" {
		sort.Slice(chirps, func(i, j int) bool { return chirps[i].CreatedAt.After(chirps[j].CreatedAt) })
	}

	JsonResponse(w, 200, chirps)
}

func (cfg *apiConfig) handlerChirpDetail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		errorResponse(w, 400, "Invalid chirp id")
		return
	}

	chirp, err := cfg.DB.GetChirpByID(r.Context(), id)
	if err != nil {
		errorResponse(w, 404, "Chirp not found")
		return
	}

	JsonResponse(w, 200, chirp)
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	params := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		errorResponse(w, 500, "cannot decode request body")
		return
	}

	if params.Email == "" || params.Password == "" {
		errorResponse(w, 400, "email and password are required")
		return
	}

	user, err := cfg.DB.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}

	err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.SecretKey, time.Hour*1)
	if err != nil {
		errorResponse(w, 500, "server error")
		return
	}
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		errorResponse(w, 500, "server error")
		return
	}
	refreshTokenParams := database.CreateRefreshTokenParams{
		Token:     refreshToken,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour * 24 * 60),
		UserID:    user.ID,
	}
	dbRefreshToken, err := cfg.DB.CreateRefreshToken(r.Context(), refreshTokenParams)
	if err != nil {
		errorResponse(w, 500, "server error")
		return
	}

	output := struct {
		ID           uuid.UUID `json:"id"`
		Email        string    `json:"email"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
	}{
		ID:           user.ID,
		Email:        user.Email,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Token:        token,
		RefreshToken: dbRefreshToken.Token,
		IsChirpyRed:  user.IsChirpyRed.Bool,
	}
	JsonResponse(w, 200, output)
}

func (cfg *apiConfig) handlerRefreshToken(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}

	user, err := cfg.DB.GetUserByRefreshToken(r.Context(), token)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}

	accessToken, err := auth.MakeJWT(user.ID, cfg.SecretKey, time.Hour*1)
	if err != nil {
		errorResponse(w, 500, "server error")
		return
	}

	payload := struct {
		Token string `json:"token"`
	}{
		Token: accessToken,
	}

	JsonResponse(w, 200, payload)
}

func (cfg *apiConfig) handlerRevokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}

	_, err = cfg.DB.GetUserByRefreshToken(r.Context(), token)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}

	currentTime := time.Now().UTC()

	revokeTokenParams := database.RevokeRefreshTokenParams{
		UpdatedAt: currentTime,
		RevokedAt: sql.NullTime{Time: currentTime, Valid: true},
		Token:     token,
	}
	err = cfg.DB.RevokeRefreshToken(r.Context(), revokeTokenParams)
	if err != nil {
		errorResponse(w, 500, "server error")
		return
	}
	w.WriteHeader(204)
	w.Write([]byte(""))
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	accessToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.SecretKey)
	if err != nil {
		errorResponse(w, 401, "unauthorized")
		return
	}

	params := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)
	if err != nil {
		errorResponse(w, 400, "Invalid request body")
		return
	}

	newPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		slog.Error("Unable to hash password", "error", err.Error())
		errorResponse(w, 500, "server error")
		return
	}

	updateUserParams := database.UpdateUserParams{
		Email:          params.Email,
		HashedPassword: newPassword,
		ID:             userID,
	}
	updatedUser, err := cfg.DB.UpdateUser(r.Context(), updateUserParams)
	if err != nil {
		slog.Error("Unable to update user", "error", err.Error())
		errorResponse(w, 500, "server error")
		return
	}

	payload := struct {
		ID          uuid.UUID `json:"id"`
		Email       string    `json:"email"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}{
		ID:          updatedUser.ID,
		Email:       updatedUser.Email,
		CreatedAt:   updatedUser.CreatedAt,
		UpdatedAt:   updatedUser.UpdatedAt,
		IsChirpyRed: updatedUser.IsChirpyRed.Bool,
	}
	JsonResponse(w, 200, payload)
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		slog.Warn("Unauthorized access", "error", err.Error())
		errorResponse(w, 401, "unauthorized")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.SecretKey)
	if err != nil {
		slog.Warn("Unauthorized access", "error", err.Error())
		errorResponse(w, 401, "unauthorized")
		return
	}

	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		slog.Warn("Chirp not found", "error", err.Error())
		errorResponse(w, 404, "not found")
		return
	}

	chirp, err := cfg.DB.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		slog.Warn("Chirp not found", "error", err.Error())
		errorResponse(w, 404, "not found")
		return
	}

	if chirp.UserID != userID {
		slog.Warn("forbidden access", "chirpID", chirpID, "userID", userID)
		errorResponse(w, 403, "forbidden")
		return
	}

	err = cfg.DB.DeleteChirp(r.Context(), chirpID)
	if err != nil {
		slog.Error("Could not delete chirp", "error", err.Error())
		errorResponse(w, 500, "server error")
		return
	}

	w.WriteHeader(204)
	w.Write([]byte("deleted"))
}

func (cfg *apiConfig) handlerUpgradeUserToRed(w http.ResponseWriter, r *http.Request) {
	key, err := auth.GetAPIKey(r.Header)
	if err != nil {
		slog.Error("Polka sent missing or malformed  api key")
		errorResponse(w, 401, "unauthorized")
		return
	}
	if key != cfg.PolkaKey {
		slog.Error("Polka sent incorrect api key")
		errorResponse(w, 401, "unauthorized")
		return
	}

	params := struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)
	if err != nil {
		slog.Error(err.Error())
		errorResponse(w, 500, "server error")
		return
	}

	if params.Event != "user.upgraded" {
		JsonResponse(w, 204, "OK")
		return
	}

	_, err = cfg.DB.UpgradeUserToRed(r.Context(), params.Data.UserID)
	if err != nil {
		slog.Error("Could not upgrade user", "error", err.Error())
		errorResponse(w, 404, "not found")
		return
	}

	JsonResponse(w, 204, "")
}
