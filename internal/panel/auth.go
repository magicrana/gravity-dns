package panel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	AdminContextKey contextKey = "admin_user"
	CookieTokenName            = "gravity_token"
)

type AdminClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateJWT creates a signed JWT for the admin user.
func GenerateJWT(secret, username string, ttlHours int) (string, error) {
	if ttlHours <= 0 {
		ttlHours = 24
	}

	claims := AdminClaims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(ttlHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   username,
			Issuer:    "gravity-dns-panel",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateJWT verifies the token signature and returns the username.
func ValidateJWT(secret, tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*AdminClaims); ok && token.Valid {
		return claims.Username, nil
	}

	return "", errors.New("invalid token")
}

// AuthMiddleware protects routes and injects authenticated username into context.
func AuthMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := ""

			// 1. Check Cookie
			if cookie, err := r.Cookie(CookieTokenName); err == nil && cookie.Value != "" {
				tokenStr = cookie.Value
			}

			// 2. Check Authorization Header
			if tokenStr == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if tokenStr == "" {
				if isAPIRequest(r) {
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			username, err := ValidateJWT(secret, tokenStr)
			if err != nil {
				if isAPIRequest(r) {
					http.Error(w, `{"error":"session expired or invalid"}`, http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			ctx := context.WithValue(r.Context(), AdminContextKey, username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isAPIRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/")
}
