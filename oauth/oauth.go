package oauth

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/rest-sh/restish/cli"
)

// ErrInvalidProfile is thrown when a profile is missing or invalid.
var ErrInvalidProfile = errors.New("invalid profile")

// TokenHandler takes a token source, gets a token, and modifies a request to
// add the token auth as a header. Uses the CLI cache to store tokens on a per-
// profile basis between runs.
func TokenHandler(source oauth2.TokenSource, key string, request *http.Request) error {
	cached := readTokenFromCache(key)

	// Get the next available token from the source.
	token, err := source.Token()
	if err != nil {
		return err
	}

	if cached == nil || (token.AccessToken != cached.AccessToken) {
		// Token either didn't exist in the cache or has changed, so let's write
		// the new values to the CLI cache.
		cli.LogDebug("Token refreshed. Updating cache.")

		if err := writeTokenToCache(key, token); err != nil {
			return err
		}
	}

	// Set the auth header so the request can be made.
	token.SetAuthHeader(request)
	return nil
}

func readTokenFromCache(authProfileKey string) *oauth2.Token {
	// Load any existing token from the CLI's cache file.
	expiresKey := authProfileKey + ".expires"
	typeKey := authProfileKey + ".type"
	tokenKey := authProfileKey + ".token"
	refreshKey := authProfileKey + ".refresh"

	expiry := cli.Cache.GetTime(expiresKey)
	if expiry.IsZero() {
		return nil
	}

	cli.LogDebug("Loading OAuth2 token from cache.")
	return &oauth2.Token{
		AccessToken:  cli.Cache.GetString(tokenKey),
		RefreshToken: cli.Cache.GetString(refreshKey),
		TokenType:    cli.Cache.GetString(typeKey),
		Expiry:       expiry,
	}
}

func writeTokenToCache(authProfileKey string, token *oauth2.Token) error {
	// Write the token to the CLI's cache file.
	expiresKey := authProfileKey + ".expires"
	typeKey := authProfileKey + ".type"
	tokenKey := authProfileKey + ".token"
	refreshKey := authProfileKey + ".refresh"

	cli.Cache.Set(expiresKey, token.Expiry)
	cli.Cache.Set(typeKey, token.Type())
	cli.Cache.Set(tokenKey, token.AccessToken)

	if token.RefreshToken != "" {
		// Only set the refresh token if present. This prevents overwriting it
		// after using a refresh token, because the newly returned token won't
		// have another refresh token set on it (you keep using the same one).
		cli.Cache.Set(refreshKey, token.RefreshToken)
	}
	// Save the cache to disk.
	if err := cli.Cache.WriteConfig(); err != nil {
		return fmt.Errorf("an error ocurred writing token to cache: %w", err)
	}

	return nil
}
