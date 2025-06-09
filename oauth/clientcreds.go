package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/rest-sh/restish/cli"
)

// ClientCredentialsHandler implements the Client Credentials OAuth2 flow.
type ClientCredentialsHandler struct{}

// Parameters returns a list of OAuth2 Authorization Code inputs.
func (h *ClientCredentialsHandler) Parameters() []cli.AuthParam {
	return []cli.AuthParam{
		{Name: "client_id", Required: true, Help: "OAuth 2.0 Client ID"},
		{Name: "client_secret", Required: true, Help: "OAuth 2.0 Client Secret"},
		{Name: "token_url", Required: true, Help: "OAuth 2.0 token URL, e.g. https://api.example.com/oauth/token"},
		{Name: "scopes", Help: "Optional scopes to request in the token"},
	}
}

// OnRequest gets run before the request goes out on the wire.
func (h *ClientCredentialsHandler) OnRequest(request *http.Request, key string, params map[string]string) error {
	if request.Header.Get("Authorization") != "" {
		return nil
	}

	clientID, exists := params["client_id"]
	if !exists {
		return fmt.Errorf("%w: profile is missing client_id", ErrInvalidProfile)
	} else if clientID == "" {
		return fmt.Errorf("%w: profile has empty client_id", ErrInvalidProfile)
	}

	clientSecret, exists := params["client_secret"]
	if !exists {
		return fmt.Errorf("%w: profile is missing client_secret", ErrInvalidProfile)
	} else if clientSecret == "" {
		return fmt.Errorf("%w: profile has empty client_secret", ErrInvalidProfile)
	}

	tokenURL, exists := params["token_url"]
	if !exists {
		return fmt.Errorf("%w: profile is missing token_url", ErrInvalidProfile)
	} else if tokenURL == "" {
		return fmt.Errorf("%w: profile has empty token_url", ErrInvalidProfile)
	}

	endpointParams := url.Values{}
	for k, v := range params {
		if k == "client_id" || k == "client_secret" || k == "scopes" || k == "token_url" {
			// Not a custom param...
			continue
		}

		endpointParams.Add(k, v)
	}

	ccConfig := &clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       tokenURL,
		EndpointParams: endpointParams,
		Scopes:         strings.Split(params["scopes"], ","),
	}

	ts := oauth2.ReuseTokenSource(
		readTokenFromCache(key),
		ccConfig.TokenSource(context.Background()),
	)

	return TokenHandler(ts, key, request)
}
