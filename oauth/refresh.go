package oauth

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/rest-sh/restish/cli"
)

// RefreshableAuthorizationCodeTokenSource will use a refresh token to try and get a new token before
// calling the original token source to get a new token.
type RefreshableAuthorizationCodeTokenSource struct {
	OAuth2Conf  *oauth2.Config
	TokenSource oauth2.TokenSource
}

// Token generates a new token using either a refresh token or by falling
// back to the original source.
func (ts *RefreshableAuthorizationCodeTokenSource) Token() (*oauth2.Token, error) {
	if ts.TokenSource != nil {
		token, err := ts.TokenSource.Token()
		if err == nil {
			return token, nil
		} else {
			cli.LogDebug("TokenSource returned an error: %q", err)
		}
	}

	authCodeTokenSource := &AuthorizationCodeTokenSource{
		OAuth2Config: ts.OAuth2Conf,
	}

	cli.LogDebug("Starting flow for new authorization code token")
	token, err := authCodeTokenSource.Token()
	if err != nil {
		return nil, err
	}

	ts.TokenSource = ts.OAuth2Conf.TokenSource(context.Background(), token)

	return token, nil
}
