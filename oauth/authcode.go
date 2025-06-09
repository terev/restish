package oauth

import (
	"bufio"
	"cmp"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"golang.org/x/oauth2"

	"github.com/rest-sh/restish/cli"
)

const DefaultRedirectURL = "http://localhost:8484"

var htmlSuccess = `
<html>
  <style>
    @keyframes bg {
      from {background: white;}
      to {background: #5fafd7;}
    }
    @keyframes x {
      from {transform: rotate(0deg) skew(30deg, 20deg);}
      to {transform: rotate(-45deg);}
    }
    @keyframes fade {
      from {opacity: 0;}
      to {opacity: 1;}
    }
    body { font-family: sans-serif; margin-top: 8%; animation: bg 1.5s ease-out; animation-fill-mode: forwards; }
    p { width: 80%; }
    .check {
      margin: auto;
      width: 18%;
      height: 15%;
      border-left: 16px solid white;
      border-bottom: 16px solid white;
      animation: x 0.7s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      animation-fill-mode: forwards;
    }
    .msg {
      margin: auto;
      margin-top: 180px;
      width: 40%;
      background: white;
      padding: 20px 32px;
      border-radius: 10px;
      animation: fade 2s;
      animation-fill-mode: forwards;
      box-shadow: 0px 15px 15px -15px rgba(0, 0, 0, 0.5);
    }
  </style>
  <body>
    <div class="check"></div>
    <div class="msg">
        <h1>Login Successful!</h1>
        Please return to the terminal. You may now close this window.
      </p>
    </div>
  </body>
</html>
`

var htmlError = `
<html>
  <style>
    @keyframes bg {
      from {background: white;}
      to {background: #E94F37;}
    }
    @keyframes x {
      from {transform: scaleY(0);}
      to {transform: scaleY(1) rotate(-90deg);}
    }
    @keyframes fade {
      from {opacity: 0;}
      to {opacity: 1;}
    }
    body { font-family: sans-serif; margin-top: 15%; animation: bg 1.5s ease-out; animation-fill-mode: forwards; }
    p { width: 80%; }
    .x, .x:after {
      margin: auto;
      background: white;
      width: 20%;
      height: 16px;
      border-radius: 3px;
      transform: rotate(-45deg);
      animation: x 0.7s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      animation-fill-mode: forwards;
    }
    .x:after {
      content: "";
      display: block;
      width: 100%;
      transform: rotate(90deg);
    }
    .msg {
      margin: auto;
      margin-top: 200px;
      width: 40%;
      background: white;
      padding: 20px 32px;
      border-radius: 10px;
      animation: fade 2s;
      animation-fill-mode: forwards;
      box-shadow: 0px 15px 15px -15px rgba(0, 0, 0, 0.5);
    }
  </style>
  <body>
    <div style="transform: rotate(-45deg);"><div class="x"></div></div>
    <div class="msg">
        <h1>Error: $ERROR</h1>
        $DETAILS
      </p>
    </div>
  </body>
</html>
`

// open opens the specified URL in the default browser regardless of OS.
func open(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
		url = encodeUrlWindows(url)
	case "darwin": // mac, ios
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

// Windows OS need strings to be encoded
// for proper command line interface handling.
func encodeUrlWindows(url string) string {
	// escape '&'
	sp := strings.Split(url, "&")
	var escaped string
	for i, p := range sp {
		// Skip adding escape at the beginning
		if i == 0 {
			escaped += p
			continue
		}
		escaped += "^&" + p
	}

	// keep protocol
	return escaped
}

// getInput waits for user input and sends it to the input channel with the
// trailing newline removed.
func getInput(input chan string) {
	r := bufio.NewReader(os.Stdin)
	result, err := r.ReadString('\n')
	if err != nil {
		panic(err)
	}

	input <- strings.TrimRight(result, "\n")
}

// authHandler is an HTTP handler that takes a channel and sends the `code`
// query param when it gets a request.
type authHandler struct {
	state string
	c     chan string
}

func (h authHandler) Callback(w http.ResponseWriter, r *http.Request) {
	if state := r.URL.Query().Get("state"); subtle.ConstantTimeCompare([]byte(state), []byte(h.state)) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	if err := r.URL.Query().Get("error"); err != "" {
		details := r.URL.Query().Get("error_description")
		rendered := strings.Replace(strings.Replace(htmlError, "$ERROR", err, 1), "$DETAILS", details, 1)
		w.Write([]byte(rendered))
		h.c <- ""
		return
	}

	h.c <- r.URL.Query().Get("code")
	w.Write([]byte(htmlSuccess))
}

// AuthorizationCodeTokenSource with PKCE as described in:
// https://www.oauth.com/oauth2-servers/pkce/
// This works by running a local HTTP server on port 8484 and then having the
// user log in through a web browser, which redirects to the redirect url with
// an authorization code. That code is then used to make another HTTP request
// to fetch an auth token (and refresh token). That token is then in turn
// used to make requests against the API.
type AuthorizationCodeTokenSource struct {
	OAuth2Config *oauth2.Config
}

// Token generates a new token using an authorization code.
func (ac *AuthorizationCodeTokenSource) Token() (*oauth2.Token, error) {
	verifier := oauth2.GenerateVerifier()
	state := oauth2.GenerateVerifier()

	// Generate a URL with the challenge to have the user log in.
	authorizeURL := ac.OAuth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	// Run server before opening the user's browser so we are ready for any redirect.
	codeChan := make(chan string)
	handler := authHandler{
		state: state,
		c:     codeChan,
	}

	// strip protocol prefix from configured redirect url for local webserver
	redirectURL, err := url.Parse(ac.OAuth2Config.RedirectURL)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+redirectURL.Path, handler.Callback)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	s := &http.Server{
		Handler:        mux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxHeaderBytes: 1024,
	}

	// Start listener in this goroutine to ensure it's started before showing the user the auth url.
	listener, err := net.Listen("tcp", redirectURL.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}

	go func() {
		// Run in a goroutine until the server is closed, or we get an error.
		if err := s.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Errorf("callback server encountered unexpected error: %w", err))
		}
	}()

	// Open auth URL in browser, print for manual use in case open fails.
	fmt.Fprintln(os.Stderr, "Open your browser to log in using the URL:")
	fmt.Fprintln(os.Stderr, authorizeURL)
	open(authorizeURL)

	// Provide a way to manually enter the code, e.g. for remote SSH sessions.
	// Only read from stdin if it is a live terminal, if a file or command has
	// been piped in it is likely the request body to use after auth.
	manualCodeChan := make(chan string)
	if isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		fmt.Fprint(os.Stderr, "Alternatively, enter the code manually: ")
		go getInput(manualCodeChan)
	}

	// Get code from handler, exchange it for a token, and then return it. This
	// select blocks until one code becomes available.
	// There is currently no timeout.
	var code string
	select {
	case code = <-codeChan:
	case code = <-manualCodeChan:
	}
	fmt.Fprintln(os.Stderr, "")
	s.Shutdown(context.Background())

	if code == "" {
		fmt.Fprintln(os.Stderr, "Unable to get a code. See browser for details. Aborting!")
		os.Exit(1)
	}

	token, err := ac.OAuth2Config.Exchange(context.Background(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	return token, nil
}

// AuthorizationCodeHandler sets up the OAuth 2.0 authorization code with PKCE authentication
// flow.
type AuthorizationCodeHandler struct{}

// Parameters returns a list of OAuth2 Authorization Code inputs.
func (h *AuthorizationCodeHandler) Parameters() []cli.AuthParam {
	return []cli.AuthParam{
		{Name: "client_id", Required: true, Help: "OAuth 2.0 Client ID"},
		{Name: "client_secret", Required: false, Help: "OAuth 2.0 Client Secret if exists"},
		{Name: "authorize_url", Required: true, Help: "OAuth 2.0 authorization URL, e.g. https://api.example.com/oauth/authorize"},
		{Name: "token_url", Required: true, Help: "OAuth 2.0 token URL, e.g. https://api.example.com/oauth/token"},
		{Name: "scopes", Help: "Optional scopes to request in the token"},
		{Name: "redirect_url", Help: "Optional redirect URL with protocol and port, defaults to 'http://localhost:8484' if not specified. "},
	}
}

// OnRequest gets run before the request goes out on the wire.
func (h *AuthorizationCodeHandler) OnRequest(request *http.Request, key string, params map[string]string) error {
	if request.Header.Get("Authorization") != "" {
		return nil
	}

	authorizeURL, err := url.Parse(params["authorize_url"])
	if err != nil {
		return fmt.Errorf("invalid authorize_url %q: %w", params["token_url"], err)
	}

	tokenURL, err := url.Parse(params["token_url"])
	if err != nil {
		return fmt.Errorf("invalid token_url %q: %w", params["token_url"], err)
	}

	tokenQuery := tokenURL.Query()
	authorizeQuery := authorizeURL.Query()
	for k, v := range params {
		if k == "client_id" || k == "client_secret" || k == "scopes" || k == "authorize_url" || k == "token_url" || k == "redirect_url" {
			// Not a custom param...
			continue
		}

		tokenQuery.Add(k, v)
		authorizeQuery.Add(k, v)
	}

	tokenURL.RawQuery = tokenQuery.Encode()
	authorizeURL.RawQuery = authorizeQuery.Encode()

	oauth2Conf := &oauth2.Config{
		ClientID:     params["client_id"],
		ClientSecret: params["client_secret"],
		RedirectURL:  cmp.Or(params["redirect_url"], DefaultRedirectURL),
		Endpoint: oauth2.Endpoint{
			AuthURL:  authorizeURL.String(),
			TokenURL: tokenURL.String(),
		},
		Scopes: strings.Split(params["scopes"], ","),
	}

	cachedToken := readTokenFromCache(key)
	var initialSource oauth2.TokenSource
	if cachedToken != nil {
		initialSource = oauth2Conf.TokenSource(context.Background(), cachedToken)
	}

	return TokenHandler(&RefreshableAuthorizationCodeTokenSource{
		OAuth2Conf:  oauth2Conf,
		TokenSource: initialSource,
	}, key, request)
}
