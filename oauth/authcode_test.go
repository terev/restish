package oauth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeUrlWindowsSuccess(t *testing.T) {
	u := "https://mydomain.auth.us-east-1.amazoncognito.com/oauth2/authorize?response_type=code&client_id=1example23456789&redirect_uri=https://www.example.com&state=abcdefg&scope=openid+profile"

	r := encodeUrlWindows(u)
	//t.Log(r)

	assert.NotEqual(t, u, r)
	assert.Contains(t, r, "^&")
	assert.False(t, strings.HasPrefix(r, "^&"))
	assert.False(t, strings.HasSuffix(r, "^&"))
}
