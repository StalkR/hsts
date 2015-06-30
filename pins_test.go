package hsts

import (
	"net/http"
	"testing"
)

type checkTransport struct{}

func (f *checkTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return reply(req, "HTTP/1.1 200 OK\r\n\r\n")
	}
	return reply(req, "HTTP/1.1 500 OK\r\n\r\n")
}

func TestStaticDomains(t *testing.T) {
	client := http.DefaultClient
	client.Transport = New(&checkTransport{})

	// We expect some domains to be pinned therefore HTTPS at first request.
	// We also expect they have includeSubDomains set.
	for _, tt := range []string{
		"accounts.google.com",
		"x.accounts.google.com",
		"login.yahoo.com",
		"x.login.yahoo.com",
	} {
		resp, err := client.Get("http://" + tt)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s is not pinned", tt)
		}
	}
}
