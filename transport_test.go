package hsts

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

func reply(req *http.Request, s string) (*http.Response, error) {
	return http.ReadResponse(bufio.NewReader(strings.NewReader(s)), req)
}

type fakeTransport struct{}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return reply(req, "HTTP/1.1 200 OK\r\n"+
			"Strict-Transport-Security: max-age=3600; includeSubDomains\r\n\r\n")
	}
	return reply(req, "HTTP/1.1 200 OK\r\n\r\n")
}

func TestTransport(t *testing.T) {
	client := http.DefaultClient
	client.Transport = New(&fakeTransport{})

	// First request to confirm HSTS not working and no HSTS header in HTTP.
	resp, err := client.Get("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("1: HSTS header in HTTP request")
	}

	// Second request over HTTPS to obtain HSTS header.
	resp, err = client.Get("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("2: HSTS header missing in HTTPS request")
	}

	// Third request over HTTP, we expect HSTS to send us to HTTPS.
	resp, err = client.Get("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("3: HSTS header missing, we did not go to HTTPS")
	}

	// Same with subdomain, we expect HSTS to send us to HTTPS.
	resp, err = client.Get("http://subdomain.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("4: HSTS header missing, we did not go to HTTPS for subdomain")
	}
}
