package hsts

import (
	"log"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

func ExampleNew() {
	client := http.DefaultClient
	// Wrap around the client's transport to add HSTS support.
	client.Transport = New(client.Transport)

	// Assuming example.com has set up HSTS, we learn it at the first HTTPS request.
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// So that any following request made in insecure HTTP would go in HTTPS.
	resp, err = client.Get("http://example.com") // will become HTTPS
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
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
		t.Fatal("1: unexpected HSTS header in HTTP request")
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
		t.Error("3: HSTS header missing, we did not go to HTTPS")
	}

	// Same with subdomain, we expect HSTS to send us to HTTPS.
	resp, err = client.Get("http://subdomain.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Error("4: HSTS header missing, we did not go to HTTPS for subdomain")
	}
}

func TestDefaultTransport(t *testing.T) {
	transport := New(nil)
	if transport.wrap != http.DefaultTransport {
		t.Fatal("expected nil to set transport to DefaultTransport")
	}
}

type cookieTransport struct{}

func (f *cookieTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return reply(req, "HTTP/1.1 200 OK\r\n"+
			"Strict-Transport-Security: max-age=3600; includeSubDomains\r\n"+
			"Set-Cookie: secure=1; Secure\r\n\r\n")
	}
	return reply(req, "HTTP/1.1 200 OK\r\n\r\n")
}

func TestSecureCookie(t *testing.T) {
	client := http.DefaultClient
	client.Transport = New(&cookieTransport{})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar

	// First request over HTTPS to obtain HSTS header and secure cookie.
	resp, err := client.Get("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("1: HSTS header missing in HTTPS request")
	}

	// Second request over HTTP to be upgraded to HTTPS. We expect secure cookie to be sent.
	resp, err = client.Get("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("2: HSTS header missing in HTTPS request")
	}
	if len(resp.Request.Cookies()) == 0 {
		t.Fatal("2: secure cookie was not sent when upgraded to HTTPS")
	}
}
