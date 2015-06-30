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
	return reply(req, "HTTP/1.1 202 OK\r\n\r\n")
}

func TestPreloaded(t *testing.T) {
	client := http.DefaultClient
	client.Transport = New(&checkTransport{})

	// We expect some domains to be preloaded therefore HTTPS at first request.
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
			t.Errorf("%s is not preloaded", tt)
		}
	}
}

type deleteTransport struct{}

func (f *deleteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return reply(req, "HTTP/1.1 200 OK\r\n"+
			"Strict-Transport-Security: max-age=0\r\n\r\n")
	}
	return reply(req, "HTTP/1.1 202 OK\r\n\r\n")
}

func TestPersistence(t *testing.T) {
	client := http.DefaultClient
	client.Transport = New(&deleteTransport{})

	domain := "accounts.google.com" // a domain we know is preloaded

	// First request goes to HTTPS because preloaded.
	resp, err := client.Get("http://" + domain)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("1: %s was not preloaded", domain)
	}

	// Even though it is preloaded, check that it gets deleted if max-age is 0.
	resp, err = client.Get("http://accounts.google.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("2: %s is still preloaded", domain)
	}

	// Create a new HSTS transport and check that it was not deleted there.
	client.Transport = New(&checkTransport{})
	resp, err = client.Get("http://" + domain)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("3: %s is no longer preloaded", domain)
	}
}
