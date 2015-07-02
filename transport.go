/*
Package hsts implements a RoundTripper that supports HTTP Strict Transport Security.

It comes preloaded with sites from Chromium (https://www.chromium.org/hsts),
updated with go generate.
*/
package hsts

//go:generate go run generate/preload.go -p hsts -v preload -o preload.go
//go:generate gofmt -w preload.go

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Transport implements a RoundTripper adding HSTS to an existing RoundTripper.
type Transport struct {
	wrap  http.RoundTripper
	m     sync.Mutex            // protects state
	state map[string]*directive // key is host (RFC section 8.3)
}

// New wraps around a RoundTripper transport to add HTTP Strict Transport Security (HSTS).
// It starts preloaded with Chromium's list (https://www.chromium.org/hsts).
// Just like an http.Client if transport is nil, http.DefaultTransport is used.
func New(transport http.RoundTripper) *Transport {
	if transport == nil {
		transport = http.DefaultTransport
	}
	state := make(map[string]*directive)
	for host, includeSubDomains := range preload {
		state[host] = &directive{includeSubDomains: includeSubDomains}
	}
	return &Transport{
		wrap:  transport,
		state: state,
	}
}

// RoundTrip executes a single HTTP transaction and adds support for HSTS.
// It is safe for concurrent use by multiple goroutines.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if u, ok := t.needsUpgrade(req); ok {
		code := http.StatusTemporaryRedirect
		return reply(req, fmt.Sprintf("HTTP/1.1 %d %s\r\nLocation: %s\r\n\r\n",
			code, http.StatusText(code), u.String()))
	}
	resp, err := t.wrap.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	t.processResponse(resp)
	return resp, nil
}

func reply(req *http.Request, s string) (*http.Response, error) {
	return http.ReadResponse(bufio.NewReader(strings.NewReader(s)), req)
}

// needsUpgrade tells whether a request is HTTP and needs upgrading to HTTPS.
// If it needs upgrading, the destination URL to redirect to is returned.
func (t *Transport) needsUpgrade(req *http.Request) (*url.URL, bool) {
	if req.URL.Scheme != "http" {
		return nil, false
	}

	t.m.Lock()
	defer t.m.Unlock()

	// TODO(StalkR): check host isn't an IP-literal or IPv4 (section 8.3.3).

	host := req.URL.Host
	d := t.find(host, true)
	if d == nil { // not found
		return nil, false
	}

	// Preloaded sites do not expire; dynamic entries do.
	preloaded := d.received.IsZero()
	if !preloaded && time.Now().After(d.received.Add(d.maxAge)) {
		delete(t.state, host)
		return nil, false
	}

	u := *req.URL // copy to avoid modifying the request URL

	// Section 8.3 step 5a says to replace the http scheme with https.
	if u.Scheme == "http" {
		u.Scheme = "https"
	}
	// Section 8.3 step 5b says to replace explicit 80 with 443.
	if strings.Contains(u.Host, ":") {
		hp := strings.SplitN(u.Host, ":", 2)
		if port, err := strconv.Atoi(hp[1]); err == nil {
			if port == 80 {
				port = 443
			}
			u.Host = fmt.Sprintf("%s:%d", hp[0], port)
		}
	}
	// Section 8.3 step 5c and 5d says to preserve otherwise.

	return &u, true
}

// find finds a host including subdomains. Lock must be taken already.
func (t *Transport) find(host string, exact bool) *directive {
	d, ok := t.state[host]
	if ok && (exact || d.includeSubDomains) {
		return d
	}
	i := strings.Index(host, ".")
	if i == -1 {
		return nil
	}
	return t.find(host[i+1:], false)
}

// processResponse looks into an HTTP response to see if HSTS state needs to be updated.
func (t *Transport) processResponse(resp *http.Response) {
	header := resp.Header.Get("Strict-Transport-Security")
	if header == "" {
		return // missing
	}
	d := parse(header)
	if d == nil {
		return // invalid
	}
	t.add(resp.Request.URL.Host, d)
}

// Add adds a host in the Strict-Transport-Security state.
func (t *Transport) add(host string, d *directive) {
	t.m.Lock()
	defer t.m.Unlock()
	if d.maxAge == 0 { // Section 6.1.1 says 0 signals the UA to forget about it.
		delete(t.state, host)
		return
	}
	t.state[host] = d
}
