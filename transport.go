/*
Package hsts implements a RoundTripper that supports HTTP Strict Transport Security.

It comes preloaded with sites from Chromium (https://www.chromium.org/hsts),
updated with go generate.
*/
package hsts

//go:generate go run generate/preload.go -p hsts -v preload -o preload.go
//go:generate gofmt -w preload.go

import (
	"fmt"
	"net/http"
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
	resp, err := t.wrap.RoundTrip(t.request(req))
	if err != nil {
		return resp, err
	}
	t.response(resp)
	return resp, nil
}

// request modifies an HTTP request for HSTS if needed.
func (t *Transport) request(req *http.Request) *http.Request {
	t.m.Lock()
	defer t.m.Unlock()

	// TODO(StalkR): check host isn't an IP-literal or IPv4 (section 8.3.3).

	host := req.URL.Host
	d := t.find(host, true)
	if d == nil { // not found
		return req
	}

	// Preloaded sites do not expire; dynamic entries do.
	preloaded := d.received.IsZero()
	if !preloaded && time.Now().After(d.received.Add(d.maxAge)) {
		delete(t.state, host)
		return req
	}

	// Section 8.3 step 5a says to replace the http scheme with https.
	if req.URL.Scheme == "http" {
		req.URL.Scheme = "https"
	}
	// Section 8.3 step 5b says to replace explicit 80 with 443.
	if strings.Contains(req.URL.Host, ":") {
		hp := strings.SplitN(req.URL.Host, ":", 2)
		if port, err := strconv.Atoi(hp[1]); err == nil {
			if port == 80 {
				port = 443
			}
			req.URL.Host = fmt.Sprintf("%s:%d", hp[0], port)
		}
	}
	// Section 8.3 step 5c and 5d says to preserve otherwise.

	return req
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

// response looks into an HTTP response to see if HSTS state needs to be updated.
func (t *Transport) response(resp *http.Response) {
	header := resp.Header.Get("Strict-Transport-Security")
	if header == "" {
		return // missing
	}
	d := parse(header)
	if d == nil {
		return // invalid
	}
	host := resp.Request.URL.Host
	t.m.Lock()
	defer t.m.Unlock()
	if d.maxAge == 0 { // Section 6.1.1 says 0 signals the UA to forget about it.
		delete(t.state, host)
		return
	}
	t.state[host] = d
}
