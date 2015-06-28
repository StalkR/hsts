/*
Package hsts implements a RoundTripper that supports HTTP Strict Transport Security.
*/
package hsts

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
	m     sync.Mutex           // protects state
	state map[string]directive // key is host (RFC section 8.3)
}

// New wraps around a RoundTripper to add HTTP Strict Transport Security (HSTS).
func New(rt http.RoundTripper) *Transport {
	return &Transport{
		wrap:  rt,
		state: make(map[string]directive),
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
	d, ok := t.find(host, true)
	if !ok {
		return req
	}

	if time.Now().After(d.expires) {
		delete(t.state, host)
		return req
	}

	// section 8.3.5
	if req.URL.Scheme == "http" {
		req.URL.Scheme = "https"
	}
	if strings.Contains(req.URL.Host, ":") {
		hp := strings.SplitN(req.URL.Host, ":", 2)
		if port, err := strconv.Atoi(hp[1]); err == nil {
			if port == 80 {
				port = 443
			}
			req.URL.Host = fmt.Sprintf("%s:%d", hp[0], port)
		}
	}

	return req
}

// find finds a host including subdomains. Lock must be taken already.
func (t *Transport) find(host string, exact bool) (directive, bool) {
	d, ok := t.state[host]
	if ok && (exact || d.includeSubDomains) {
		return d, true
	}
	i := strings.Index(host, ".")
	if i == -1 {
		return directive{}, false
	}
	return t.find(host[i+1:], false)
}

// response looks into an HTTP response to see if HSTS state needs to be updated.
func (t *Transport) response(resp *http.Response) {
	t.m.Lock()
	defer t.m.Unlock()
	d := parse(resp.Header.Get("Strict-Transport-Security"))
	host := resp.Request.URL.Host
	if d.maxAge == 0 {
		delete(t.state, host)
		return
	}
	t.state[host] = d
}
