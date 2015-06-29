package hsts

import (
	"testing"
	"time"
)

func TestDirectives(t *testing.T) {
	for _, tt := range []struct {
		parse             string
		invalid           bool
		maxAge            time.Duration
		includeSubDomains bool
	}{
		// completely valid
		{
			parse:  "max-age=0",
			maxAge: 0,
		},
		{
			parse:  "max-age=1234",
			maxAge: 1234 * time.Second,
		},
		{ // Value can be a quoted-string.
			parse:  `max-age="5678"`,
			maxAge: 5678 * time.Second,
		},
		{
			parse:             "max-age=1234; includeSubDomains",
			maxAge:            1234 * time.Second,
			includeSubDomains: true,
		},
		{ // Directives have no order.
			parse:             "includeSubDomains; max-age=1234",
			maxAge:            1234 * time.Second,
			includeSubDomains: true,
		},
		{ // Directive name is case-insensitive.
			parse:             "MaX-AgE=1234; InClUdEsUbDoMaInS",
			maxAge:            1234 * time.Second,
			includeSubDomains: true,
		},

		// valid with invalid directives ignored
		{ // ignore the second value
			parse:  "max-age=1234; max-age=0",
			maxAge: 1234 * time.Second,
		},
		{ // ignore spaces and empty fields
			parse:             " \t ; \t max-age=1234 \t ; \t ; \t includeSubDomains \t ; \t ",
			maxAge:            1234 * time.Second,
			includeSubDomains: true,
		},

		// plain invalid
		{
			parse:   `max-age='1234'`,
			invalid: true, // ignore invalid quoting
		},
		{
			parse:   "includeSubDomains",
			invalid: true, // required max-age directive missing
		},
	} {
		d := parse(tt.parse)
		if d == nil {
			if !tt.invalid {
				t.Errorf("parse(%v) returned invalid but wanted valid", tt.parse)
			}
			continue
		}
		if d.maxAge != tt.maxAge {
			t.Errorf("parse(%v) got max age %d; want %d", tt.parse, d.maxAge, tt.maxAge)
		}
		if d.includeSubDomains != tt.includeSubDomains {
			t.Errorf("parse(%v) got includeSubDomains %v; want %v", tt.parse,
				d.includeSubDomains, tt.includeSubDomains)
		}
	}
}
