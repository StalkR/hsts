package hsts

import (
	"strconv"
	"strings"
	"time"
)

// A directive stores HSTS state information for a given host.
type directive struct {
	received          time.Time
	maxAge            time.Duration
	includeSubDomains bool
}

// parse parses a Strict-Transport-Security header as specified in section 6.1.
// Section 6.1 requirements 4 & 5 say to ignore non-conformance so no error is returned.
func parse(header string) *directive {
	// Use a map as a set to check for unicity (6.1 requirement 2).
	directives := make(map[string]struct{})

	// Known directives.
	var maxAge time.Duration
	var includeSubDomains bool

	// Section 6.1 defines the grammar as:
	//   Strict-Transport-Security = [ directive ]  *( ";" [ directive ] )
	//   directive                 = directive-name [ "=" directive-value ]
	//   directive-name            = token
	//   directive-value           = token | quoted-string
	for _, directive := range strings.Split(header, ";") {
		var name, value string

		// Grammar says directive value is optional.
		if strings.Contains(directive, "=") {
			nv := strings.SplitN(directive, "=", 2)
			name = nv[0]
			value = nv[1]
		} else {
			name = directive
		}

		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)

		name = strings.ToLower(name) // Section 6.1 requirement 3.

		if _, ok := directives[name]; ok {
			// Section 6.1 requirement 2 says directives must appear only once
			// and requirements 4 & 5 say to ignore directives that do not conform
			// so we ignore duplicates.
			continue
		}
		directives[name] = struct{}{}

		// Grammar says directive value can be be a quoted string.
		if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			v, err := strconv.Unquote(value)
			if err != nil {
				// Section 6.1 requirement 4 says to ignore non-conforming values.
				continue
			}
			value = v
		}

		switch name { // Note it's been lowercased
		case "max-age":
			secs, err := strconv.Atoi(value)
			if err != nil {
				// Section 6.1 requirement 4 says to ignore non-conforming values.
				continue
			}
			maxAge = time.Duration(secs) * time.Second
		case "includesubdomains":
			if value != "" {
				// Section 6.1 requirement 4 says to ignore non-conforming values.
				continue
			}
			includeSubDomains = true
		}
	}

	// Section 6.1.1 says the max-age directive is required and section 6.1
	// requirements 4 & 5 say to ignore non-conformance, so we ignore all of it.
	if _, ok := directives["max-age"]; !ok {
		return nil
	}

	return &directive{
		received:          time.Now(),
		maxAge:            maxAge,
		includeSubDomains: includeSubDomains,
	}
}
