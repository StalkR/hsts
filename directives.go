package hsts

import (
	"strconv"
	"strings"
	"time"
)

// A directive stores HSTS state information for a given host.
type directive struct {
	maxAge            uint      // keep it because if 0 it means removing
	expires           time.Time // derived from max-age, convenient for compare
	includeSubDomains bool      // optional, default false
}

// parse parses a Strict-Transport-Security header as per RFC section 6.1.
// Section 6.1.4 says to ignore non-conformance so no error returned.
func parse(header string) directive {
	var d directive
	for _, field := range strings.Split(header, ";") {
		field := strings.TrimSpace(field)
		if strings.HasPrefix(field, "max-age=") {
			value := field[len("max-age="):]
			if strings.HasPrefix(value, `"`) {
				v, err := strconv.Unquote(value)
				if err != nil {
					continue
				}
				value = v
			}
			secs, err := strconv.Atoi(value)
			if err != nil {
				continue
			}
			d.maxAge = uint(secs)
			d.expires = time.Now().Add(time.Duration(secs) * time.Second)
		} else if field == "includeSubDomains" {
			d.includeSubDomains = true
		}
	}
	return d
}
