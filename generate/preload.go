// Binary preload generates a Go file with preloaded HSTS sites from Chromium.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strings"
)

var (
	pkg     = flag.String("p", "hsts", "Package name.")
	varname = flag.String("v", "preload", "Variable name.")
	out     = flag.String("o", "preload.go", "Output file.")
)

func main() {
	flag.Parse()
	sites, err := get()
	if err != nil {
		log.Fatal(err)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "package %s\n", *pkg)
	b.WriteString("\n")
	b.WriteString("// Automatically generated with go generate.\n")
	b.WriteString("\n")
	b.WriteString("// Host -> includeSubDomains\n")
	fmt.Fprintf(&b, "var %s = map[string]bool{\n", *varname)
	for _, e := range sites {
		fmt.Fprintf(&b, "\t%#v: %v,\n", e.Name, e.IncludeSubDomains)
	}
	b.WriteString("}\n")
	if err := ioutil.WriteFile(*out, b.Bytes(), 0660); err != nil {
		log.Fatal(err)
	}
}

const preloadURL = "https://github.com/chromium/chromium/raw/main/net/http/transport_security_state_static.json"

// get obtains the file, decodes base64 and parses JSON to return preloaded HSTS sites.
func get() ([]entry, error) {
	resp, err := http.Get(preloadURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned: %v", resp.Status)
	}
	js, err := removeComments(resp.Body)
	if err != nil {
		return nil, err
	}
	var tss transportSecurityState
	if err := json.Unmarshal(js, &tss); err != nil {
		return nil, err
	}
	set := make(map[string]entry) // host name -> includeSubDomains
	for _, entry := range tss.Entries {
		if entry.Mode != "force-https" {
			continue
		}
		set[entry.Name] = entry
	}
	if len(set) == 0 {
		return nil, errors.New("preload list empty")
	}
	var entries []entry
	for _, entry := range set {
		entries = append(entries, entry)
	}
	sort.Sort(byName(entries))
	return entries, nil
}

func removeComments(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if strings.HasPrefix(strings.TrimSpace(scanner.Text()), "//") {
			continue
		}
		fmt.Fprintf(&buf, "%s\n", scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type transportSecurityState struct {
	Entries []entry `json:"entries"`
}

type entry struct {
	Name              string `json:"name"`
	IncludeSubDomains bool   `json:"include_subdomains"`
	Mode              string `json:"mode"`
}

type byName []entry

func (s byName) Len() int           { return len(s) }
func (s byName) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byName) Less(i, j int) bool { return s[i].Name < s[j].Name }
