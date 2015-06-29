// Binary pins generates a Go file with strict transport security pins from Chromium.
// It does not extract public key pins.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
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
	varname = flag.String("v", "pins", "Variable name.")
	out     = flag.String("o", "pins.go", "Output file.")
)

func main() {
	flag.Parse()
	pins, err := Get()
	if err != nil {
		log.Fatal(err)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "package %s\n", *pkg)
	b.WriteString("\n")
	fmt.Fprintf(&b, "var %s = map[string]*directive{\n", *varname)
	for _, e := range pins {
		if e.IncludeSubDomains {
			fmt.Fprintf(&b, "\t%#v: &directive{includeSubDomains: true},\n", e.Name)
		} else {
			fmt.Fprintf(&b, "\t%#v: &directive{},\n", e.Name)
		}
	}
	b.WriteString("}\n")
	if err := ioutil.WriteFile(*out, b.Bytes(), 0660); err != nil {
		log.Fatal(err)
	}
}

/*
Chromium source code is hosted on Gerrit. The file we are interested in is:
https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json
Unfortunately there does not seem to be a way to download a single file.
We do not want to clone the entire repo but we can get an archive of this particular
directory: https://chromium.googlesource.com/chromium/src/+archive/master/net/http.tar.gz
*/
const (
	archiveURL = "https://chromium.googlesource.com/chromium/src/+archive/master/net/http.tar.gz"
	fileName   = "transport_security_state_static.json"
)

// Get obtains the archive, decompresses, extracts the JSON and parses it to return the pins.
func Get() ([]entry, error) {
	resp, err := http.Get(archiveURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalln(err)
		}
		if hdr.Name == fileName {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("pins: %s not found in archive", fileName)
	}
	js, err := removeComments(tr)
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
		return nil, errors.New("pins data empty")
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
