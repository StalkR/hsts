package main

import "testing"

// TestGenerate tests that we can still generate the list, to catch
// if anything changes on Chromium side.
func TestGenerate(t *testing.T) {
	sites, err := get()
	if err != nil {
		t.Fatal(err)
	}
	// 2019-05-01 list was 69567 domains long.
	if len(sites) < 50000 {
		t.Errorf("too few sites: %v", len(sites))
	}
	domains := map[string]bool{}
	for _, e := range sites {
		domains[e.Name] = e.IncludeSubDomains
	}
	// Domains we expect in the list and to include subdomains.
	for _, d := range []string{
		"accounts.google.com",
		"login.yahoo.com",
	} {
		include, ok := domains[d]
		if !ok {
			t.Errorf("not in the list: %v", d)
		} else if !include {
			t.Errorf("does not include subdomains: %v", d)
		}
	}
}
