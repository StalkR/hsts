# HTTP Strict Transport Security (HSTS)

[![Build Status][1]][2] [![Godoc][3]][4]

http [RoundTripper][8] implementing [HTTP Strict Transport Security][6]
([RFC 6797][7]) with sites preloaded from [Chromium][9] using `go generate`.

Install:

	go get github.com/StalkR/hsts

Usage (taken from the example in [godoc][4]):

	client := http.DefaultClient
	// Wrap around the client's transport to add HSTS support.
	client.Transport = hsts.New(client.Transport)

	// Assuming example.com has set up HSTS, we learn it at the first HTTPS request.
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// So that any following request made in insecure HTTP would go in HTTPS.
	resp, err = client.Get("http://example.com") // will become HTTPS
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

Bugs, comments, questions: create a [new issue][5].

[1]: https://github.com/StalkR/hsts/actions/workflows/build.yml/badge.svg
[2]: https://github.com/StalkR/hsts/actions/workflows/build.yml
[3]: https://godoc.org/github.com/StalkR/hsts?status.png
[4]: https://godoc.org/github.com/StalkR/hsts
[5]: https://github.com/StalkR/hsts/issues/new
[6]: https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
[7]: https://tools.ietf.org/html/rfc6797
[8]: https://godoc.org/net/http#RoundTripper
[9]: https://www.chromium.org/hsts
