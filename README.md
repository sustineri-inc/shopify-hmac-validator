# shopify-hmac-validator

A Shopify HMAC validator written in Golang.

This library uses only the standard library and designed for `net/http` users.

## Usage

### OAuth

```go
package main

import (
	"log"
	"net/http"

	"github.com/sustineri-inc/shopify-hmac-validator"
)

func handleOAuth(w http.ResponseWriter, r *http.Request) {
	if ok := shopifyhv.OAuth(r, "secret"); !ok {
		http.Error(w, "invalid oauth request", http.StatusUnauthorized)
		return
	}
	log.Println(r.URL.Query().Get("shop"))
	// handling code...
}
```

### App Proxies

```go
package main

import (
	"log"
	"net/http"

	"github.com/sustineri-inc/shopify-hmac-validator"
)

func handleAppProxy(w http.ResponseWriter, r *http.Request) {
	if ok := shopifyhv.AppProxy(r, "secret"); !ok {
		http.Error(w, "invalid app proxy request", http.StatusUnauthorized)
		return
	}
	log.Println(r.URL.Query().Get("shop"))
	// handling code...
}
```

### App Bridge

```go
package main

import (
	"log"
	"net/http"

	"github.com/sustineri-inc/shopify-hmac-validator"
)

func handleAppBridge(w http.ResponseWriter, r *http.Request) {
	shop, ok := shopifyhv.AppBridge(r, "key", "secret")
	if !ok {
		http.Error(w, "invalid app bridge request", http.StatusUnauthorized)
		return
	}
	log.Println(shop)
	// handling code...
}
```

### Webhooks

```go
package main

import (
	"io"
	"log"
	"net/http"

	"github.com/sustineri-inc/shopify-hmac-validator"
)

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		return
	}
	if !shopifyhv.Webhook(r, body, "secret") {
		http.Error(w, "invalid webhook", http.StatusUnauthorized)
		return
	}
	// handling code...
}
```

## LICENSE

[BSD 3-clause](LICENSE)

## Author

[Sustineri Inc](https://sustineri.co.jp/)
