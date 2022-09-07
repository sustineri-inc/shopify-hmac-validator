package shopifyhv

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// OAuth validates Shopify OAuth requests.
// Returns true if this request was validated successfully; false otherwise.
func OAuth(r *http.Request, secret string) bool {
	params := r.URL.Query()
	if len(params) == 0 || len(params["hmac"]) == 0 {
		return false
	}
	signature := params["hmac"][0]
	params.Del("hmac")
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(params.Encode()))
	computed := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(computed))
}

// AppProxy validates Shopify App Proxies requests.
// Returns true if this request was validated successfully; false otherwise.
func AppProxy(r *http.Request, secret string) bool {
	params := r.URL.Query()
	if len(params) == 0 || len(params["signature"]) == 0 {
		return false
	}
	signature := params["signature"][0]
	params.Del("signature")
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var encoded string
	for _, k := range keys {
		encoded += k + "=" + strings.Join(params[k], ",")
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(encoded))
	computed := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(computed))
}

// AppBridge validates Shopify App Bridge requests.
// Returns (shop,true) if this request was validated successfully; (empty,false) otherwise.
// The shop is a hostname (e.g. xxx.myshopify.com).
func AppBridge(r *http.Request, key, secret string) (shop string, ok bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	tokens := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
	if len(tokens) != 3 {
		return "", false
	}
	base64Header, base64Payload, base64Signature := tokens[0], tokens[1], tokens[2]
	rawPayload, err := base64.RawURLEncoding.DecodeString(base64Payload)
	if err != nil {
		return "", false
	}
	payload := struct {
		Issuer         string `json:"iss"`
		Destination    string `json:"dest"`
		Audience       string `json:"aud"`
		Subject        string `json:"sub"`
		ExpirationTime int    `json:"exp"`
		NotBefore      int    `json:"nbf"`
		IssuedAt       int    `json:"iat"`
		TokenID        string `json:"jti"`
		SessionID      string `json:"sid"`
	}{}
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return "", false
	}
	now := time.Now().Unix()
	if payload.ExpirationTime < int(now) {
		return "", false
	}
	if payload.NotBefore > int(now) {
		return "", false
	}
	issuerURL, err := url.Parse(payload.Issuer)
	if err != nil {
		return "", false
	}
	destinationURL, err := url.Parse(payload.Destination)
	if err != nil {
		return "", false
	}
	if issuerURL.Hostname() != destinationURL.Hostname() {
		return "", false
	}
	if payload.Audience != key {
		return "", false
	}
	signature, err := base64.RawURLEncoding.DecodeString(base64Signature)
	if err != nil {
		return "", false
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(base64Header + "." + base64Payload))
	if !hmac.Equal(signature, h.Sum(nil)) {
		return "", false
	}
	return destinationURL.Hostname(), true
}

// Webhook validates Shopify Webhook requests.
// Returns true if this request was validated successfully; false otherwise.
func Webhook(r *http.Request, body []byte, secret string) bool {
	signature := r.Header.Get("X-Shopify-Hmac-SHA256")
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	computed := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(h.Sum(nil))))
	return hmac.Equal([]byte(signature), []byte(computed))
}
