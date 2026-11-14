// Package upstream is the server-side client for the VPNaaS backend API. The
// API key is read from a file on every request and never leaves the server.
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	ErrKey         = errors.New("API key tidak tersedia di server dashboard")
	ErrUnavailable = errors.New("VPN API tidak dapat dihubungi. Periksa SSH tunnel dan layanan backend.")
	ErrNotAllowed  = errors.New("rute API tidak dikenal")

	getRe    = regexp.MustCompile(`^(health|overview|connections|users|policies|status|audit|users/[^/]+/profile|connections/[^/]+/sites/[ab]/config)$`)
	postRe   = regexp.MustCompile(`^(connections|users|policies|connections/[^/]+/(initiate|terminate)|connections/[^/]+/sites/[ab]/(connect|disconnect))$`)
	itemRe   = regexp.MustCompile(`^(connections|users|policies)/[^/]+$`)
	maxReply = int64(8 << 20)
)

// Allowed reproduces the Python proxy allowlist exactly.
func Allowed(method, path string) bool {
	if strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\") {
		return false
	}
	switch method {
	case http.MethodGet:
		return getRe.MatchString(path)
	case http.MethodPost:
		return postRe.MatchString(path)
	case http.MethodPut, http.MethodDelete:
		return itemRe.MatchString(path)
	}
	return false
}

type Client struct {
	base    string
	keyFile string
	http    *http.Client
}

func New(base, keyFile string) *Client {
	return &Client{base: strings.TrimRight(base, "/"), keyFile: keyFile, http: &http.Client{
		Timeout:       25 * time.Second,
		Transport:     &http.Transport{Proxy: nil, MaxIdleConns: 8, IdleConnTimeout: 60 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *Response) OK() bool { return r.Status >= 200 && r.Status < 300 }

// Detail extracts a human-readable error message from an upstream reply.
func (r *Response) Detail() string {
	var v map[string]any
	if json.Unmarshal(r.Body, &v) == nil {
		for _, k := range []string{"detail", "error"} {
			if d, ok := v[k]; ok {
				if s, ok := d.(string); ok {
					return s
				}
				b, _ := json.Marshal(d)
				return string(b)
			}
		}
	}
	return fmt.Sprintf("Permintaan gagal (HTTP %d)", r.Status)
}

func (c *Client) key() (string, error) {
	raw, err := os.ReadFile(c.keyFile)
	if err != nil {
		return "", ErrKey
	}
	k := strings.TrimSpace(string(raw))
	if k == "" {
		return "", ErrKey
	}
	return k, nil
}

// Do performs an allowlisted call. contentType defaults to application/json.
func (c *Client) Do(ctx context.Context, method, path, rawQuery string, body []byte, contentType string) (*Response, error) {
	if !Allowed(method, path) {
		return nil, ErrNotAllowed
	}
	key, err := c.key()
	if err != nil {
		return nil, err
	}
	u := c.base + "/api/" + path
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, ErrNotAllowed
	}
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxReply))
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Response{Status: res.StatusCode, Header: res.Header, Body: data}, nil
}

// JSON performs a call and decodes a 2xx JSON reply into out.
func (c *Client) JSON(ctx context.Context, method, path string, body any, out any) (*Response, error) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	res, err := c.Do(ctx, method, path, "", raw, "")
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return res, errors.New(res.Detail())
	}
	if out != nil {
		if err := json.Unmarshal(res.Body, out); err != nil {
			return res, errors.New("respons API tidak terduga (format JSON tidak sesuai)")
		}
	}
	return res, nil
}
