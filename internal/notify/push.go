package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// Gotify and ntfy: the two self-hosted push services, and the two channels most
// likely to be the whole alerting setup on a single-operator install. Neither
// needs an account anywhere.

func sendGotify(ctx context.Context, s *Sender, c conf, ev Event) (Receipt, error) {
	text, err := message(c, "message_template", ev)
	if err != nil {
		return Receipt{}, err
	}

	payload := map[string]any{
		"title":    Title(ev),
		"message":  text,
		"priority": c.num("priority", 5),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Receipt{}, err
	}

	// The token goes in a header rather than the ?token= query parameter Gotify
	// also accepts: a query string ends up in the server's access log, and this
	// one is a credential.
	return s.do(ctx, request{
		url:         strings.TrimRight(c.str("server_url", ""), "/") + "/message",
		contentType: "application/json",
		body:        body,
		headers:     map[string]string{"X-Gotify-Key": c.str("application_token", "")},
		verifyTLS:   true,
	})
}

func sendNtfy(ctx context.Context, s *Sender, c conf, ev Event) (Receipt, error) {
	text, err := message(c, "message_template", ev)
	if err != nil {
		return Receipt{}, err
	}

	payload := map[string]any{
		"topic":    c.str("topic", ""),
		"title":    Title(ev),
		"message":  text,
		"priority": c.num("priority", 3),
	}
	if tags := c.list("tags"); len(tags) > 0 {
		payload["tags"] = tags
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return Receipt{}, err
	}

	// Posted as JSON to the server root rather than as a plain body to /topic:
	// the header form carries the title, and headers are latin-1, so a monitor
	// named in anything but ASCII arrives mangled or rejected.
	headers := map[string]string{}
	switch c.str("auth_type", "none") {
	case "basic":
		credential := c.str("username", "") + ":" + c.str("password", "")
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(credential))
	case "token":
		headers["Authorization"] = "Bearer " + c.str("token", "")
	}

	return s.do(ctx, request{
		url:         strings.TrimRight(c.str("server_url", "https://ntfy.sh"), "/") + "/",
		contentType: "application/json",
		body:        body,
		headers:     headers,
		verifyTLS:   true,
	})
}

// sendPushover delivers a notification through Pushover's API
// (https://pushover.net/api). It posts an application token and a user key
// which together authenticate and route the message — the same pair that
// identifies both sender and recipient.
//
// Pushover's endpoint is https://api.pushover.net/1/messages.json. The
// body is form-encoded, not JSON, matching their documented format.
func sendPushover(ctx context.Context, s *Sender, c conf, ev Event) (Receipt, error) {
	text, err := message(c, "message_template", ev)
	if err != nil {
		return Receipt{}, err
	}

	form := url.Values{}
	form.Set("token", c.str("api_token", ""))
	form.Set("user", c.str("user_key", ""))
	form.Set("title", truncate(Title(ev), 250))
	form.Set("message", text)

	// priority ranges from -2 (lowest) to 2 (emergency). 0 is the neutral
	// default. The field is omitted when the user has not configured it, but
	// explicitly included when set so the value is not silently ignored.
	if p := c.num("priority", 0); p != 0 {
		form.Set("priority", strconv.Itoa(int(p)))
	}
	if sound := c.str("sound", ""); sound != "" {
		form.Set("sound", sound)
	}
	if device := c.str("device", ""); device != "" {
		form.Set("device", device)
	}

	encoded := []byte(form.Encode())
	return s.do(ctx, request{
		url:         "https://api.pushover.net/1/messages.json",
		contentType: "application/x-www-form-urlencoded",
		body:        encoded,
		verifyTLS:   true,
		// The form body contains the api_token and user_key; record only the
		// rendered message so credentials do not appear in the delivery log.
		record: text,
	})
}
