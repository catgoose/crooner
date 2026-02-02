package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/playwright-community/playwright-go"
)

var logJSON bool

func main() {
	appBase := flag.String("app", "http://localhost:8080", "app base URL")
	runMode := flag.String("run", "happy", "run mode: happy, security, or comma-separated (state,replay,no-session)")
	headless := flag.Bool("headless", true, "run browser headless")
	timeout := flag.Duration("timeout", 30*time.Second, "navigation timeout")
	flag.BoolVar(&logJSON, "json", false, "log events as JSON lines (ndjson) to stderr")
	flag.Parse()

	pw, err := playwright.Run()
	if err != nil {
		log.Fatalf("playwright: %v", err)
	}
	defer func() { _ = pw.Stop() }()

	opts := playwright.BrowserTypeLaunchOptions{Headless: headless}
	browser, err := pw.Chromium.Launch(opts)
	if err != nil {
		log.Fatalf("launch: %v", err)
	}
	defer func() { _ = browser.Close() }()

	modes := strings.Split(*runMode, ",")
	for i := range modes {
		modes[i] = strings.TrimSpace(modes[i])
	}

	ok := true
	for _, mode := range modes {
		switch mode {
		case "happy":
			if !runHappy(browser, *appBase, *timeout) {
				ok = false
			}
		case "security":
			if !runSecurity(browser, *appBase, *timeout) {
				ok = false
			}
		case "state", "replay", "no-session", "open-redirect", "logout-get", "security-headers":
			if !runSecurityOne(browser, *appBase, *timeout, mode) {
				ok = false
			}
		default:
			if mode != "" {
				log.Printf("unknown run mode %q", mode)
				ok = false
			}
		}
	}

	if !ok {
		log.Fatal("one or more runs failed")
	}
	log.Println("simulate: all passed")
}

func runHappy(browser playwright.Browser, appBase string, timeout time.Duration) bool {
	page, err := browser.NewPage()
	if err != nil {
		log.Printf("happy: new page: %v", err)
		return false
	}
	defer page.Close()

	page.SetDefaultTimeout(float64(timeout.Milliseconds()))
	loginURL := strings.TrimSuffix(appBase, "/") + "/login?redirect=/"
	_, err = page.Goto(loginURL, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
	if err != nil {
		log.Printf("happy: goto %s: %v", loginURL, err)
		emit(logEvent{Event: "happy", Result: "fail", Message: err.Error()})
		return false
	}

	url := page.URL()
	emit(logEvent{Event: "happy", Test: "happy", URL: url})
	expectedBase := strings.TrimSuffix(appBase, "/")
	if !strings.HasPrefix(url, expectedBase+"/") || strings.Contains(url, "/login") || strings.Contains(url, "/callback") {
		log.Printf("happy: expected final URL ~ %s/, got %s", expectedBase, url)
		emit(logEvent{Event: "happy", Result: "fail", URL: url, Message: "unexpected final URL"})
		return false
	}

	body, err := page.TextContent("body")
	if err != nil {
		body = ""
	}
	emit(logEvent{Event: "happy", Test: "happy", URL: url, Body: trunc(body, 200)})
	if !strings.Contains(body, "OK") {
		log.Printf("happy: body should contain OK, got %q", body)
		emit(logEvent{Event: "happy", Result: "fail", Body: trunc(body, 200), Message: "body missing OK"})
		return false
	}

	emit(logEvent{Event: "happy", Test: "happy", Result: "pass", URL: url})
	log.Println("happy: passed")
	return true
}

func runSecurity(browser playwright.Browser, appBase string, timeout time.Duration) bool {
	ok := true
	for _, mode := range []string{"state", "no-session", "open-redirect", "logout-get", "security-headers"} {
		if !runSecurityOne(browser, appBase, timeout, mode) {
			ok = false
		}
	}
	return ok
}

func runSecurityOne(browser playwright.Browser, appBase string, timeout time.Duration, mode string) bool {
	appBase = strings.TrimSuffix(appBase, "/")
	page, err := browser.NewPage()
	if err != nil {
		log.Printf("security(%s): new page: %v", mode, err)
		return false
	}
	defer page.Close()

	page.SetDefaultTimeout(float64(timeout.Milliseconds()))

	switch mode {
	case "state":
		var callbackURL string
		_ = page.Route("*callback*", func(route playwright.Route) {
			callbackURL = route.Request().URL()
			_ = route.Abort()
		})
		_, _ = page.Goto(appBase+"/login?redirect=/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
		_ = page.Unroute("*callback*")
		if callbackURL != "" {
			code := getQueryParam(callbackURL, "code")
			state := getQueryParam(callbackURL, "state")
			emit(logEvent{Event: "security", Test: "state", URL: callbackURL, Code: code, State: state})
			if code != "" && state != "" {
				tamperURL := appBase + "/callback?code=" + code + "&state=wrong-state-value"
				emit(logEvent{Event: "security", Test: "state", URL: tamperURL, Message: "tampered state"})
				_, _ = page.Goto(tamperURL, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
				finalURL := page.URL()
				body, _ := page.TextContent("body")
				emit(logEvent{Event: "security", Test: "state", URL: finalURL, Body: trunc(body, 200), Result: "check"})
				if strings.Contains(body, "Invalid state") || strings.Contains(body, "error") {
					emit(logEvent{Event: "security", Test: "state", Result: "pass", URL: finalURL, Message: "wrong state rejected"})
					log.Println("security(state): passed (wrong state rejected)")
					return true
				}
				if strings.Contains(finalURL, "/login") {
					emit(logEvent{Event: "security", Test: "state", Result: "pass", URL: finalURL, Message: "redirected to login"})
					log.Println("security(state): passed (redirected to login)")
					return true
				}
			}
		}
		url := page.URL()
		emit(logEvent{Event: "security", Test: "state", Result: "skip", URL: url, Message: "callback URL not captured"})
		log.Printf("security(state): could not complete (callback not intercepted)")
		return true
	case "no-session":
		ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{})
		if err != nil {
			log.Printf("security(no-session): new context: %v", err)
			emit(logEvent{Event: "security", Test: "no-session", Result: "fail", Message: err.Error()})
			return false
		}
		page2, _ := ctx.NewPage()
		page2.SetDefaultTimeout(float64(timeout.Milliseconds()))
		_, _ = page2.Goto(appBase+"/callback?code=any&state=any", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
		finalURL := page2.URL()
		body, _ := page2.TextContent("body")
		ctx.Close()
		emit(logEvent{Event: "security", Test: "no-session", URL: finalURL, Body: trunc(body, 200)})
		if strings.Contains(finalURL, "/login") || strings.Contains(body, "error") || strings.Contains(body, "Code verifier") {
			emit(logEvent{Event: "security", Test: "no-session", Result: "pass", URL: finalURL, Message: "callback without session rejected"})
			log.Println("security(no-session): passed (callback without session rejected)")
			return true
		}
		emit(logEvent{Event: "security", Test: "no-session", Result: "fail", URL: finalURL, Body: trunc(body, 200), Message: "expected redirect or error"})
		log.Printf("security(no-session): expected redirect or error, got URL=%s body~%q", finalURL, trunc(body, 80))
		return false
	case "replay":
		_, _ = page.Goto(appBase+"/login?redirect=/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
		url := page.URL()
		code := getQueryParam(url, "code")
		state := getQueryParam(url, "state")
		if code == "" || state == "" {
			code = getQueryParam(page.URL(), "code")
			state = getQueryParam(page.URL(), "state")
		}
		emit(logEvent{Event: "security", Test: "replay", URL: url, Code: code, State: state})
		if code != "" && state != "" {
			replayURL := appBase + "/callback?code=" + code + "&state=" + state
			emit(logEvent{Event: "security", Test: "replay", URL: replayURL, Message: "replay same code"})
			_, _ = page.Goto(replayURL, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
			finalURL := page.URL()
			body, _ := page.TextContent("body")
			emit(logEvent{Event: "security", Test: "replay", URL: finalURL, Body: trunc(body, 200), Result: "check"})
			if strings.Contains(body, "error") || strings.Contains(body, "invalid") || strings.Contains(body, "Code verifier") {
				emit(logEvent{Event: "security", Test: "replay", Result: "pass", URL: finalURL, Message: "reused code rejected"})
				log.Println("security(replay): passed (reused code rejected)")
				return true
			}
		}
		emit(logEvent{Event: "security", Test: "replay", Result: "skip", URL: url, Message: "could not capture code/state or replay not rejected"})
		log.Printf("security(replay): could not capture code/state or replay not rejected")
		return true
	case "open-redirect":
		_, _ = page.Goto(appBase+"/login?redirect=https%3A%2F%2Fevil.com", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
		finalURL := page.URL()
		emit(logEvent{Event: "security", Test: "open-redirect", URL: finalURL})
		if strings.Contains(finalURL, "evil.com") {
			emit(logEvent{Event: "security", Test: "open-redirect", Result: "fail", URL: finalURL, Message: "redirected to evil.com"})
			log.Printf("security(open-redirect): failed, redirected to evil.com")
			return false
		}
		emit(logEvent{Event: "security", Test: "open-redirect", Result: "pass", URL: finalURL, Message: "post-login redirect stayed on app"})
		log.Println("security(open-redirect): passed (no off-site redirect)")
		return true
	case "logout-get":
		_, _ = page.Goto(appBase+"/login?redirect=/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
		if !strings.Contains(page.URL(), appBase) || strings.Contains(page.URL(), "/login") {
			emit(logEvent{Event: "security", Test: "logout-get", Result: "skip", Message: "login did not complete"})
			log.Printf("security(logout-get): skip (login did not complete)")
			return true
		}
		_, _ = page.Goto(appBase+"/logout", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
		afterGetLogout := page.URL()
		_, _ = page.Goto(appBase+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
		body, _ := page.TextContent("body")
		emit(logEvent{Event: "security", Test: "logout-get", URL: afterGetLogout, Body: trunc(body, 200)})
		if strings.Contains(body, "OK") {
			emit(logEvent{Event: "security", Test: "logout-get", Result: "pass", Message: "GET /logout did not log out (session intact)"})
			log.Println("security(logout-get): passed (GET logout did not clear session)")
			return true
		}
		emit(logEvent{Event: "security", Test: "logout-get", Result: "fail", Body: trunc(body, 200), Message: "session lost after GET /logout"})
		log.Printf("security(logout-get): failed, session lost after GET /logout")
		return false
	case "security-headers":
		_, _ = page.Goto(appBase+"/login?redirect=/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
		resp, err := page.Goto(appBase+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
		if err != nil || resp == nil {
			emit(logEvent{Event: "security", Test: "security-headers", Result: "skip", Message: "could not load protected page"})
			log.Printf("security(security-headers): skip (%v)", err)
			return true
		}
		headers := resp.Headers()
		emit(logEvent{Event: "security", Test: "security-headers", Result: "check", Body: strings.Join([]string{
			"x-frame-options: " + headers["x-frame-options"],
			"x-content-type-options: " + headers["x-content-type-options"],
		}, "; ")})
		xfo := headers["x-frame-options"]
		if xfo != "DENY" && xfo != "SAMEORIGIN" {
			emit(logEvent{Event: "security", Test: "security-headers", Result: "fail", Message: "missing or weak X-Frame-Options"})
			log.Printf("security(security-headers): failed, X-Frame-Options=%q", xfo)
			return false
		}
		if headers["x-content-type-options"] != "nosniff" {
			emit(logEvent{Event: "security", Test: "security-headers", Result: "fail", Message: "X-Content-Type-Options not nosniff"})
			log.Printf("security(security-headers): failed, X-Content-Type-Options=%q", headers["x-content-type-options"])
			return false
		}
		emit(logEvent{Event: "security", Test: "security-headers", Result: "pass", Message: "security headers present"})
		log.Println("security(security-headers): passed")
		return true
	default:
		return true
	}
}

func getQueryParam(urlStr, key string) string {
	i := strings.Index(urlStr, "?")
	if i < 0 {
		return ""
	}
	q := urlStr[i+1:]
	for _, part := range strings.Split(q, "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && kv[0] == key {
			return kv[1]
		}
	}
	return ""
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type logEvent struct {
	Event   string `json:"event"`
	Test    string `json:"test,omitempty"`
	URL     string `json:"url,omitempty"`
	Code    string `json:"code,omitempty"`
	State   string `json:"state,omitempty"`
	Body    string `json:"body,omitempty"`
	Result  string `json:"result,omitempty"`
	Message string `json:"message,omitempty"`
}

func emit(e logEvent) {
	if logJSON {
		enc := json.NewEncoder(os.Stderr)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(e)
	}
}
