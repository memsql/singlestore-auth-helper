//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

// linux darwin freebsd netbsd openbsd dragonfly

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthHelperJSON(t *testing.T) {
	cases := []struct {
		name   string
		want   string
		claims jwt.MapClaims
		code   int
	}{
		{
			name: "sub over email",
			want: "foosubject",
			claims: jwt.MapClaims{
				"email": "foo@example.com",
				"sub":   "foosubject",
			},
		},
		{
			name: "username over sub",
			want: "fooperson",
			claims: jwt.MapClaims{
				"username": "fooperson",
				"email":    "foo@example.com",
				"sub":      "foosubject",
			},
		},
		{
			name: "no sub no username",
			want: "",
			claims: jwt.MapClaims{
				"email": "foo@example.com",
			},
			code: 400,
		},
		{
			name: "no email",
			want: "",
			claims: jwt.MapClaims{
				"username": "fooperson",
			},
			code: 400,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testAuthHelper(t, "json", tc.code, tc.want, tc.claims)
			testAuthHelper(t, "cnf", tc.code, tc.want, tc.claims)
			testAuthHelper(t, "userpass", tc.code, tc.want, tc.claims)
		})
	}
}

func TestAuthHelperJWT(t *testing.T) {
	testAuthHelper(t, "jwt", 0, "", jwt.MapClaims{
		"email": "foo@example.com",
		"sub":   "foo",
	})
}

func TestAuthHelperDefault(t *testing.T) {
	testAuthHelper(t, "", 0, "", jwt.MapClaims{
		"email": "foo@example.com",
		"sub":   "foo",
	})
}

func testAuthHelper(t *testing.T, format string, httpError int, expectedUsername string, baseClaims jwt.MapClaims) {
	dir, err := os.MkdirTemp("", "ahtest")
	require.NoError(t, err, "mktmp")
	//nolint:errcheck // ignore error from RemoveAll
	defer os.RemoveAll(dir)

	script := fmt.Sprintf(`#!/bin/sh
echo "$*" > %s/.args.$$
mv %s/.args.$$ %s/args.$$
`, dir, dir, dir)

	err = os.WriteFile(dir+"/xdg-open", []byte(script), 0o755)
	require.NoError(t, err, "write script")

	err = os.WriteFile(dir+"/open", []byte(script), 0o755)
	require.NoError(t, err, "write script")

	err = os.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	require.NoError(t, err)

	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err, "new watcher")
	//nolint:errcheck // ignore error from Close
	defer watcher.Close()

	watchResults := make(chan error)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					watchResults <- fmt.Errorf("watcher events closed")
					return
				}
				if event.Op&fsnotify.Create == fsnotify.Create {
					if strings.HasPrefix(filepath.Base(event.Name), ".") {
						t.Logf("Watcher says file %s was created, but we're not intersted in that", event.Name)
						continue
					}
					t.Logf("Watcher says file %s was created", event.Name)
					raw, err := os.ReadFile(event.Name)
					if err != nil {
						watchResults <- err
					} else {
						watchResults <- fakeBrowser(t, string(raw), baseClaims, httpError)
					}
					return
				}
			case err := <-watcher.Errors:
				if err != nil {
					watchResults <- err
				}
				watchResults <- fmt.Errorf("watcher errors closed")
				return
			case <-time.After(10 * time.Second):
				watchResults <- fmt.Errorf("no useful watcher event after 10 seconds")
				return
			}
		}
	}()
	t.Logf("Watcher on %s started", dir)
	err = watcher.Add(dir)
	require.NoError(t, err, "add watcher directory")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		t.Log("watch results wait finished")
		assert.NoError(t, <-watchResults, "watch results error")
	}()
	go func() {
		defer wg.Done()
		t.Log("Starting auth helper")
		var buf bytes.Buffer
		var args []string
		if format != "" {
			args = append(args, "-o", format)
		}
		main2(&buf, lockedGetConfig(args...))

		var output AuthHelperOutput
		t.Log("auth helper output", buf.String())

		if httpError == 0 {
			var jwtString string
			switch format {
			case "json":
				err = json.Unmarshal(buf.Bytes(), &output)
				require.NoErrorf(t, err, "unmarshal output from helper")

				assert.Equal(t, 1, output.ModelVersionNumber, "model version number")
				if e, ok := baseClaims["email"]; ok {
					assert.Equal(t, e.(string), output.Email, "email")
				}
				assert.Less(t, time.Now().Format(time.RFC3339), output.ExpiresAt, "expires")
				assert.Equal(t, expectedUsername, output.Username, "username")

				jwtString = output.PasswordToken
			case "", "jwt":
				jwtString = buf.String()
			case "cnf":
				lines := strings.Split(buf.String(), "\n")
				outputUser := strings.TrimSpace(lines[1][strings.Index(lines[1], "user=")+len("user="):])
				assert.Equal(t, expectedUsername, outputUser, "cnf username")
				jwtString = strings.TrimSpace(lines[2][len("password="):])
			case "userpass":
				outputUser := strings.SplitN(strings.TrimSpace(buf.String()), " ", 2)[0]
				assert.Equal(t, expectedUsername, outputUser, "userpass username")
				jwtString = strings.TrimSpace(buf.String())[strings.Index(buf.String(), " ")+1:]
			default:
				assert.Fail(t, "unexpected format")
			}
			var mapClaims jwt.MapClaims
			_, err := jwt.ParseWithClaims(jwtString, &mapClaims, func(token *jwt.Token) (interface{}, error) {
				return []byte("a secret"), nil
			})
			if assert.NoError(t, err, "decode token in output") {
				assert.Equal(t, "foo@example.com", mapClaims["email"], "email in token")
			}
		} else {
			if format == "json" {
				assert.Equal(t, "{}\n", buf.String(), "empty JSON expected")
			} else {
				assert.Equal(t, "", buf.String(), "no output expected")
			}
		}
	}()
	wg.Wait()
}

var configLock sync.Mutex

// locked because we modify a global: os.Args
func lockedGetConfig(args ...string) configData {
	configLock.Lock()
	defer configLock.Unlock()
	argsCopy := make([]string, len(os.Args))
	copy(argsCopy, os.Args)
	defer func() {
		os.Args = argsCopy
	}()
	os.Args = append([]string{os.Args[0]}, args...)
	return getConfig()
}

func fakeBrowser(t *testing.T, us string, claims jwt.MapClaims, httpError int) error {
	us = strings.TrimSuffix(us, "\n")
	t.Logf("Browser invoked with %s", us)
	config := lockedGetConfig()
	if !strings.HasPrefix(us, config.BaseURL) {
		return fmt.Errorf("url does not start with base url: %s", us)
	}
	u, err := url.Parse(us)
	if err != nil {
		return fmt.Errorf("parse url %s: %w", us, err)
	}

	returnTo := u.Query().Get("returnTo")
	if returnTo == "" {
		return fmt.Errorf("no returnTo in URL %s", us)
	}

	claims["exp"] = time.Now().Add(time.Hour).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("a secret"))
	if err != nil {
		return fmt.Errorf("sign token %w", err)
	}

	t.Logf("POST token to %s", returnTo)
	optionsRequest, err := http.NewRequest(http.MethodOptions, returnTo, strings.NewReader(""))
	if err != nil {
		return fmt.Errorf("OPTIONS NewRequest %s error: %w", returnTo, err)
	}
	optionsResponse, err := http.DefaultClient.Do(optionsRequest)
	if err != nil {
		return fmt.Errorf("OPTIONS response to %s error: %w", returnTo, err)
	}
	allow := optionsResponse.Header.Get("Allow")
	if allow != http.MethodPost {
		return fmt.Errorf("invalid OPTIONS response to %s: %s", returnTo, allow)
	}
	resp, err := http.Post(returnTo, "text/plain", strings.NewReader(tokenString))
	if err != nil {
		return fmt.Errorf("POST to %s error: %w", returnTo, err)
	}
	//nolint:errcheck // ignore error from Close
	defer resp.Body.Close()
	bod, _ := io.ReadAll(resp.Body)
	if len(bod) != 0 {
		t.Log("Recevied response:", string(bod))
	}
	if httpError != 0 {
		if resp.StatusCode != httpError {
			return fmt.Errorf("POST to %s response code %d", returnTo, resp.StatusCode)
		}
	} else if resp.StatusCode != 204 {
		return fmt.Errorf("POST to %s response code %d", returnTo, resp.StatusCode)
	}
	return nil
}
