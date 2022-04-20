//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly
// +build linux darwin freebsd netbsd openbsd dragonfly

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
	testAuthHelper(t, "json")
}

func TestAuthHelperJWT(t *testing.T) {
	testAuthHelper(t, "jwt")
}

func TestAuthHelperDefault(t *testing.T) {
	testAuthHelper(t, "")
}

func testAuthHelper(t *testing.T, format string) {
	dir, err := os.MkdirTemp("", "ahtest")
	require.NoError(t, err, "mktmp")
	defer os.RemoveAll(dir)

	script := fmt.Sprintf(`#!/bin/sh
echo "$*" > %s/.args.$$
mv %s/.args.$$ %s/args.$$
`, dir, dir, dir)

	err = os.WriteFile(dir+"/xdg-open", []byte(script), 0755)
	require.NoError(t, err, "write script")

	os.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err, "new watcher")
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
						watchResults <- fakeBrowser(t, string(raw))
					}
					return
				}
			case err := <-watcher.Errors:
				if err != nil {
					watchResults <- err
				}
				watchResults <- fmt.Errorf("watcher errors closed")
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
		var jwtString string
		switch format {
		case "json":
			err = json.Unmarshal(buf.Bytes(), &output)
			require.NoErrorf(t, err, "unmarshal output from helper")

			assert.Equal(t, 1, output.ModelVersionNumber, "model version number")
			assert.Equal(t, "foo@example.com", output.Email, "email")
			assert.Less(t, time.Now().Format(time.RFC3339), output.ExpiresAt, "expires")

			jwtString = output.PasswordToken
		case "", "jwt":
			jwtString = string(buf.Bytes())
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

func fakeBrowser(t *testing.T, us string) error {
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": "foo@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("a secret"))
	if err != nil {
		return fmt.Errorf("sign token %w", err)
	}

	t.Logf("POST token to %s", returnTo)
	resp, err := http.Post(returnTo, "text/plain", strings.NewReader(tokenString))
	if err != nil {
		return fmt.Errorf("POST to %s error: %w", returnTo, err)
	}
	defer resp.Body.Close()
	bod, _ := io.ReadAll(resp.Body)
	if len(bod) != 0 {
		t.Log("Recevied response:", string(bod))
	}
	if resp.StatusCode != 204 {
		return fmt.Errorf("POST to %s response code %d", returnTo, resp.StatusCode)
	}
	return nil
}
