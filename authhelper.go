package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/Pallinder/go-randomdata"
	"github.com/golang-jwt/jwt/v4"
	"github.com/muir/nfigure"
	"github.com/pkg/browser"
)

// AuthHelperOutput is written to STDOUT as JSON
type AuthHelperOutput struct {
	ExpiresAt          string `json:"expire"`   // RFC3339 format
	PasswordToken      string `json:"password"` // A JWT
	Username           string `json:"username"`
	Email              string `json:"email"`
	ModelVersionNumber int    `json:"modelVersionNumber"`
}

func main() {
	main2(os.Stdout, getConfig())
}

type configData struct {
	BaseURL      string   `flag:"baseURL" default:"https://portal.singlestore.com/engine-sso" help:"override the URL passed to the browser"`
	Email        string   `flag:"email e" validate:"omitempty,validate" help:"users SSO email address, if known"`
	ClusterID    []string `flag:"cluster-id,split=comma" help:"comma-separated list of specific clusters to access"`
	Databases    []string `flag:"databases,split=comma" help:"comma-separated list of specific databases to access"`
	OutputFormat string   `flag:"output o" validate:"oneof=jwt json" default:"jwt" help:"output format (jwt, json)"`
	HangAround   bool     `flag:"hang-around" help:"keep listening even if an invalid request was made"`
	Debug        bool     `flag:"debug d" help:"print the recevied claims"`
}

func getConfig() (config configData) {
	flagFiller := nfigure.PosixFlagHandler(nfigure.WithHelpText(""))
	reg := nfigure.NewRegistry(nfigure.WithFiller("flag", flagFiller))
	err := reg.Request(&config)
	if err != nil {
		panic(err.Error())
	}
	err = reg.Configure()
	if err != nil {
		panic(err.Error())
	}
	return
}

func main2(stdout io.Writer, config configData) {
	path := "/" + randomdata.Alphanumeric(20)

	var wg sync.WaitGroup
	wg.Add(1)

	// Using httptest since it takes care of picking a random port
	var svr *httptest.Server
	svr = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := handle(w, r, svr, stdout, path, config)
		if done || !config.HangAround {
			wg.Done()
		}
	}))

	svr.Start()

	browser.Stdout = browser.Stderr

	values := url.Values{}
	values["returnTo"] = []string{svr.URL + path}
	if config.Email != "" {
		values["email"] = []string{config.Email}
	}
	if len(config.ClusterID) != 0 {
		values["cluster"] = config.ClusterID
	}
	if len(config.Databases) != 0 {
		values["db"] = config.Databases
	}
	url := config.BaseURL + "?" + values.Encode()
	err := browser.OpenURL(url)
	if err != nil {
		panic("Could not open browser: " + err.Error())
	}

	wg.Wait()

	svr.Close()
}

type Claims struct {
	jwt.RegisteredClaims
	Email    string `json:"email"`
	Username string `json:"username"`
}

func (c Claims) Valid() error {
	err := c.RegisteredClaims.Valid()
	if err != nil {
		return err
	}
	if c.Subject == "" && c.Username == "" {
		return fmt.Errorf("Missing 'sub' and 'username' in claims")
	}
	if c.Email == "" {
		return fmt.Errorf("Missing 'email' in claims")
	}
	if !c.VerifyExpiresAt(time.Now().Add(time.Minute), true) {
		return fmt.Errorf("Invalid/missing 'exp' in claims")
	}
	return nil
}

func handle(w http.ResponseWriter, r *http.Request, svr *httptest.Server, stdout io.Writer, path string, config configData) (result bool) {
	defer func() {
		if !result && config.OutputFormat == "json" && !config.HangAround {
			fmt.Fprintln(stdout, "{}")
		}
	}()
	w.Header().Set("Access-Control-Allow-Origin", "*")
	defer r.Body.Close()
	if r.Method != "POST" {
		http.Error(w, "POST expected", 400)
		return false
	}
	switch r.URL.String() {
	case svr.URL + path, path:
		// okay
	default:
		http.Error(w, fmt.Sprintf("route not found: '%s' != '%s'", r.URL.String(), svr.URL+path), 404)
		// http.Error(w, "route not found", 404)
		return false
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Bad read from request: %s", err)
		http.Error(w, "bad read", 500)
		return false
	}
	jwtParser := jwt.NewParser()
	var claims Claims
	_, _, err = jwtParser.ParseUnverified(string(raw), &claims)
	if err != nil {
		log.Printf("Could not parse claims: %s", err)
		http.Error(w, "could not parse claims: "+err.Error(), 400)
		return false
	}
	if config.Debug {
		log.Println("JWT", string(raw))
		enc, err := json.MarshalIndent(claims, "", "  ")
		if err == nil {
			log.Println("Claims", string(enc))
		}
	}
	if err := claims.Valid(); err != nil {
		log.Printf("Could not parse claims: %s", err)
		http.Error(w, "could not parse claims: "+err.Error(), 400)
		return false
	}
	var username string
	if claims.Username != "" {
		username = claims.Username
	} else {
		username = claims.Subject
	}
	switch config.OutputFormat {
	case "jwt":
		fmt.Fprintln(stdout, string(raw))
	case "json":
		output := AuthHelperOutput{
			ExpiresAt:          claims.ExpiresAt.Format(time.RFC3339),
			PasswordToken:      string(raw),
			Email:              claims.Email,
			Username:           username,
			ModelVersionNumber: 1,
		}
		enc, err := json.Marshal(output)
		if err != nil {
			log.Printf("Could not marshal output: %s", err)
			http.Error(w, "could not marshal output "+err.Error(), 500)
			return false
		}
		fmt.Fprintln(stdout, string(enc))
	default:
		panic("unreachable")
	}
	w.WriteHeader(204)
	return true
}
