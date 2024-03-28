package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

type UaaConfig struct {
	UaaClientId     string
	UaaClientSecret string
	BaseUrl         string
	AuthUrl         string
}

func getUaaConfig() UaaConfig {
	return UaaConfig{
		UaaClientId:     os.Getenv("UAA_CLIENT_ID"),
		UaaClientSecret: os.Getenv("UAA_CLIENT_SECRET"),
		BaseUrl:         os.Getenv("UAA_BASE_URL"),
		AuthUrl:         os.Getenv("UAA_AUTH_URL"),
	}
}

func getOauthConfig(uaaConfig UaaConfig) *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "http://localhost:3000/auth/cloudfoundry/callback",
		ClientID:     uaaConfig.UaaClientId,
		ClientSecret: uaaConfig.UaaClientSecret,
		Scopes:       []string{""},
		Endpoint: oauth2.Endpoint{
			TokenURL:  fmt.Sprintf("%s/oauth/token", uaaConfig.BaseUrl),
			AuthURL:   uaaConfig.AuthUrl,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func getUserData(code string) (map[string]interface{}, error) {
	uaaConfig := getUaaConfig()
	conf := getOauthConfig(uaaConfig)

	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	// log.Printf("token: %s", token)

	client := conf.Client(context.Background(), token)
	resp, err := client.Get(fmt.Sprintf("%s/userinfo", uaaConfig.BaseUrl))
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %s", err.Error())
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}

	var userInfo map[string]interface{}
	json.Unmarshal(data, &userInfo)
	return userInfo, nil
}

func oauthCfLogin(w http.ResponseWriter, r *http.Request) {
	conf := getOauthConfig(getUaaConfig())
	oauthState := generateStateOauthCookie(w)
	url := conf.AuthCodeURL(oauthState, oauth2.AccessTypeOffline)

	log.Printf("Redirecting to %s", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func test(w http.ResponseWriter, r *http.Request) {
	oauthCfLogin(w, r)
}

func oauthCfCallback(w http.ResponseWriter, r *http.Request) {
	log.Print("Reached callback")

	// Read oauthState from Cookie
	oauthState, err := r.Cookie("oauthstate")
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	userInfo, err := getUserData(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Fprintf(w, "user info: %s\n", userInfo)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	mux := http.NewServeMux()

	testHanlder := http.HandlerFunc(test)
	mux.Handle("/", testHanlder)

	mux.HandleFunc("/auth/cloudfoundry/login", oauthCfLogin)
	mux.HandleFunc("/auth/cloudfoundry/callback", oauthCfCallback)

	log.Print("Listening on http://localhost:3000")
	err = http.ListenAndServe(":3000", mux)
	if err != nil {
		log.Fatal(err)
	}
}
