package prompt

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"code.google.com/p/xsrftoken"
	"github.com/medium/medium-sdk-go"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/memcache"
	"google.golang.org/appengine/urlfetch"
)

func init() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/write", mediumLoginRequired(handleWrite))
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/_cb", handleCallback)
	http.HandleFunc("/_create", mediumLoginRequired(handleCreate))
}

type appConfig struct {
	ClientID, ClientSecret, CallbackURL, XSRFKey string
}

type userInfo struct {
	User        medium.User        `json:"user"`
	AccessToken medium.AccessToken `json:"-"`
}

type contextKey int

const userKey contextKey = 0

type handlerFuncWithContext func(ctx context.Context, w http.ResponseWriter, r *http.Request)

func mediumLoginRequired(handlerFunc handlerFuncWithContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)

		unameCookie, err := r.Cookie("username")
		if err != nil {
			log.Infof(ctx, "couldn't get username cookie")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		key := userInfoKey(ctx, unameCookie.Value)
		if key == nil {
			log.Infof(ctx, "couldn't create user info key")
			http.Redirect(w, r, "/logout", http.StatusSeeOther)
			return
		}
		var info userInfo
		if err := datastore.Get(ctx, key, &info); err != nil {
			log.Infof(ctx, "couldn't get user from datastore: %v", err)
			http.Redirect(w, r, "/logout", http.StatusSeeOther)
			return
		}
		ctx = context.WithValue(ctx, userKey, info)
		handlerFunc(ctx, w, r)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "username",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	unameCookie, err := r.Cookie("username")
	if err == nil && len(unameCookie.Value) > 0 {
		http.Redirect(w, r, "/write", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := template.ParseFiles("./templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := t.Execute(w, nil); err != nil {
		log.Errorf(ctx, "unable to execute template: %v", err)
		return
	}
}

func handleWrite(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	info, ok := ctx.Value(userKey).(userInfo)
	if !ok {
		http.Error(w, "could not get user from context", http.StatusInternalServerError)
		return
	}

	appConfig, err := getAppConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	xsrf := xsrftoken.Generate(appConfig.XSRFKey, info.User.ID, "POST")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	userJSON, err := json.Marshal(info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t, err := template.ParseFiles("./templates/write.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmplData := struct {
		UserJSON        template.JS
		XSRFToken       string
		PromptText      string
		PlaceholderText string
	}{
		UserJSON:        template.JS(userJSON),
		XSRFToken:       xsrf,
		PromptText:      "What’s the fastest way to make a situation awkward?",
		PlaceholderText: "Put prose here",
	}
	if err := t.Execute(w, tmplData); err != nil {
		log.Errorf(ctx, "unable to execute template: %v", err)
		return
	}
}

func handleCreate(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	info, ok := ctx.Value(userKey).(userInfo)
	if !ok {
		http.Error(w, "could not get user from context", http.StatusInternalServerError)
		return
	}
	appConfig, err := getAppConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token := r.Header.Get("X-XSRF-Token")
	if !xsrftoken.Valid(token, appConfig.XSRFKey, info.User.ID, "POST") {
		http.Error(w, "bad xsrf token", http.StatusUnauthorized)
		return
	}

	client := medium.NewClient(appConfig.ClientID, appConfig.ClientSecret)
	client.AccessToken = info.AccessToken.AccessToken
	client.Timeout = 0
	client.Transport = &urlfetch.Transport{Context: ctx}

	var reqJSON struct {
		Title, Content string
	}

	if err := json.NewDecoder(r.Body).Decode(&reqJSON); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.Body.Close()

	content := "# " + reqJSON.Title
	content += "\n\n" + reqJSON.Content

	post, err := client.CreatePost(medium.CreatePostOptions{
		UserID:        info.User.ID,
		Title:         reqJSON.Title,
		Content:       content,
		ContentFormat: medium.ContentFormatMarkdown,
		PublishStatus: medium.PublishStatusDraft,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(post); err != nil {
		log.Errorf(ctx, "could not encode response: %v", err)
		return
	}
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		t, err := template.ParseFiles("./templates/admin.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		info, err := getAppConfig(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := t.Execute(w, info); err != nil {
			log.Errorf(ctx, "unable to execute template: %v", err)
			return
		}
	} else if r.Method == "POST" {
		info := appConfig{
			ClientID:     r.FormValue("clientID"),
			ClientSecret: r.FormValue("clientSecret"),
			CallbackURL:  r.FormValue("callbackURL"),
			XSRFKey:      r.FormValue("xsrfKey"),
		}
		if _, err := datastore.Put(ctx, appConfigKey(ctx), &info); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, r.URL.String(), http.StatusSeeOther)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	info, err := getAppConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := medium.NewClient(info.ClientID, info.ClientSecret)
	state, err := genKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	item := &memcache.Item{
		Key:        state,
		Value:      []byte{},
		Expiration: 5 * time.Minute,
	}
	if err := memcache.Add(ctx, item); err == memcache.ErrNotStored {
		http.Error(w, fmt.Sprintf("item with key %q already exists", state),
			http.StatusInternalServerError)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authURL := client.GetAuthorizationURL(state, info.CallbackURL,
		medium.ScopeBasicProfile, medium.ScopePublishPost)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	var (
		state = r.FormValue("state")
		code  = r.FormValue("code")
	)
	if _, err := memcache.Get(ctx, state); err != nil {
		log.Errorf(ctx, "could not find state %q in memcache: %v", state, err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := memcache.Delete(ctx, state); err != nil {
		log.Errorf(ctx, "could not delete state %q in memcache: %v", state, err)
	}

	info, err := getAppConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := medium.NewClient(info.ClientID, info.ClientSecret)
	client.Timeout = 0
	client.Transport = &urlfetch.Transport{Context: ctx}

	accessToken, err := client.ExchangeAuthorizationCode(code, info.CallbackURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user, err := client.GetUser()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	uinfo := userInfo{
		User:        *user,
		AccessToken: accessToken,
	}
	if _, err := datastore.Put(ctx, userInfoKey(ctx, user.Username), &uinfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	http.SetCookie(w, &http.Cookie{
		Name:     "username",
		Value:    user.Username,
		Expires:  time.Unix(accessToken.ExpiresAt/1000, 0),
		HttpOnly: true,
		Secure:   true,
	})
	http.Redirect(w, r, "/write", http.StatusSeeOther)
}

func userInfoKey(ctx context.Context, username string) *datastore.Key {
	return datastore.NewKey(ctx, "userInfo", username, 0, nil)
}

func appConfigKey(ctx context.Context) *datastore.Key {
	return datastore.NewKey(ctx, "appConfig", "appconfig", 0, nil)
}

func genKey() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func getAppConfig(ctx context.Context) (*appConfig, error) {
	key := appConfigKey(ctx)
	if key == nil {
		return nil, errors.New("could not create `appconfig` key")
	}
	var config appConfig
	if err := datastore.Get(ctx, key, &config); err != nil && err != datastore.ErrNoSuchEntity {
		return nil, err
	}
	return &config, nil
}
