package main

import (
	"fmt"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"
)

/*
var (
	clientID     string = uuid.New().String()[:8]
	clientSecret string = uuid.New().String()[:8]
)*/

const (
	sessionLabelUserID       string = "LoggedInUserID"
	sessionLabelAccessToken  string = "LoggedAccessToken"
	sessionLabelRefreshToken string = "LoggedRefreshToken"
)

type Address string

func (a Address) String() string {
	return string(a)
}

type userData struct {
	clientID     string
	clientSecret string
	address      Address
	name         string
	email        string
	password     string
}

var database = map[Address]userData{
	"address 1": {
		clientID:     uuid.New().String()[:8],
		clientSecret: uuid.New().String()[:8],
		address:      "address 1",
		name:         "adrien",
		email:        "adrienparrochia@gmail.com",
		password:     "toto",
	},
	"address 2": {
		clientID:     uuid.New().String()[:8],
		clientSecret: uuid.New().String()[:8],
		address:      "address 2",
		name:         "adrien+2",
		email:        "adrienparrochia+2@gmail.com",
		password:     "toto",
	},
	"address 3": {
		clientID:     uuid.New().String()[:8],
		clientSecret: uuid.New().String()[:8],
		address:      "address 3",
		name:         "adrien+3",
		email:        "adrienparrochia+3@gmail.com",
		password:     "toto",
	},
}

// https://github.com/go-oauth2/oauth2/blob/b208c14e621016995debae2fa7dc20c8f0e4f6f8/example/server/server.go
// https://github.com/go-oauth2/oauth2/blob/fa969a085ba42725f9b957c744ec5ba6d548b4ab/manage/manage_test.go
func main() {
	manager := manage.NewDefaultManager()

	manager.SetAuthorizeCodeExp(time.Minute * 10)
	manager.SetPasswordTokenCfg(manage.DefaultPasswordTokenCfg)
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)
	manager.SetClientTokenCfg(manage.DefaultClientTokenCfg)
	manager.SetImplicitTokenCfg(&manage.Config{AccessTokenExp: time.Hour * 2, RefreshTokenExp: time.Hour * 24 * 7, IsGenerateRefresh: true})

	manager.MustTokenStorage(store.NewMemoryTokenStore())
	// generate jwt access token
	// manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	// you can (un)comment this to set a user specific client ID
	clientStore := store.NewClientStore()
	/*clientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: clientSecret,
		// Domain: "http://127.0.0.1:9096",
	})*/
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	/* if you want to force delay before token expire
	srv.SetAccessTokenExpHandler(func(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error) {
		return time.Duration(60 * time.Second), nil
	})
	*/

	srv.SetRefreshingValidationHandler(func(ti oauth2.TokenInfo) (allowed bool, err error) {
		return true, nil
	})

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			return
		}

		uid, ok := store.Get(sessionLabelUserID)
		if !ok {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
			return
		}

		userID = uid.(Address).String()
		store.Delete(sessionLabelUserID)
		store.Save()
		return
	})

	/*
		srv.SetPasswordAuthorizationHandler(func(username, password string) (userID string, err error) {
			fmt.Println("************************************** SetPasswordAuthorizationHandler")
			if username == "test" && password == "test" {
				userID = "test"
			}
			return
		})
	*/

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})
	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	r := mux.NewRouter()
	// login page
	r.HandleFunc("/login", hasValidToken(func(w http.ResponseWriter, r *http.Request) {
		outputHTML(w, "login", struct{}{})
	}, srv))
	// login page call credentials
	r.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		email := r.FormValue("email")
		password := r.FormValue("password")

		userData := getUserDataWithLogin(email, password)
		if userData == nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		// call user verification here
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			return
		}
		store.Set(sessionLabelUserID, userData.address)
		store.Save()

		if err := clientStore.Set(userData.clientID, &models.Client{
			ID:     userData.clientID,
			Secret: userData.clientSecret,
			// Domain: "http://localhost:9094",
		}); err != nil {
			fmt.Println(err.Error())
		}
		/* call token or authorize endpoint/ */
		/*w.Header().Set("Location", "/token")*/
		w.Header().Set("Location", "/authorize")
		w.WriteHeader(http.StatusFound)
	})

	r.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		parm := r.Form
		if parm == nil {
			parm = url.Values{}
		}

		// user authorization
		address, err := srv.UserAuthorizationHandler(w, r)
		if err != nil {
			//return s.redirectError(w, req, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			// err := srv.redirectError(w, req, err)}
			return
		} else if address == "" {
			w.Header().Set("Location", "/login")
			return
		}

		userData := getUserDataWithAddress(address)

		parm.Add("grant_type", "client_credentials")
		parm.Add("client_id", userData.clientID)
		parm.Add("client_secret", userData.clientSecret)
		parm.Add("scope", "all")
		parm.Add("response_type", "token")

		r.Form = parm

		req, err := srv.ValidationAuthorizeRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			// err := srv.redirectError(w, req, err)}
			return
		}
		req.UserID = address

		// specify the scope of authorization
		if fn := srv.AuthorizeScopeHandler; fn != nil {
			scope, err := fn(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			} else if scope != "" {
				req.Scope = scope
			}
		}

		// specify the expiration time of access token
		if fn := srv.AccessTokenExpHandler; fn != nil {
			exp, err := fn(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			req.AccessTokenExp = exp
		}

		ti, err := srv.GetAuthorizeToken(ctx, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// If the redirect URI is empty, the default domain provided by the client is used.
		if req.RedirectURI == "" {
			client, err := srv.Manager.GetClient(ctx, req.ClientID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			req.RedirectURI = client.GetDomain()
		}

		data := srv.GetAuthorizeData(req.ResponseType, ti)

		/*  outputJSON(data) */
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			return
		}
		store.Set(sessionLabelAccessToken, data["access_token"].(string))
		store.Set(sessionLabelRefreshToken, data["refresh_token"].(string))
		store.Save()

		w.Header().Set("Location", "/protected")
		w.WriteHeader(http.StatusFound)
	})

	r.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := refreshToken(srv, w, r); err != nil {
			_, statusCode, _ := srv.GetErrorData(err)
			http.Error(w, err.Error(), statusCode)
			return
		}
		w.Header().Set("Location", "/protected")
		w.WriteHeader(http.StatusFound)
	})

	r.HandleFunc("/protected", validateToken(func(w http.ResponseWriter, r *http.Request) {
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		accessToken, _ := store.Get(sessionLabelAccessToken)
		token, err := srv.Manager.LoadAccessToken(r.Context(), accessToken.(string))
		if err != nil {
			return
		}

		/* juste pour info, mais inutile de les retourner
		w.Header().Set("expires", fmt.Sprintf("%d", int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds())))
		w.Header().Set("access_token", token.GetAccess())
		w.Header().Set("refresh_token", token.GetRefresh())
		w.Header().Set("refresh_expires", fmt.Sprintf("%d", int64(token.GetRefreshCreateAt().Add(token.GetRefreshExpiresIn()).Sub(time.Now()).Seconds())))
		w.Header().Set("token_type", "Bearer")
		w.Header().Set("scope", token.GetScope())
		 */
		w.Header().Set("cache-control", "no-cache,no-store")
		w.Header().Set("Pragma", "no-cache")

		linkRefreshToken := "/token"

		outputHTML(w, "protected", struct {
			User string
			Link string
		}{
			User: token.GetUserID(),
			Link: linkRefreshToken,
		})
	}, srv))

	log.Println("Server is running at 9096 port.")

	corsWrapper := cors.New(cors.Options{
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Origin", "Accept", "*"},
	})

	log.Fatal(http.ListenAndServe(":9096", corsWrapper.Handler(r)))
}

/* inutile avec ce code
func outputJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("cache-control", "no-cache,no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}*/

func outputHTML(w http.ResponseWriter, filename string, data interface{}) {
	t := template.Must(template.ParseFiles("static/" + filename + ".tmpl"))
	err := t.Execute(w, data)
	if err != nil {
		panic(err)
	}
}

func hasValidToken(f http.HandlerFunc, srv *server.Server) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			return
		}
		accessToken, ok := store.Get(sessionLabelAccessToken)
		// si pas de token, on reste sur la page
		if !ok {
			f.ServeHTTP(w, r)
			return
		}
		// si token valide, on change de page
		if _, err := srv.Manager.LoadAccessToken(r.Context(), accessToken.(string)); err == nil {
			w.Header().Set("Location", "/protected")
			w.WriteHeader(http.StatusFound)
			return
		}
		// on reste sur la page
		f.ServeHTTP(w, r)
	})
}

func validateToken(f http.HandlerFunc, srv *server.Server) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		accessToken, ok := store.Get(sessionLabelAccessToken)
		if !ok {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		if _, err := srv.Manager.LoadAccessToken(r.Context(), accessToken.(string)); err != nil {
			// try to refresh token
			if err = refreshToken(srv, w, r); err != nil {
				w.Header().Set("Location", "/login")
				w.WriteHeader(http.StatusFound)
				return
			}
		}
		/*data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}*/
		f.ServeHTTP(w, r)
	})
}

func refreshToken(srv *server.Server, w http.ResponseWriter, r *http.Request) error {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return err
	}
	refreshToken, ok := store.Get(sessionLabelRefreshToken)
	if !ok {
		return err
	}

	rti, err := srv.Manager.LoadRefreshToken(r.Context(), refreshToken.(string))
	if err != nil {
		return err
	}
	userData := getUserDataWithAddress(rti.GetUserID())

	parm := r.Form
	if parm == nil {
		parm = url.Values{}
	}
	parm.Add("refresh_token", refreshToken.(string))
	parm.Add("grant_type", oauth2.Refreshing.String())
	parm.Add("client_id", userData.clientID)
	parm.Add("client_secret", userData.clientSecret)
	parm.Add("scope", "all")

	r.Form = parm

	ctx := r.Context()

	gt, tgr, err := srv.ValidationTokenRequest(r)
	if err != nil {
		return err
	}

	ti, err := srv.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		return err
	}

	data := srv.GetTokenData(ti)
	store.Set(sessionLabelAccessToken, data["access_token"].(string))
	store.Set(sessionLabelRefreshToken, data["refresh_token"].(string))
	store.Save()
	return nil
}

// func for simulate database

func getUserDataWithLogin(email, password string) *userData {
	for _, s := range database {
		if s.email == email && s.password == password {
			return &s
		}
	}
	return nil
}

func getUserDataWithAddress(ad string) *userData {
	for a, data := range database {
		if a == Address(ad) {
			return &data
		}
	}
	return nil
}
