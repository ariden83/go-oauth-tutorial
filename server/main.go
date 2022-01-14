package main

import (
	"encoding/json"
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
	guuid "github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"log"
	"net/http"
	"time"
	"html/template"
)

var (
	clientID     string = uuid.New().String()[:8]
	clientSecret string = uuid.New().String()[:8]
)

const (
	sessionLabelUserID string = "LoggedInUserID"
)
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

	clientStore := store.NewClientStore()
	clientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: clientSecret,
		Domain: "http://127.0.0.1:9096",
	})

	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	/* if you want to force delay before token expire
	srv.SetAccessTokenExpHandler(func(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error) {
		return time.Duration(60 * time.Second), nil
	})
	*/

	// if you want to set a specific delay for token expiration
	/*srv.SetAccessTokenExpHandler(func(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error) {
		return time.Duration(60 * time.Second), nil
	})*/

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

		userID = uid.(string)
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
	r.HandleFunc("/login", loginHandler)
	// login page call credentials
	r.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		username := r.FormValue("username")
		password := r.FormValue("password")

		fmt.Println(fmt.Sprintf("%s : %s", username, password))
		// call user verification here

		userID := guuid.New().String()
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			return
		}
		store.Set(sessionLabelUserID, userID)
		store.Save()

		/*
			// your pubkey
			clientID := uuid.New().String()[:8]
			// your privateKey
			clientSecret := uuid.New().String()[:8]

			if err := clientStore.Set(clientID, &models.Client{
				ID:     clientID,
				Secret: clientSecret,
				Domain: "http://localhost:9094",
				// UserID: address,
			}); err != nil {
				fmt.Println(err.Error())
			}
		*/

		/* call token or authorize endpoint/ */
		/*
		w.Header().Set("Location", "/token?grant_type=client_credentials"+
			"&client_id="+clientID+
			"&client_secret="+clientSecret+
			"&scope=all")
		*/

		/*w.Header().Set("Location", "/token?grant_type=refresh_token"+
			"&client_id="+clientID+
			"&client_secret="+clientSecret+
			"&refresh_token="+
			"&scope=all")*/

		w.Header().Set("Location", "/authorize?grant_type=client_credentials"+
			"&client_id="+clientID+
			"&client_secret="+clientSecret+
			"&scope=all"+
			"&redirect_uri=http://127.0.0.1:9096/test"+
			"&response_type=token")

		w.WriteHeader(http.StatusFound)
	})

	r.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		req, err := srv.ValidationAuthorizeRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			// err := srv.redirectError(w, req, err)}
			return
		}

		// user authorization
		userID, err := srv.UserAuthorizationHandler(w, r)
		if err != nil {
			//return s.redirectError(w, req, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			// err := srv.redirectError(w, req, err)}
			return
		} else if userID == "" {
			return
		}
		req.UserID = userID

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

		w.Header().Set("Location", "/protected?access_token="+data["access_token"].(string))
		w.WriteHeader(http.StatusFound)
	})

	r.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	r.HandleFunc("/protected", validateToken(func(w http.ResponseWriter, r *http.Request) {
		token, _ := srv.ValidationBearerToken(r)

		w.Header().Set("expires", fmt.Sprintf("%d", int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds())))
		w.Header().Set("access_token", token.GetAccess())
		w.Header().Set("refresh_token", token.GetRefresh())
		w.Header().Set("refresh_expires", fmt.Sprintf("%d", int64(token.GetRefreshCreateAt().Add(token.GetRefreshExpiresIn()).Sub(time.Now()).Seconds())))
		w.Header().Set("token_type", "Bearer")
		w.Header().Set("scope", token.GetScope())

		linkRefreshToken := "/token?grant_type=refresh_token&client_id="+clientID+"&client_secret="+clientSecret+"&refresh_token="+token.GetRefresh()+"&scope=all"

		outputHTML(w,"protected", struct {
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

func loginHandler(w http.ResponseWriter, r *http.Request) {
	outputHTML(w,"login", struct {}{})
}

func outputJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

func outputHTML(w http.ResponseWriter, filename string, data interface{}) {
	t := template.Must(template.ParseFiles("static/"+filename+".tmpl"))
	err := t.Execute(w, data)
	if err != nil {
		panic(err)
	}
}

func validateToken(f http.HandlerFunc, srv *server.Server) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		/*data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}*/
		f.ServeHTTP(w, r)
	})
}
