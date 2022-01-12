package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"gopkg.in/oauth2.v3/models"
	"log"
	"net/http"
	"os"

	"github.com/go-session/session"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

var (
	clientID     string = uuid.New().String()[:8]
	clientSecret string = uuid.New().String()[:8]
)

const (
	sessionLabelAddress string = "address"
)

func main() {
	manager := manage.NewDefaultManager()

	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	clientStore := store.NewClientStore()
	clientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: clientSecret,
		Domain: "http://localhostt:9096",
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	// srv.SetPasswordAuthorizationHandler(passwordHandler)
	// srv.SetAllowedGrantType(oauth2.PasswordCredentials)
	/* srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		fmt.Println("************************************** SetUserAuthorizationHandler")
		return "12", nil
	}) */

	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	r := mux.NewRouter()

	r.HandleFunc("/login", loginHandler)

	r.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		username := r.FormValue("username")
		password := r.FormValue("password")

		fmt.Println(fmt.Sprintf("%s : %s", username, password))
		// call user verification here

		address := "my adrress"
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			return
		}
		store.Set(sessionLabelAddress, address)
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

		w.Header().Set("Location", "/token?grant_type=client_credentials&client_id="+clientID+"&client_secret="+clientSecret+"&scope=all")
		w.WriteHeader(http.StatusFound)
	})

	// http.HandleFunc("/auth", authHandler)

	r.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	r.HandleFunc("/protected", validateToken(func(w http.ResponseWriter, r *http.Request) {
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			return
		}

		address, ok := store.Get(sessionLabelAddress)
		if !ok {
			w.Write([]byte("fail to get user address"))
			return
		}

		w.Write([]byte("Hello, I'm protected, and my address is" + address.(string)))
	}, srv))

	log.Println("Server is running at 9096 port.")

	corsWrapper := cors.New(cors.Options{
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Origin", "Accept", "*"},
	})

	log.Fatal(http.ListenAndServe(":9096", corsWrapper.Handler(r)))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	outputHTML(w, r, "static/login.html")
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}

func validateToken(f http.HandlerFunc, srv *server.Server) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Println(fmt.Sprintf("userID :: %+v", data.GetUserID()))

		f.ServeHTTP(w, r)
	})
}
