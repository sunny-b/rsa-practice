package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

var secretMessage = []byte("Hello from the other side!")

type request struct {
	PublicKey string `json:"public_key,omitempty"`
}

type response struct {
	EncryptedMessage string `json:"encrypted_message,omitempty"`
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/message", sendEncryptedMessage).Methods(http.MethodPost)

	srv := &http.Server{
		Handler:      r,
		Addr:         ":80",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Info("Starting server, listening on port 80")

	log.Fatal(srv.ListenAndServe())
}

func sendEncryptedMessage(w http.ResponseWriter, r *http.Request) {
	logToConsole("received request")

	parsedReq := &request{}
	json.NewDecoder(r.Body).Decode(parsedReq)

	defer r.Body.Close()

	sleep()

	logToConsole("public key from client - %s", truncate(parsedReq.PublicKey))

	strVals := strings.Split(parsedReq.PublicKey, "+")

	n, ok := new(big.Int).SetString(strVals[0], 10)
	if !ok {
		log.Error("failed to parse public key")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	e, ok := new(big.Int).SetString(strVals[1], 10)
	if !ok {
		log.Error("failed to parse public key")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	msgInt := new(big.Int).SetBytes(secretMessage)

	// encrypting message using the cipher = (msg**E)(mod N) rsa encryption algorithm
	em := new(big.Int).Exp(msgInt, e, n)

	sleep()

	logToConsole("sending encrypted message - %s", truncate(em.String()))

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	json.NewEncoder(w).Encode(&response{
		EncryptedMessage: em.String(),
	})
}

func truncate(s string) string {
	return s[:len(s)/4]
}

func sleep() {
	time.Sleep(2 * time.Second)
}

func logToConsole(msg string, args ...interface{}) {
	fmt.Println(fmt.Sprintf("server: "+msg, args...))
	fmt.Println()
}
