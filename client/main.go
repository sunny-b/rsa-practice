package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	serverEndpoint = "http://rsa-test.tk/message"
)

type request struct {
	PublicKey string `json:"public_key,omitempty"`
}

type response struct {
	EncryptedMessage string `json:"encrypted_message,omitempty"`
}

func main() {
	log.Info("generating private key")

	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.WithError(err).Fatal("failed to create private key")
	}

	pub := privKey.PublicKey

	req := &request{
		PublicKey: fmt.Sprintf("%v+%v", pub.N, pub.E),
	}

	log.WithField(
		"public_key", truncate(req.PublicKey),
	).Info("sending public key to test server")

	reqJSON, err := json.Marshal(*req)
	if err != nil {
		log.WithError(err).Fatal("failed to marshal json")
	}

	resp, err := http.Post(serverEndpoint, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		log.WithError(err).Fatal("request failed")
	} else if resp.StatusCode != http.StatusOK {
		log.Fatal("request failed")
	}
	defer resp.Body.Close()

	em := &response{}
	json.NewDecoder(resp.Body).Decode(em)

	log.Infof("received message from server: %s", truncate(em.EncryptedMessage))

	c, ok := new(big.Int).SetString(em.EncryptedMessage, 10)
	if !ok {
		log.Fatal("failed to parse encrypted message")
	}

	log.Info("decrypting message")

	decrypted := new(big.Int).Exp(c, privKey.D, privKey.N)

	log.Infof("decrypted message: %s", string(decrypted.Bytes()))
}

func truncate(s string) string {
	return s[:len(s)/2]
}
