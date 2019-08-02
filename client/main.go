package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	serverEndpoint = "http://rsa-test.tk/message"
)

var (
	bigOne = big.NewInt(1)

	errUnableToCalculateKeys = errors.New("unable to calculate encryption keys")
)

// A PublicKey represents the public part of an RSA key.
type PublicKey struct {
	N *big.Int // modulus
	E int      // public exponent
}

// A PrivateKey represents an RSA key
type PrivateKey struct {
	PublicKey            // public part.
	D         *big.Int   // private exponent
	Primes    []*big.Int // prime factors of N, has >= 2 elements.
}

type request struct {
	PublicKey string `json:"public_key,omitempty"`
}

type response struct {
	EncryptedMessage string `json:"encrypted_message,omitempty"`
}

func main() {
	logToConsole("generating private key")

	privKey, err := generateKeys(1024)
	if err != nil {
		log.WithError(err).Fatal("failed to create private key")
	}

	req := &request{
		PublicKey: fmt.Sprintf("%v+%v", privKey.N, privKey.E),
	}

	sleep()

	logToConsole("sending public key to server - %s", truncate(req.PublicKey))

	reqJSON, err := json.Marshal(*req)
	if err != nil {
		log.WithError(err).Fatal("failed to marshal json")
	}

	resp, err := http.Post(serverEndpoint, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		log.WithError(err).Fatal("request failed")
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatal("request returned with error code")
	}
	defer resp.Body.Close()

	em := &response{}
	json.NewDecoder(resp.Body).Decode(em)

	sleep()

	logToConsole("received message from server - %s", truncate(em.EncryptedMessage))

	cipher, ok := new(big.Int).SetString(em.EncryptedMessage, 10)
	if !ok {
		log.Fatal("failed to parse encrypted message")
	}

	sleep()

	logToConsole("decrypting message")

	// decrypt via the msg = (c^D)(mod N) algorithm
	decrypted := new(big.Int).Exp(cipher, privKey.D, privKey.N)

	sleep()

	logToConsole("decrypted message: %s", string(decrypted.Bytes()))
}

func truncate(s string) string {
	return s[:len(s)/4]
}

func generateKeys(bits int) (*PrivateKey, error) {
	primes, err := generatePrimes(bits, 2)
	if err != nil {
		return nil, err
	}

	return calculateKeys(primes)
}

func generatePrimes(bits, nprimes int) ([]*big.Int, error) {
	primes := make([]*big.Int, nprimes)

	for {
		// Generate two prime numbers: p and q
		for i := 0; i < nprimes; i++ {
			var err error
			primes[i], err = rand.Prime(rand.Reader, bits/nprimes)
			if err != nil {
				return nil, err
			}
		}

		// Make sure that the primes aren't the same.
		if primes[0].Cmp(primes[1]) != 0 {
			break
		}
	}

	return primes, nil
}

func calculateKeys(primes []*big.Int) (*PrivateKey, error) {
	priv := new(PrivateKey)

	// always use 65537 for exponent E as it will always be relatively prime to φ(totient)
	priv.E = 65537

	// calculate N (p*q) and φ(totient) = (p-1)(q-1)
	n := new(big.Int).Set(bigOne)
	totient := new(big.Int).Set(bigOne)
	pminus1 := new(big.Int)
	for _, prime := range primes {
		n.Mul(n, prime)
		pminus1.Sub(prime, bigOne)
		totient.Mul(totient, pminus1)
	}

	// use E and (p-1)(q-1) to find inverse modulus (D)
	priv.D = new(big.Int)
	e := big.NewInt(int64(priv.E))
	ok := priv.D.ModInverse(e, totient)

	if ok == nil {
		return nil, errUnableToCalculateKeys
	}

	priv.Primes = primes
	priv.N = n

	return priv, nil
}

func sleep() {
	time.Sleep(2 * time.Second)
}

func logToConsole(msg string, args ...interface{}) {
	fmt.Println(fmt.Sprintf("client: "+msg, args...))
	fmt.Println()
}
