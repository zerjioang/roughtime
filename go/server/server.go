// Copyright 2016 The Roughtime Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License. */

// server is a very basic Roughtime server.
//
// First, run with the flag -generate-key. This will print out a private key
// and a JSON template for the server. Put the private key (as hex) in a file
// named "priv" and then run with no arguments.
package main

// TODO(agl): add a test once the client functionality has landed.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ed25519"
	"roughtime.googlesource.com/go/config"
	"roughtime.googlesource.com/go/protocol"
)

var (
	genKey         = flag.Bool("generate-key", false, "Generate a new key pair")
	privateKeyFile = flag.String("private-key", "priv", "Filename of the private key (hex encoded)")
	port           = flag.Int("port", 5333, "Port number to listen on")
)

func main() {
	flag.Parse()

	var err error
	if *genKey {
		err = generateKeyPair()
	} else {
		err = serveForever()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func serveForever() error {
	privateKeyHex, err := ioutil.ReadFile(*privateKeyFile)
	if err != nil {
		return errors.New("Cannot open private key: " + err.Error())
	}

	privateKey, err := hex.DecodeString(string(bytes.TrimSpace(privateKeyHex)))
	if err != nil {
		return errors.New("Cannot parse private key: " + err.Error())
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: *port})
	if err != nil {
		return errors.New("Cannot listen on port: " + err.Error())
	}

	onlinePublicKey, onlinePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("Cannot generate private key: " + err.Error())
	}

	// As this is just an example, the certificate is created covering the
	// maximum possible range.
	cert, err := protocol.CreateCertificate(0, ^uint64(0), onlinePublicKey, privateKey)
	if err != nil {
		return errors.New("Cannot generate certificate: " + err.Error())
	}

	log.Printf("Processing requests on port %d", *port)

	var packetBuf [protocol.MinRequestSize]byte

	for {
		n, sourceAddr, err := conn.ReadFromUDP(packetBuf[:])
		if err != nil {
			log.Print(err)
		}

		if n < protocol.MinRequestSize {
			continue
		}

		packet, err := protocol.Decode(packetBuf[:n])
		if err != nil {
			continue
		}

		nonce, ok := packet[protocol.TagNonce]
		if !ok || len(nonce) != protocol.NonceSize {
			continue
		}

		midpoint := uint64(time.Now().UnixNano() / 1000)
		radius := uint32(1000000)

		replies, err := protocol.CreateReplies([][]byte{nonce}, midpoint, radius, cert, onlinePrivateKey)
		if err != nil {
			log.Print(err)
			continue
		}

		if len(replies) != 1 {
			continue
		}

		conn.WriteToUDP(replies[0], sourceAddr)
	}
}

func generateKeyPair() error {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	fmt.Printf("Private key: %x\n\n", rootPrivate)

	exampleConfig := config.ServersJSON{
		Servers: []config.Server{
			config.Server{
				Name:          "FIXME",
				PublicKeyType: "ed25519",
				PublicKey:     rootPublic,
				Addresses: []config.ServerAddress{
					config.ServerAddress{
						Protocol: "udp",
						Address:  "FIXME",
					},
				},
			},
		},
	}

	jsonBytes, err := json.MarshalIndent(exampleConfig, "", "  ")
	if err != nil {
		return err
	}

	os.Stdout.Write(jsonBytes)
	os.Stdout.WriteString("\n")

	return nil
}
