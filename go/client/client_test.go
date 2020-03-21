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

package main

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
	"roughtime.googlesource.com/go/config"
	"roughtime.googlesource.com/go/protocol"
)

const (
	nonsenseReply = ^time.Duration(0)
	maxRadius     = 10 * time.Second
)

type timeSpan struct {
	midpoint uint64
	radius   time.Duration
}

var timeEstablishmentTests = []struct {
	quorum                   int
	times                    []timeSpan
	shouldEstablish          bool
	shouldSignalMisbehaviour bool
	shouldHaveErrors         []int
}{
	{
		quorum: 1,
		times: []timeSpan{
			timeSpan{10, 5},
		},
		shouldEstablish: true,
	},
	{
		quorum: 1,
		times: []timeSpan{
			timeSpan{10, 5},
			timeSpan{20, 5},
		},
		shouldEstablish: true,
	},
	{
		quorum: 2,
		times: []timeSpan{
			timeSpan{100e6, maxRadius},
			timeSpan{200e6, maxRadius},
		},
		shouldEstablish: false,
	},
	{
		quorum: 2,
		times: []timeSpan{
			timeSpan{175e6, maxRadius},
			timeSpan{200e6, maxRadius},
			timeSpan{201e6, maxRadius},
		},
		shouldEstablish: true,
	},
	{
		quorum: 3,
		times: []timeSpan{
			timeSpan{100e6, maxRadius},
			timeSpan{101e6, maxRadius},
			timeSpan{102e6, maxRadius},
		},
		shouldEstablish: true,
	},
	{
		quorum: 3,
		times: []timeSpan{
			timeSpan{175e6, maxRadius},
			timeSpan{175e6, maxRadius},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
			timeSpan{175e6, maxRadius},
		},
		shouldEstablish: true,
	},
	{
		// An excessive radius should be rejected as invalid.
		quorum: 3,
		times: []timeSpan{
			timeSpan{200e6, 1 * time.Hour},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
		},
		shouldHaveErrors: []int{0},
		shouldEstablish:  false,
	},
	{
		// A zero radius is acceptable if the midpoint is reasonable.
		quorum: 3,
		times: []timeSpan{
			timeSpan{200e6, 0},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
		},
		shouldEstablish: true,
	},
	{
		quorum: 3,
		times: []timeSpan{
			timeSpan{201e6, 1 * time.Second},
			timeSpan{201e6, 2 * time.Second},
			timeSpan{201e6, 3 * time.Second},
		},
		shouldEstablish: true,
	},
	{
		quorum: 2,
		times: []timeSpan{
			timeSpan{100e6, maxRadius},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
		},
		shouldEstablish:          true,
		shouldSignalMisbehaviour: true,
	},
	{
		quorum: 2,
		times: []timeSpan{
			timeSpan{0, nonsenseReply},
			timeSpan{0, nonsenseReply},
			timeSpan{200e6, maxRadius},
			timeSpan{200e6, maxRadius},
		},
		shouldEstablish:  true,
		shouldHaveErrors: []int{0, 1},
	},
}

func TestEstablishment(t *testing.T) {
	client := &Client{
		nowFunc: func() time.Duration {
			// The monotonic clock always returns zero to avoid
			// query latency affecting the results.
			return 0
		},

		Permutation: func(n int) []int {
			// The permutation is fixed so that "servers" will be
			// queried in the order given.
			ret := make([]int, n)
			for i := range ret {
				ret[i] = i
			}

			return ret
		},

		MaxRadius:     maxRadius,
		MaxDifference: 60 * time.Second,
		QueryTimeout:  30 * time.Second,
		NumQueries:    1,
	}

	var waitGroup sync.WaitGroup
	defer waitGroup.Wait()

	for i, test := range timeEstablishmentTests {
		var handles []*serverHandle
		var servers []config.Server

		for j, span := range test.times {
			handle, err := startServer(&waitGroup, span)
			if err != nil {
				t.Fatal(err)
			}

			handles = append(handles, handle)
			servers = append(servers, config.Server{
				Name:      strconv.Itoa(j),
				PublicKey: handle.publicKey,
				Addresses: []config.ServerAddress{
					config.ServerAddress{
						Protocol: "udp",
						Address:  handle.addr.String(),
					},
				},
			})
			defer handle.Close()
		}

		var chain config.Chain
		result, err := client.EstablishTime(&chain, test.quorum, servers)
		if err != nil {
			t.Fatal(err)
		}

		if test.shouldEstablish != (result.MonoUTCDelta != nil) {
			t.Errorf("#%d: time establishment mismatch, wanted: %t", i, test.shouldEstablish)
		}

		if test.shouldEstablish && len(chain.Links) < test.quorum {
			t.Errorf("#%d: chain too short (%d) to be valid", i, len(chain.Links))
		}

		// Serialize and reparse chain to ensure that it's valid.
		chainBytes, err := json.MarshalIndent(chain, "", "  ")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := LoadChain(chainBytes); err != nil {
			t.Errorf("#%d: resulting chain does not parse: %s", i, err)
		}

		if test.shouldSignalMisbehaviour != result.OutOfRangeAnswer {
			t.Errorf("#%d: misbehaviour mismatch, wanted: %t", i, test.shouldSignalMisbehaviour)
		}

		if len(result.ServerErrors) != len(test.shouldHaveErrors) {
			t.Errorf("#%d: server errors mismatch, got %#v but wanted errors from #%v", i, result.ServerErrors, test.shouldHaveErrors)
		}

		for _, serverNumber := range test.shouldHaveErrors {
			if _, ok := result.ServerErrors[strconv.Itoa(serverNumber)]; !ok {
				t.Errorf("#%d: missing error for server %d", i, serverNumber)
			}
		}
	}
}

type serverHandle struct {
	publicKey []byte
	addr      *net.UDPAddr
}

func (handle *serverHandle) Close() {
	conn, err := net.DialUDP("udp", nil, handle.addr)
	if err != nil {
		panic(err)
	}

	conn.Write([]byte{0})
}

func startServer(wg *sync.WaitGroup, span timeSpan) (*serverHandle, error) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	onlinePublicKey, onlinePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	cert, err := protocol.CreateCertificate(0, ^uint64(0), onlinePublicKey, rootPrivate)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		panic("not a UDP address")
	}

	wg.Add(1)

	go func() {
		var packetBuf [protocol.MinRequestSize]byte
		defer wg.Done()

		for {
			n, sourceAddr, err := conn.ReadFromUDP(packetBuf[:])
			if err != nil {
				panic(err)
			}

			if n == 1 && packetBuf[0] == 0 {
				return
			}

			if span.radius == nonsenseReply {
				conn.WriteToUDP([]byte{1, 2, 3, 4, 5}, sourceAddr)
				continue
			}

			packet, err := protocol.Decode(packetBuf[:n])
			if err != nil {
				println(n)
				panic(err)
			}

			nonce, ok := packet[protocol.TagNonce]
			if !ok || len(nonce) != protocol.NonceSize {
				panic("missing nonce")
			}

			replies, err := protocol.CreateReplies([][]byte{nonce}, span.midpoint, uint32(span.radius/time.Microsecond), cert, onlinePrivateKey)
			if err != nil {
				panic(err)
			}

			conn.WriteToUDP(replies[0], sourceAddr)
		}
	}()

	return &serverHandle{
		publicKey: rootPublic,
		addr:      localAddr,
	}, nil
}

func TestFindNOverlapping(t *testing.T) {
	type sample struct {
		min int64
		max int64
	}
	testcases := []struct {
		samples []sample
		maxN    int
	}{
		{
			samples: []sample{
				{0, 2},
				{1, 3},
			},
			maxN: 2,
		},
		{
			samples: []sample{
				{0, 2},
				{1, 3},
				{4, 5},
			},
			maxN: 2,
		},
		{
			samples: []sample{
				{0, 10},
				{1, 2},
				{5, 10},
				{6, 10},
			},
			maxN: 3,
		},
	}
	for i, tc := range testcases {
		samples := make([]*timeSample, len(tc.samples))
		for j, s := range tc.samples {
			samples[j] = &timeSample{
				base: big.NewInt(0),
				min:  big.NewInt(s.min),
				max:  big.NewInt(s.max),
			}
		}
		for n := 1; n <= len(samples); n++ {
			expectedOk := n <= tc.maxN
			_, ok := findNOverlapping(samples, n)
			if ok != expectedOk {
				t.Errorf("#%d: findNOverlapping(n=%d) returned %v, wanted %v", i, n, ok, expectedOk)
			}
		}
	}
}
