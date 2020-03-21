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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"roughtime.googlesource.com/go/client/monotime"
	"roughtime.googlesource.com/go/config"
)

var (
	chainFile    = flag.String("chain-file", "roughtime-chain.json", "The name of a file in which the query chain will be maintained")
	maxChainSize = flag.Int("max-chain-size", 128, "The maximum number of entries to maintain in the chain file")
	serversFile  = flag.String("servers-file", "roughtime-servers.json", "The name of a file that lists trusted Roughtime servers")
)

const (
	// defaultServerQuorum is the default number of overlapping responses
	// that are required to establish the current time.
	defaultServerQuorum = 3
)

func do() error {
	flag.Parse()

	serversData, err := ioutil.ReadFile(*serversFile)
	if err != nil {
		return err
	}

	servers, numServersSkipped, err := LoadServers(serversData)
	if err != nil {
		return err
	}
	if numServersSkipped > 0 {
		fmt.Fprintf(os.Stderr, "Ignoring %d unsupported servers\n", numServersSkipped)
	}

	chain := &config.Chain{}
	chainData, err := ioutil.ReadFile(*chainFile)
	if err == nil {
		if chain, err = LoadChain(chainData); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	quorum := defaultServerQuorum
	if quorum > len(servers) {
		fmt.Fprintf(os.Stderr, "Quorum set to %d servers because not enough valid servers were found to meet the default (%d)!\n", len(servers), quorum)
		quorum = len(servers)
	}

	var client Client
	result, err := client.EstablishTime(chain, quorum, servers)
	if err != nil {
		return err
	}

	for serverName, err := range result.ServerErrors {
		fmt.Fprintf(os.Stderr, "Failed to query %q: %s\n", serverName, err)
	}

	maxLenServerName := 0
	for name := range result.ServerInfo {
		if len(name) > maxLenServerName {
			maxLenServerName = len(name)
		}
	}

	for name, info := range result.ServerInfo {
		fmt.Printf("%s:%s %d–%d (answered in %s)\n", name, strings.Repeat(" ", maxLenServerName-len(name)), info.Min, info.Max, info.QueryDuration)
	}

	if result.MonoUTCDelta == nil {
		fmt.Fprintf(os.Stderr, "Failed to get %d servers to agree on the time.\n", quorum)
	} else {
		nowUTC := time.Unix(0, int64(monotime.Now()+*result.MonoUTCDelta))
		nowRealTime := time.Now()

		fmt.Printf("real-time delta: %s\n", nowRealTime.Sub(nowUTC))
	}

	// TODO: if result.OutOfRangeAnswer is set then cap the chain and
	// upload it.
	if result.OutOfRangeAnswer {
		fmt.Fprintf(os.Stderr, "One or more of the answers was significantly out of range.\n")
	}

	trimChain(chain, *maxChainSize)
	chainBytes, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return err
	}

	tempFile, err := ioutil.TempFile(filepath.Dir(*chainFile), filepath.Base(*chainFile))
	if err != nil {
		return err
	}
	defer tempFile.Close()

	if _, err := tempFile.Write(chainBytes); err != nil {
		return err
	}

	if err := os.Rename(tempFile.Name(), *chainFile); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := do(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
