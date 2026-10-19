// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package winrm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrSprayAborted is returned when a spray stops to protect the account.
var ErrSprayAborted = errors.New("spray aborted")

// SprayConfig is one credential against many WinRM hosts.
type SprayConfig struct {
	Hosts    []string
	Username string
	Password string
	Timeout  time.Duration
	Delay    time.Duration
	Workers  int
	HTTPS    bool
	Each     func(AccessReport)
}

// Spray tries the credential against every host. A bad-password verdict
// cancels remaining work so badPwdCount stops incrementing. Access denied
// after successful NTLM does not abort.
func Spray(ctx context.Context, cfg SprayConfig) ([]AccessReport, error) {
	if len(cfg.Hosts) == 0 {
		return nil, fmt.Errorf("no hosts given")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	if workers > 32 {
		workers = 32
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := &Plugin{UseHTTPS: cfg.HTTPS}
	jobs := make(chan string)
	var (
		mu    sync.Mutex
		out   []AccessReport
		abort error
		wg    sync.WaitGroup
	)

	worker := func() {
		defer wg.Done()
		for host := range jobs {
			if ctx.Err() != nil {
				return
			}
			rep := p.ProbeAccess(ctx, host, cfg.Username, cfg.Password, timeout)
			mu.Lock()
			out = append(out, rep)
			if cfg.Each != nil {
				cfg.Each(rep)
			}
			if rep.Kind.AbortsSpray() && abort == nil {
				abort = fmt.Errorf("%w: %s on %s (%s)", ErrSprayAborted, rep.Kind, rep.Host, rep.Detail)
				cancel()
			}
			mu.Unlock()
			if cfg.Delay > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(cfg.Delay):
				}
			}
		}
	}

	wg.Add(workers)
	for range workers {
		go worker()
	}
	for _, host := range cfg.Hosts {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case jobs <- host:
		}
	}
	close(jobs)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	return out, abort
}
