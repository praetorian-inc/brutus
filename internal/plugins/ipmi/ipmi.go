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

package ipmi

import (
	"context"
	"strconv"
	"time"

	ipmiclient "github.com/bougou/go-ipmi/pkg/client"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "623"

var ipmiAuthIndicators = []string{
	"unauthorized",
	"authentication failed",
	"invalid user",
	"wrong password",
	"privilege",
	"rakp",
}

func init() {
	brutus.Register("ipmi", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "ipmi" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("ipmi", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, portStr := brutus.ParseTarget(target, defaultPort)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	c, err := ipmiclient.NewClient(host, port, username, password)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	c.WithTimeout(timeout).WithRetry(0)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := c.Connect(dialCtx); err != nil {
		result.Error = classifyError(err)
		return result
	}
	_ = c.Close(dialCtx)
	result.Success = true
	return result
}

var classifyError = brutus.NewClassifier(ipmiAuthIndicators)
