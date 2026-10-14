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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/brutus/template"
)

var (
	flagTemplateTarget string
	flagTemplateTech   []string
	flagTemplateNerva  string
	flagTemplateDir    string
	flagTemplateCreds  string
)

var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Run product-specific default-credential templates",
	Long: `Templates bind a Nerva technology name to one login request.

A URL alone does not select templates. Pass --tech or a Nerva JSON/JSONL
file so only the detected products are attempted. Embedded pairs are the
vendor defaults. -c replaces them.

Templates with no embedded pairs run only when -c is set.`,
	Example: `  brutus template list

  brutus template run --target https://10.0.0.5 --tech fortinet-fortigate

  nerva --json -t 10.0.0.0/24 | brutus template run --nerva-file -`,
}

var templateListCmd = &cobra.Command{
	Use:   "list",
	Short: "List embedded and extra templates",
	RunE:  runTemplateList,
}

var templateRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run templates selected by technology",
	RunE:  runTemplateRun,
}

func init() {
	templateCmd.AddCommand(templateListCmd, templateRunCmd)
	f := templateRunCmd.Flags()
	f.StringVar(&flagTemplateTarget, "target", "", "Base URL (scheme://host[:port]) when not reading Nerva JSON")
	f.StringSliceVar(&flagTemplateTech, "tech", nil, "Nerva technology name (repeatable). Required with --target")
	f.StringVar(&flagTemplateNerva, "nerva-file", "", "Nerva JSON or JSONL file, or - for stdin")
	f.StringVar(&flagTemplateDir, "template-dir", "", "Directory of extra YAML templates; same id replaces embedded")
	f.StringVarP(&flagTemplateCreds, "credentials", "c", "", "Comma-separated user:pass pairs, used instead of template defaults")
	rootCmd.AddCommand(templateCmd)
}

func runTemplateList(cmd *cobra.Command, args []string) error {
	tpls, err := template.LoadExtra(flagTemplateDir)
	if err != nil {
		return err
	}
	if flagJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, t := range tpls {
			if err := enc.Encode(t); err != nil {
				return err
			}
		}
		return nil
	}
	for _, t := range tpls {
		fmt.Printf("%s\t%s\t%s\t%s\n", t.ID, t.Method, t.Path, strings.Join(t.Nerva, ","))
	}
	return nil
}

func runTemplateRun(cmd *cobra.Command, args []string) error {
	if flagTemplateTarget == "" && flagTemplateNerva == "" {
		return fmt.Errorf("--target or --nerva-file is required")
	}
	if flagTemplateTarget != "" && len(flagTemplateTech) == 0 && flagTemplateNerva == "" {
		return fmt.Errorf("--tech is required with --target; a URL alone does not select products")
	}
	tpls, err := template.LoadExtra(flagTemplateDir)
	if err != nil {
		return err
	}
	creds, err := parseTemplateCreds(flagTemplateCreds)
	if err != nil {
		return err
	}
	targets, err := templateTargets()
	if err != nil {
		return err
	}
	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	opt := template.Options{
		Timeout:  flagTimeout,
		TLSMode:  "skip-verify",
		ProxyURL: proxyURL,
		Creds:    creds,
	}
	if flagVerifyTLS {
		opt.TLSMode = "verify"
	}
	var hits []template.Hit
	for _, target := range targets {
		selected := template.Match(tpls, target.Technologies)
		if len(selected) == 0 {
			continue
		}
		found, err := template.Run(ctx, target.BaseURL, selected, opt)
		if err != nil {
			return fmt.Errorf("%s: %w", target.BaseURL, err)
		}
		hits = append(hits, found...)
	}
	return writeTemplateHits(hits)
}

func templateTargets() ([]template.Target, error) {
	if flagTemplateNerva != "" {
		r := os.Stdin
		if flagTemplateNerva != "-" {
			f, err := os.Open(flagTemplateNerva)
			if err != nil {
				return nil, err
			}
			defer func() { _ = f.Close() }()
			return template.ParseNerva(f)
		}
		return template.ParseNerva(r)
	}
	return []template.Target{{
		BaseURL:      flagTemplateTarget,
		Technologies: flagTemplateTech,
	}}, nil
}

func parseTemplateCreds(raw string) ([]template.Pair, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []template.Pair
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		user, pass, ok := strings.Cut(item, ":")
		if !ok || user == "" {
			return nil, fmt.Errorf("credential %q is not user:pass", item)
		}
		out = append(out, template.Pair{Username: user, Password: pass})
	}
	return out, nil
}

func writeTemplateHits(hits []template.Hit) error {
	if flagJSON || flagOutputFile != "" {
		enc := json.NewEncoder(os.Stdout)
		if flagOutputFile != "" {
			f, err := os.Create(flagOutputFile)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			enc = json.NewEncoder(f)
		}
		for _, hit := range hits {
			if err := enc.Encode(hit); err != nil {
				return err
			}
		}
		return nil
	}
	for _, hit := range hits {
		fmt.Printf("%s %s %s:%s\n", hit.TemplateID, hit.URL, hit.Username, hit.Password)
	}
	if len(hits) == 0 && !flagQuiet {
		fmt.Fprintln(os.Stderr, "no template credentials matched")
	}
	return nil
}
