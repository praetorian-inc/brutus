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

// Package badkeys provides embedded SSH private keys known to be used as defaults
// in various software and hardware products. These keys are publicly documented
// and should never be used for actual authentication, but are commonly found
// in misconfigured systems.
//
// Sources:
//   - https://github.com/rapid7/ssh-badkeys
//   - https://github.com/hashicorp/vagrant/tree/master/keys
//
// Usage:
//
//	// Get all SSH key credentials for brute forcing
//	creds := badkeys.GetSSHCredentials()
//	for _, cred := range creds {
//	    fmt.Printf("Testing %s with key %s\n", cred.Username, cred.Name)
//	}
//
//	// Get credentials for a specific product
//	vagrantCreds := badkeys.GetCredentialsByProduct("vagrant")
package badkeys

import (
	"embed"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed keys/rapid7/*.key keys/vagrant/*.key
var keysFS embed.FS

// SSHCredential represents a username:key pair with metadata about its origin.
type SSHCredential struct {
	// Name is a human-readable identifier for this key (e.g., "vagrant-default")
	Name string
	// Username is the associated default username for this key
	Username string
	// Key is the raw PEM-encoded private key
	Key []byte
	// Product identifies the software/hardware this key is associated with
	Product string
	// CVE is the CVE identifier if one exists (empty string if none)
	CVE string
	// Description provides context about where this key is typically found
	Description string
	// DefaultPort is the typical SSH port for this service (usually 22)
	DefaultPort int
}

type keyInfo struct {
	Username    string
	Product     string
	CVE         string
	Description string
	DefaultPort int
}

// keyMetadata contains the username and metadata for each known key file.
var keyMetadata = map[string]keyInfo{
	// rapid7/ssh-badkeys authorized keys
	"array-networks-vapv-vxag.key": {
		Username:    "sync",
		Product:     "array-networks",
		CVE:         "",
		Description: "Array Networks vAPV/vxAG virtual appliances use this static key for the 'sync' user",
		DefaultPort: 22,
	},
	"barracuda_load_balancer_vm.key": {
		Username:    "cluster",
		Product:     "barracuda",
		CVE:         "CVE-2014-8428",
		Description: "Barracuda Load Balancer VM uses this static key on port 8002 for cluster management",
		DefaultPort: 8002,
	},
	"ceragon-fibeair-cve-2015-0936.key": {
		Username:    "mateidu",
		Product:     "ceragon",
		CVE:         "CVE-2015-0936",
		Description: "Ceragon FibeAir wireless backhaul devices use this hardcoded key",
		DefaultPort: 22,
	},
	"exagrid-cve-2016-1561.key": {
		Username:    "root",
		Product:     "exagrid",
		CVE:         "CVE-2016-1561",
		Description: "ExaGrid backup appliances contain a backdoor SSH key for root access",
		DefaultPort: 22,
	},
	"f5-bigip-cve-2012-1493.key": {
		Username:    "root",
		Product:     "f5-bigip",
		CVE:         "CVE-2012-1493",
		Description: "F5 BIG-IP load balancers shipped with this static root SSH key",
		DefaultPort: 22,
	},
	"loadbalancer.org-enterprise-va.key": {
		Username:    "root",
		Product:     "loadbalancer-org",
		CVE:         "",
		Description: "Loadbalancer.org Enterprise VA 7.5.2 and earlier use this static key",
		DefaultPort: 22,
	},
	"monroe-dasdec-cve-2013-0137.key": {
		Username:    "root",
		Product:     "monroe-dasdec",
		CVE:         "CVE-2013-0137",
		Description: "Monroe Electronics DASDEC emergency alert systems use this hardcoded key",
		DefaultPort: 22,
	},
	"quantum-dxi-v1000.key": {
		Username:    "root",
		Product:     "quantum-dxi",
		CVE:         "",
		Description: "Quantum DXi V1000 deduplication appliances use this static root key",
		DefaultPort: 22,
	},
	"vagrant-default.key": {
		Username:    "root",
		Product:     "vagrant",
		CVE:         "",
		Description: "Vagrant default insecure key (also in rapid7 collection)",
		DefaultPort: 22,
	},
	// Hashicorp Vagrant official key
	"vagrant.key": {
		Username:    "vagrant",
		Product:     "vagrant",
		CVE:         "",
		Description: "HashiCorp Vagrant insecure private key - default for 'vagrant' user in base boxes",
		DefaultPort: 22,
	},
	// Recent auth-key cases. These are metadata-only entries for operator-supplied
	// key packs; the repository intentionally does not embed these private keys.
	"aikaan-cloud-controller-cve-2025-57601.key": {
		Username:    "proxyuser",
		Product:     "aikaan",
		CVE:         "CVE-2025-57601",
		Description: "AiKaan Cloud Controller reused a hardcoded SSH private key for proxyuser remote terminal access",
		DefaultPort: 22,
	},
	"aikaan-proxyuser-cve-2025-57602.key": {
		Username:    "proxyuser",
		Product:     "aikaan",
		CVE:         "CVE-2025-57602",
		Description: "AiKaan IoT management platform proxyuser account combined with shared SSH private key enabled shell access",
		DefaultPort: 22,
	},
	"bettini-gams-cve-2022-25569.key": {
		Username:    "root",
		Product:     "bettini-gams",
		CVE:         "CVE-2022-25569",
		Description: "Bettini GAMS Product Line/SGSetup reused static SSH keys across installations",
		DefaultPort: 22,
	},
	"cisco-policy-suite-cve-2021-40119.key": {
		Username:    "root",
		Product:     "cisco-policy-suite",
		CVE:         "CVE-2021-40119",
		Description: "Cisco Policy Suite reused static SSH keys across installations for root SSH access",
		DefaultPort: 22,
	},
	"motorola-ace1000-cve-2022-30271.key": {
		Username:    "root",
		Product:     "motorola-ace1000",
		CVE:         "CVE-2022-30271",
		Description: "Motorola ACE1000 RTU shipped with a hardcoded SSH private key likely used by default",
		DefaultPort: 22,
	},
	"ruckus-network-director-cve-2025-67305.key": {
		Username:    "postgres",
		Product:     "ruckus-network-director",
		CVE:         "CVE-2025-67305",
		Description: "RUCKUS Network Director OVA contained hardcoded SSH keys for the postgres user",
		DefaultPort: 22,
	},
	"ruckus-smartzone-cve-2025-44954.key": {
		Username:    "root",
		Product:     "ruckus-smartzone",
		CVE:         "CVE-2025-44954",
		Description: "RUCKUS SmartZone contained a hardcoded SSH private key for a root-equivalent user account",
		DefaultPort: 22,
	},
	"rundeck-docker-cve-2022-29186.key": {
		Username:    "rundeck",
		Product:     "rundeck",
		CVE:         "CVE-2022-29186",
		Description: "Rundeck Docker images included a pre-generated SSH keypair that could be copied into authorized_keys",
		DefaultPort: 22,
	},
	"siemens-cpci85-cve-2023-36380.key": {
		Username:    "root",
		Product:     "siemens-cpci85",
		CVE:         "CVE-2023-36380",
		Description: "Siemens CP-8031/CP-8050 debug SSH authorized_keys contained a hardcoded key ID",
		DefaultPort: 22,
	},
	"vasion-printerlogic-cve-2025-34217.key": {
		Username:    "printerlogic",
		Product:     "vasion-printerlogic",
		CVE:         "CVE-2025-34217",
		Description: "Vasion Print/PrinterLogic had an undocumented printerlogic user with a hardcoded authorized SSH key",
		DefaultPort: 22,
	},
}

// additionalUsernames maps products to additional usernames that may work
// beyond the primary default username.
var additionalUsernames = map[string][]string{
	"vagrant":          {"vagrant", "root", "ubuntu", "centos", "ec2-user", "admin"},
	"exagrid":          {"root", "admin", "support"},
	"f5-bigip":         {"root", "admin"},
	"barracuda":        {"cluster", "root", "admin"},
	"array-networks":   {"sync", "root", "admin"},
	"ceragon":          {"mateidu", "root", "admin"},
	"loadbalancer-org": {"root", "loadbalancer", "admin"},
	"monroe-dasdec":    {"root", "dasdec", "admin"},
	"quantum-dxi":      {"root", "admin", "service"},
}

type localManifest struct {
	Keys []localManifestKey `json:"keys"`
}

type localManifestKey struct {
	File        string   `json:"file"`
	Name        string   `json:"name"`
	Username    string   `json:"username"`
	Usernames   []string `json:"usernames"`
	Product     string   `json:"product"`
	CVE         string   `json:"cve"`
	Description string   `json:"description"`
	DefaultPort int      `json:"default_port"`
}

func defaultKeyInfo(filename string) keyInfo {
	if meta, ok := keyMetadata[filename]; ok {
		return meta
	}
	return keyInfo{
		Username:    "root",
		Product:     "unknown",
		Description: "Operator-supplied SSH key",
		DefaultPort: 22,
	}
}

func credentialFromInfo(filename string, keyData []byte, meta keyInfo) SSHCredential {
	return SSHCredential{
		Name:        strings.TrimSuffix(filename, ".key"),
		Username:    meta.Username,
		Key:         keyData,
		Product:     meta.Product,
		CVE:         meta.CVE,
		Description: meta.Description,
		DefaultPort: meta.DefaultPort,
	}
}

// GetSSHCredentials returns all known SSH bad key credentials.
// Each credential includes the username most likely to work with that key.
func GetSSHCredentials() []SSHCredential {
	var creds []SSHCredential

	// Walk through embedded filesystem
	walkErr := fs.WalkDir(keysFS, "keys", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".key") {
			return nil
		}

		keyData, readErr := keysFS.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		filename := filepath.Base(path)
		creds = append(creds, credentialFromInfo(filename, keyData, defaultKeyInfo(filename)))

		return nil
	})

	if walkErr != nil {
		return nil
	}

	return creds
}

// LoadSSHCredentialsFromDir loads operator-supplied SSH bad keys from a local
// directory. Files ending in .key are loaded as private keys. If badkeys.json
// exists, it can provide metadata and one or more usernames per key:
//
//	{
//	  "keys": [
//	    {
//	      "file": "ruckus-network-director-cve-2025-67305.key",
//	      "usernames": ["postgres"],
//	      "product": "ruckus-network-director",
//	      "cve": "CVE-2025-67305"
//	    }
//	  ]
//	}
//
// Without a manifest, known filenames use built-in metadata and unknown files
// default to the root username.
func LoadSSHCredentialsFromDir(dir string) ([]SSHCredential, error) {
	if dir == "" {
		return nil, nil
	}

	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "readdir", Path: dir, Err: fs.ErrInvalid}
	}

	manifest, err := loadLocalManifest(filepath.Join(dir, "badkeys.json"))
	if err != nil {
		return nil, err
	}

	if len(manifest.Keys) > 0 {
		return loadManifestCredentials(dir, manifest)
	}

	var creds []SSHCredential
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".key") {
			return nil
		}
		keyData, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		filename := filepath.Base(path)
		creds = append(creds, credentialFromInfo(filename, keyData, defaultKeyInfo(filename)))
		return nil
	})
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func loadLocalManifest(path string) (localManifest, error) {
	var manifest localManifest
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return manifest, nil
		}
		return manifest, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return manifest, nil
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func loadManifestCredentials(dir string, manifest localManifest) ([]SSHCredential, error) {
	var creds []SSHCredential
	for i := range manifest.Keys {
		entry := &manifest.Keys[i]
		if entry.File == "" {
			continue
		}
		keyData, err := os.ReadFile(filepath.Join(dir, entry.File))
		if err != nil {
			return nil, err
		}

		meta := defaultKeyInfo(entry.File)
		if entry.Username != "" {
			meta.Username = entry.Username
		}
		if entry.Product != "" {
			meta.Product = entry.Product
		}
		if entry.CVE != "" {
			meta.CVE = strings.ToUpper(entry.CVE)
		}
		if entry.Description != "" {
			meta.Description = entry.Description
		}
		if entry.DefaultPort != 0 {
			meta.DefaultPort = entry.DefaultPort
		}

		usernames := entry.Usernames
		if len(usernames) == 0 && meta.Username != "" {
			usernames = []string{meta.Username}
		}
		for _, username := range usernames {
			if username == "" {
				continue
			}
			meta.Username = username
			cred := credentialFromInfo(entry.File, keyData, meta)
			if entry.Name != "" {
				cred.Name = entry.Name
			}
			creds = append(creds, cred)
		}
	}
	return creds, nil
}

// GetExpandedSSHCredentials returns credentials expanded with all likely usernames.
// For products with multiple possible usernames, this returns a credential
// for each username:key combination.
func GetExpandedSSHCredentials() []SSHCredential {
	baseCreds := GetSSHCredentials()
	var expanded []SSHCredential

	for _, cred := range baseCreds {
		usernames := additionalUsernames[cred.Product]
		if len(usernames) == 0 {
			// No additional usernames, use the default
			expanded = append(expanded, cred)
			continue
		}

		// Create a credential for each possible username
		for _, username := range usernames {
			expandedCred := SSHCredential{
				Name:        cred.Name,
				Username:    username,
				Key:         cred.Key,
				Product:     cred.Product,
				CVE:         cred.CVE,
				Description: cred.Description,
				DefaultPort: cred.DefaultPort,
			}
			expanded = append(expanded, expandedCred)
		}
	}

	return expanded
}

// GetCredentialsByProduct returns credentials for a specific product.
func GetCredentialsByProduct(product string) []SSHCredential {
	var creds []SSHCredential
	product = strings.ToLower(product)

	for _, cred := range GetSSHCredentials() {
		if strings.Contains(strings.ToLower(cred.Product), product) {
			creds = append(creds, cred)
		}
	}

	return creds
}

// GetCredentialsByCVE returns credentials associated with a specific CVE.
func GetCredentialsByCVE(cve string) []SSHCredential {
	var creds []SSHCredential
	cve = strings.ToUpper(cve)

	for _, cred := range GetSSHCredentials() {
		if cred.CVE == cve {
			creds = append(creds, cred)
		}
	}

	return creds
}

// GetKeys returns just the raw private keys without metadata.
// Useful for simple key-based brute forcing where you want to try
// all keys against a target.
func GetKeys() [][]byte {
	var keys [][]byte

	for _, cred := range GetSSHCredentials() {
		keys = append(keys, cred.Key)
	}

	return keys
}

// GetUsernames returns all unique usernames associated with bad keys.
func GetUsernames() []string {
	seen := make(map[string]bool)
	var usernames []string

	for _, cred := range GetExpandedSSHCredentials() {
		if !seen[cred.Username] {
			seen[cred.Username] = true
			usernames = append(usernames, cred.Username)
		}
	}

	return usernames
}

// GetKeyByName returns a specific key by its name (without .key extension).
func GetKeyByName(name string) ([]byte, bool) {
	// Try with and without .key extension
	filename := name
	if !strings.HasSuffix(filename, ".key") {
		filename = name + ".key"
	}

	// Check rapid7 directory
	data, err := keysFS.ReadFile("keys/rapid7/" + filename)
	if err == nil {
		return data, true
	}

	// Check vagrant directory
	data, err = keysFS.ReadFile("keys/vagrant/" + filename)
	if err == nil {
		return data, true
	}

	return nil, false
}

// ListKeys returns the names of all available keys.
func ListKeys() []string {
	var names []string

	walkErr := fs.WalkDir(keysFS, "keys", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".key") {
			names = append(names, strings.TrimSuffix(filepath.Base(path), ".key"))
		}
		return nil
	})

	if walkErr != nil {
		return nil
	}

	return names
}

// Stats returns statistics about the embedded key collection.
type Stats struct {
	TotalKeys       int
	TotalProducts   int
	KeysWithCVE     int
	UniqueUsernames int
}

// GetStats returns statistics about the embedded key collection.
func GetStats() Stats {
	creds := GetSSHCredentials()
	products := make(map[string]bool)
	keysWithCVE := 0

	for _, cred := range creds {
		products[cred.Product] = true
		if cred.CVE != "" {
			keysWithCVE++
		}
	}

	return Stats{
		TotalKeys:       len(creds),
		TotalProducts:   len(products),
		KeysWithCVE:     keysWithCVE,
		UniqueUsernames: len(GetUsernames()),
	}
}
