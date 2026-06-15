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

package plugins

// Import all plugins to auto-register them
import (
	_ "github.com/praetorian-inc/brutus/internal/plugins/browser"
	_ "github.com/praetorian-inc/brutus/internal/plugins/cassandra"
	_ "github.com/praetorian-inc/brutus/internal/plugins/couchdb"
	_ "github.com/praetorian-inc/brutus/internal/plugins/docker"
	_ "github.com/praetorian-inc/brutus/internal/plugins/elasticsearch"
	_ "github.com/praetorian-inc/brutus/internal/plugins/ftp"
	_ "github.com/praetorian-inc/brutus/internal/plugins/http"
	_ "github.com/praetorian-inc/brutus/internal/plugins/imap"
	_ "github.com/praetorian-inc/brutus/internal/plugins/influxdb"
	_ "github.com/praetorian-inc/brutus/internal/plugins/kubernetes"
	_ "github.com/praetorian-inc/brutus/internal/plugins/ldap"
	_ "github.com/praetorian-inc/brutus/internal/plugins/mongodb"
	_ "github.com/praetorian-inc/brutus/internal/plugins/mssql"
	_ "github.com/praetorian-inc/brutus/internal/plugins/mysql"
	_ "github.com/praetorian-inc/brutus/internal/plugins/neo4j"
	_ "github.com/praetorian-inc/brutus/internal/plugins/oracle"
	_ "github.com/praetorian-inc/brutus/internal/plugins/pop3"
	_ "github.com/praetorian-inc/brutus/internal/plugins/postgresql"
	_ "github.com/praetorian-inc/brutus/internal/plugins/rdp"
	_ "github.com/praetorian-inc/brutus/internal/plugins/redis"
	_ "github.com/praetorian-inc/brutus/internal/plugins/smb"
	_ "github.com/praetorian-inc/brutus/internal/plugins/smtp"
	_ "github.com/praetorian-inc/brutus/internal/plugins/snmp"
	_ "github.com/praetorian-inc/brutus/internal/plugins/ssh"
	_ "github.com/praetorian-inc/brutus/internal/plugins/telnet"
	_ "github.com/praetorian-inc/brutus/internal/plugins/turn"
	_ "github.com/praetorian-inc/brutus/internal/plugins/vnc"
	_ "github.com/praetorian-inc/brutus/internal/plugins/winrm"
)
