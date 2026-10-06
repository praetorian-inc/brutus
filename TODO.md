# Shipped

`brutus template` loads YAML templates, selects them by Nerva technology name, and runs basic, form, or JSON logins. A URL alone does not select products. Embedded templates: adminer, argocd, coldfusion, confluence, elasticsearch, fortigate, gitlab, grafana, guacamole, jenkins, nexus, panos, pgadmin, phpmyadmin, qnap, rabbitmq, roundcube, synology, tomcat, watchguard, wordpress. Products without a vendor default run only with `-c`.

The rest of this file is the backlog.

# TODO: service credential templates

Brutus sprays generic defaults per protocol. Nerva already names the web application and, for many products, the login path. A template should bind a Nerva detection to one login method, one path, field names, a success matcher, and a small default-credential set. Do not spray the HTTP Basic Auth wordlist at every form login.

## Already covered

- `internal/plugins/http/http.go` `extractAppIdentifiers` only tags a banner. It does not change the request path, body, or success check. Markers: Grafana, Prometheus, Nagios, Jenkins, Nexus, Artifactory, SonarQube, Tomcat, Traefik, RabbitMQ, ActiveMQ, Elasticsearch, CouchDB, InfluxDB, Docker Registry, Consul, etcd, phpMyAdmin, Webmin.
- `pkg/brutus/wordlists/http_defaults.txt` is generic HTTP Basic Auth (`admin:admin`, `elastic:changeme`, `tomcat:tomcat`, `grafana:grafana`, `jenkins:jenkins`). No path, no form fields.
- Browser mode can drive an unknown form with an LLM. That is not a product template.
- Native protocol plugins already cover the service port (MySQL, Postgres, Redis, Elasticsearch, CouchDB, SMB, WinRM, and the rest). An HTTP template is only for the management UI.

## Template engine

- [ ] Schema: `id`, Nerva technology name, path, method (`basic`, `form`, `json`), request fields, success matcher, failure matcher, credential pairs.
- [ ] Select templates from a Nerva result (technology / fingerprinter name), not from the port alone.
- [ ] Run selected templates through the existing HTTP worker. No second spray engine.
- [ ] Missing computer-name style failures stay failures. A template that does not match the response is a miss, not a fallback onto the generic Basic Auth list.
- [ ] Fixture test per executor: wrong password is a miss, default password is a hit, unrelated HTML is not a hit.
- [ ] CLI: run templates against a target, and accept a Nerva JSON file so only matching products are attempted.

Credential pairs come from vendor documentation and the existing wordlists. Do not invent passwords to fill a template.

## Do not template

These Nerva detections are servers, libraries, or metadata. They have no product login.

`apache_httpd`, `nginx`, `iis`, `caddy`, `lighttpd`, `tengine`, `mini_httpd`, `micro_httpd`, `boa`, `goahead`, `civetweb`, `mongoose`, `rompager`, `appweb`, `expressjs`, `jsframework`, `favicon`, `robotstxt`, `soap`, `tinymce`, `upnp`, `swagger-*`, `openapi-json`.

`adminpath` (`/wp-admin/`, `/wp-login.php`, `/phpmyadmin/`, `/administrator/`, `/users/sign_in`, `/admin/`, `/login`) is a deep sweep, not a product. Prefer the named fingerprinter when one exists.

## Form and appliance logins

Nerva file is under `pkg/plugins/fingerprinters/`. Path is the probe or login path that fingerprinter already uses.

### Network and VPN

- [ ] `fortinet-fortigate` — `/remote/login` — `fortigate.go`
- [ ] `globalprotect` — `/global-protect/prelogin.esp` — `globalprotect.go`
- [ ] `anyconnect` / `cisco-asa-ftd` — `/+CSCOE+/logon.html` — `anyconnect.go`, `cisco_asa_ftd.go`
- [ ] `panos-mgmt` — `/php/login.php` — `panos_mgmt.go`
- [ ] `sophos-firewall` — `/webconsole/webpages/login.jsp` — `sophos.go`
- [ ] `sonicwall` — `/auth1.html` — `sonicwall.go`
- [x] `watchguard-firebox` — `/auth/login` — `watchguard.go`
- [ ] `zyxel-firewall` — `/weblogin.cgi` — `zyxel.go`
- [ ] `checkpoint-gateway` — `/cgi-bin/home.tcl`, `/sslvpn/` — `checkpoint.go`
- [ ] `citrix-netscaler` — `/logon/LogonPoint/`, `/vpn/login.js` — `citrix_netscaler.go`
- [ ] `bigip` — `/mgmt/tm/sys/version` (REST; confirm form vs token) — `bigip.go`
- [ ] `ivanti-connect-secure` — `/dana-na/auth/` — `ivanti_connect_secure.go`
- [ ] `pfsense` — root HTML match; confirm login path — `pfsense.go`
- [ ] `opnsense` — `/ui/` — `opnsense.go`
- [ ] `juniper-srx` — root match — `juniper.go`
- [ ] `mikrotik-routeros` — `/webfig/` — `mikrotik.go`
- [ ] `draytek-vigor` — `/weblogin.htm` — `draytek.go`
- [ ] `tp-link-router` — `/webpages/login.html` — `tp_link.go`
- [ ] `netgear-router`, `d-link-router`, `maipu-network-device` — `netgear.go`, `d_link.go`, `maipu.go` (`/form/formUserLogin`)
- [ ] `apc-nmc` — `/logon.htm` — `apc_nmc.go`

### Storage, printers, and out-of-band

- [ ] `hp-ilo`, `hp-ews`, `hp-chaisoe` — root match — `hp.go`
- [x] `qnap-qts` — `/cgi-bin/authLogin.cgi` — `qnap.go`
- [x] `synology-dsm` — login `POST /webapi/auth.cgi` (detection page `/webman/index.cgi`) — `synology_dsm.go`
- [ ] `unifi-status` — `/status`, `/api/system` — `unifi.go`
- [ ] `hikvision` — `/ISAPI/System/deviceInfo` — `hikvision.go`
- [ ] `dahua` — `/cgi-bin/magicBox.cgi` — `dahua.go`
- [ ] `webmin` — root match — `webmin.go`
- [ ] `samsung-magicinfo` — `/MagicInfo/` — `magicinfo.go`

### Admin UIs Nerva already separates from the API

- [ ] `adminer` — `/adminer.php`, `/adminer/`, `/` — `adminer.go`
- [ ] `phpmyadmin` — `/phpmyadmin/`, `/pma/`, `/phpMyAdmin/`, `/phpmyadmin/setup/` — `phpmyadmin.go`
- [x] `pgadmin` / `pgadmin-login` — `/login` — `pgadmin.go`
- [ ] `jenkins` — confirm `/login` vs `/script` — `jenkins.go`
- [ ] `gitlab` — API `/api/v4/version`; login is `/users/sign_in` (also in `adminpath.go`) — `gitlab.go`
- [ ] `gitea` — `/api/v1/version`; confirm login path — `gitea.go`
- [ ] `grafana` — `/api/health`; login is form, not the Basic Auth pair in `http_defaults.txt` — `grafana.go`
- [ ] `nexus-repository` / `nexus-repository-login` — `/service/rest/v1/status` — `nexus.go`
- [ ] `artifactory` — `/artifactory/api/system/ping` — `artifactory.go`
- [ ] `harbor` — `/api/v2.0/systeminfo` — `harbor.go`
- [ ] `argocd` / `argocd-login` — `/login` — `argocd.go`
- [ ] `rancher` / `rancher_dashboard` — `/dashboard/` — `rancher.go`
- [ ] `portainer` — `/api/users/admin/check` — `portainer.go`
- [ ] `keycloak` — `/realms/master` — `keycloak.go`
- [x] `guacamole` / `guacamole-login` — login `POST /guacamole/api/tokens` (detection page `/guacamole/`) — `guacamole.go`
- [ ] `kibana` — `/api/status` — `kibana.go`
- [ ] `opensearch-dashboards` — root match — `opensearch_dashboards.go`
- [ ] `prometheus` — `/api/v1/status/buildinfo` (often open; template only if auth is on) — `prometheus.go`
- [ ] `vault` — `/v1/sys/health` — `vault.go`
- [ ] `consul` — `/v1/agent/self` — `consul.go`
- [ ] `minio` — `/minio/health/live` — `minio.go`
- [ ] `rabbitmq-management` — `/api/overview` — `rabbitmq_management.go`
- [ ] `traefik-dashboard` — `/api/overview` — `traefik.go`
- [ ] `docker-registry` — `/v2/` — `docker_registry.go`
- [ ] `tomcat` — manager path is not `/`; do not send Basic Auth to `/` — `tomcat.go`
- [ ] `teamcity` — `/app/rest/server` — `teamcity.go`
- [ ] `splunk` — `/` — `splunk.go`
- [ ] `confluence` — `/login.action` — `confluence.go`
- [ ] `wordpress` — `/wp-login.php` via `adminpath.go`; product fingerprinter is `/wp-json/wp/v2/` — `wordpress.go`

### Enterprise and file-transfer portals

- [ ] `exchange` — `/owa/` — `exchange.go`
- [ ] `sharepoint` — `/_layouts/` — `sharepoint.go`
- [ ] `adfs` — `/adfs/ls` — `adfs.go`
- [ ] `adcs-web-enrollment` — `/certsrv/` — `adcs_web_enrollment.go`
- [ ] `zimbra` — `/zimbra/` — `zimbra.go`
- [ ] `roundcube` — `/?_task=login` — `roundcube.go`
- [ ] `sap-netweaver` — `/sap/public/info` — `sapnetweaver.go`
- [ ] `coldfusion` — `/CFIDE/administrator/` — `coldfusion.go`
- [ ] `sitecore` — `/sitecore/login` — `sitecore.go`
- [ ] `kentico` — `/CMSPages/GetResource.ashx` — `kentico.go`
- [ ] `adobe_experience_manager` — `/libs/granite/core/content/login.html` — `aem.go`
- [ ] `craftcms` — `/admin/login` — `craftcms.go`
- [ ] `solarwinds-whd` — `/helpdesk/WebObjects/Helpdesk.woa` — `solarwinds_whd.go`
- [ ] `manageengine` — `/showlogin.cc` and product prefixes — `manageengine.go`
- [ ] `papercut` — `/app` — `papercut.go`
- [ ] `screenconnect` — `/SetupWizard.aspx` — `screenconnect.go`
- [ ] `simplehelp` — `/technician` — `simplehelp.go`
- [ ] `veeam_enterprise_manager_web` — `/login.aspx` — `veeam.go`
- [ ] `commvault` — root match — `commvault.go`
- [ ] `quest-kace` — `/admin` — `quest_kace.go`
- [ ] `nakivo` — `/c/login` — `nakivo.go`
- [ ] `moveit` — `/human.aspx` — `moveit.go`
- [ ] `crushftp` — `/WebInterface/login.html` — `crushftp.go`
- [ ] `cleo` — `/Synchronization` — `cleo.go`
- [ ] `goanywhere` — `/goanywhere/` — `goanywhere.go`
- [ ] `beyondtrust-pra` — `/appliance` — `beyondtrust_pra.go`
- [ ] `vmware-horizon` — `/portal/webclient/index.html` — `vmware_horizon.go`
- [ ] `oracle_primavera_p6` — `/p6/action/login` — `oracle_primavera_p6.go`
- [ ] `oracle_primavera_unifier`, `oracle-otm`, `oracle_ats`, `oracle_commerce`, `oracle-service-cloud`, `oracle_simphony` — confirm login vs SOAP before writing a template
- [ ] `telerik-report-server` — `/Account/Login` — `telerik_report_server.go`
- [ ] `wsus` — `/ClientWebService/client.asmx` — service endpoint, not a password form
- [ ] `sccm-mp` — `/sms_mp/.sms_aut?mplist` — service endpoint, not a password form

### Data and BI consoles

- [ ] `metabase` — `/auth/login` — `metabase.go`
- [ ] `superset` — `/login/` — `superset.go`
- [ ] `redash` — `/login` — `redash.go`
- [ ] `airflow` — confirm `/login` — `airflow.go`
- [ ] `mlflow` — `/api/2.0/mlflow/experiments/search` — `mlflow.go`
- [ ] `backstage` — `/.backstage/health/v1/readiness` — `backstage.go`
- [ ] `doccano` — `/auth/login` — `doccano.go`
- [ ] `redis_commander` — root match — `redis_commander.go`
- [ ] `clickhouse-http`, `arangodb`, `cockroachdb`, `yugabytedb`, `tidb`, `elasticsearch`, `opensearch`, `couchdb` — HTTP API auth. Reuse the native plugin when the service port is open; template only the HTTP console.

### AI and notebook UIs

- [ ] `jupyterhub` — `/hub/login` — `jupyter.go`
- [ ] `jupyter-notebook` / `jupyterlab` — token or empty token, not a password form
- [ ] `open_webui` — `/api/config` — `open_webui.go`
- [ ] `dify` — `/console/api/setup` — `dify.go`
- [ ] `flowise`, `langflow`, `langfuse`, `gradio`, `streamlit`, `anythingllm` — confirm whether the detected page is a login or an open API
- [ ] `ollama`, `localai`, `tgi`, `triton`, `ray`, `weaviate`, `chromadb`, `pinecone`, `litellm` — version/health endpoints. Template only if the fingerprinter also sees an auth wall.

## Order

1. Template schema, Nerva match, and one executor test.
2. Form logins Nerva already pins: FortiGate, PAN-OS, Sophos, WatchGuard, Zyxel, Citrix, Ivanti, phpMyAdmin, Adminer, pgAdmin, Grafana, Jenkins, GitLab, Guacamole, Confluence, Roundcube, ColdFusion, Sitecore, PaperCut, CrushFTP, QNAP, Synology, iLO.
3. Basic Auth products already named in `extractAppIdentifiers`, with the real manager path (Tomcat `/manager/html`, RabbitMQ `/api/overview`, Nexus, Artifactory, Traefik, Prometheus).
4. Everything else in the lists above, one product per template, after the login request is confirmed against that fingerprinter's fixture in `nerva/testdata/` or `*_test.go`.
