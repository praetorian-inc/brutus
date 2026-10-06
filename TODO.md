# Shipped

`brutus template` loads YAML templates, selects them by Nerva technology name, and runs basic, form, or JSON logins. A URL alone does not select products. Embedded templates: adminer, adfs, aem, apc-nmc, argocd, artifactory, beyondtrust-pra, bigip, checkpoint, citrix, coldfusion, confluence, craftcms, crushftp, dahua, draytek, elasticsearch, exchange, fortigate, gitea, gitlab, goanywhere, grafana, guacamole, harbor, hikvision, hp-ilo, ivanti, jenkins, juniper, kentico, keycloak, manageengine, mikrotik, moveit, nakivo, nexus, opnsense, panos, papercut, pfsense, pgadmin, phpmyadmin, portainer, qnap, quest-kace, rabbitmq, rancher, roundcube, screenconnect, sharepoint, simplehelp, sitecore, solarwinds-whd, sonicwall, synology, tomcat, tp-link, unifi, veeam, watchguard, webmin, wordpress, zimbra, zyxel. Products without a vendor default run only with `-c`.

The rest of this file is the backlog.

# TODO: service credential templates

Brutus sprays generic defaults per protocol. Nerva already names the web application and, for many products, the login path. A template should bind a Nerva detection to one login method, one path, field names, a success matcher, and a small default-credential set. Do not spray the HTTP Basic Auth wordlist at every form login.

## Already covered

- `internal/plugins/http/http.go` `extractAppIdentifiers` only tags a banner. It does not change the request path, body, or success check. Markers: Grafana, Prometheus, Nagios, Jenkins, Nexus, Artifactory, SonarQube, Tomcat, Traefik, RabbitMQ, ActiveMQ, Elasticsearch, CouchDB, InfluxDB, Docker Registry, Consul, etcd, phpMyAdmin, Webmin.
- `pkg/brutus/wordlists/http_defaults.txt` is generic HTTP Basic Auth (`admin:admin`, `elastic:changeme`, `tomcat:tomcat`, `grafana:grafana`, `jenkins:jenkins`). No path, no form fields.
- Browser mode can drive an unknown form with an LLM. That is not a product template.
- Native protocol plugins already cover the service port (MySQL, Postgres, Redis, Elasticsearch, CouchDB, SMB, WinRM, and the rest). An HTTP template is only for the management UI.

## Template engine

- [x] Schema: `id`, Nerva technology name, path, method (`basic`, `form`, `json`), request fields, success matcher, and credential pairs. A failed login is the negative control, not a separate matcher field.
- [x] Select templates from a Nerva result by technology or fingerprinter name. A URL or port alone matches nothing.
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

- [x] `fortinet-fortigate` — login `POST /remote/logincheck` (detection `/remote/login`) — `fortigate.go`
- [x] `globalprotect` — login `POST /global-protect/getconfig.esp` (detection `/global-protect/prelogin.esp`; technology `palo-alto-globalprotect`) — `globalprotect.go`
- [x] `anyconnect` / `cisco-asa-ftd` — login `POST /+webvpn+/index.html` (detection `/+CSCOE+/logon.html`) — `anyconnect.go`, `cisco_asa_ftd.go`
- [x] `panos-mgmt` — login `POST /php/login.php` — `panos_mgmt.go`
- [x] `sophos-firewall` — login `POST /webconsole/Controller` (detection `/webconsole/webpages/login.jsp`) — `sophos.go`
- [x] `sonicwall` — login `POST /api/sonicos/auth` (detection `/auth1.html`) — `sonicwall.go`
- [x] `watchguard-firebox` — `/auth/login` — `watchguard.go`
- [x] `zyxel-firewall` — `/weblogin.cgi` — `zyxel.go`
- [x] `checkpoint-gateway` — login `POST /cgi-bin/home.tcl` (detection page; `/sslvpn/` is the mobile-access portal) — `checkpoint.go`
- [x] `citrix-netscaler` — login `POST /cgi/login` (detection `/logon/LogonPoint/` and `/vpn/login.js`) — `citrix_netscaler.go`
- [x] `bigip` — `/mgmt/tm/sys/version` is HTTP Basic Auth, not a form or token login — `bigip.go`
- [x] `ivanti-connect-secure` — login `POST /dana-na/auth/url_default/login.cgi` (detection `/dana-na/auth/url_default/welcome.cgi`) — `ivanti_connect_secure.go`
- [x] `pfsense` — login `POST /` with `usernamefld`/`passwordfld` (detection is the root login form) — `pfsense.go`
- [x] `opnsense` — login `POST /` with `usernamefld`/`passwordfld` (detection `/ui/` and `/api/core/firmware/info`) — `opnsense.go`
- [x] `juniper-srx` — login `POST /` with `username`/`password` (detection is the J-Web root page) — `juniper.go`
- [x] `mikrotik-routeros` — login `POST /login` (detection `/webfig/`) — `mikrotik.go`
- [x] `draytek-vigor` — login `POST /cgi-bin/wlogin.cgi` (detection `/weblogin.htm`) — `draytek.go`
- [x] `tp-link-router` — `/webpages/login.html` — `tp_link.go`
- [x] `netgear-router` — Basic Auth on `/` when it challenges (detection `/currentsetting.htm`; factory `admin:password`) — `netgear.go`
- [x] `d-link-router` — login `POST /login.htm` (detection is the brand page; factory `admin` with an empty password, then `admin:admin`) — `d_link.go`
- [x] `maipu-network-device` — login `POST /form/formUserLogin` — `maipu.go`
- [x] `apc-nmc` — login `POST /Forms/login1` (detection `/logon.htm`) — `apc_nmc.go`

### Storage, printers, and out-of-band

- [x] `hp-ilo` — login `POST /redfish/v1/SessionService/Sessions` (detection is the `HP-iLO-Server` header) — `hp.go`
- [x] `hp-ews` — Basic Auth on `/` when it challenges (detection is the printer `Server` header; factory `admin` with an empty password, then `admin:admin`) — `hp.go`
- [x] `hp-chaisoe` — Basic Auth on `/` when it challenges (detection is the `HP-ChaiSOE` `Server` header) — `hp.go`
- [x] `qnap-qts` — `/cgi-bin/authLogin.cgi` — `qnap.go`
- [x] `synology-dsm` — login `POST /webapi/auth.cgi` (detection page `/webman/index.cgi`) — `synology_dsm.go`
- [x] `unifi-status` — login `POST /api/login` (detection `/status`; technology `unifi-controller`) — `unifi.go`
- [x] `hikvision` — `/ISAPI/System/deviceInfo` — `hikvision.go`
- [x] `dahua` — `/cgi-bin/magicBox.cgi` — `dahua.go`
- [x] `webmin` — login `POST /session_login.cgi` (detection is the root login page) — `webmin.go`
- [x] `samsung-magicinfo` — login `POST /MagicInfo/servlet/LoginServlet` (detection `/MagicInfo/`) — `magicinfo.go`

### Admin UIs Nerva already separates from the API

- [x] `adminer` — login `POST` `/adminer.php`, `/adminer/`, and `/` — `adminer.go`
- [x] `phpmyadmin` — login `POST` `index.php` under `/phpmyadmin/`, `/pma/`, and `/phpMyAdmin/`; `/phpmyadmin/setup/` is the installer, not a login — `phpmyadmin.go`
- [x] `pgadmin` / `pgadmin-login` — `/login` — `pgadmin.go`
- [x] `jenkins` — login `POST /j_spring_security_check`, not `/script` and not a GET of `/login` — `jenkins.go`
- [x] `gitlab` — login `POST /users/sign_in` (detection `/api/v4/version`) — `gitlab.go`
- [x] `gitea` — login `POST /user/login` (detection `/api/v1/version`) — `gitea.go`
- [x] `grafana` — login `POST /login` JSON `user`/`password`, not Basic Auth (detection `/api/health`) — `grafana.go`
- [x] `nexus-repository` / `nexus-repository-login` — Basic Auth on `/service/rest/v1/status` only when that path challenges — `nexus.go`
- [x] `artifactory` — `/artifactory/api/system/ping` — `artifactory.go`
- [x] `harbor` — login `POST /c/login` (detection `/api/v2.0/systeminfo`) — `harbor.go`
- [x] `argocd` / `argocd-login` — login `POST /api/v1/session` (UI `/login`; initial admin password is generated, so no embedded default) — `argocd.go`
- [x] `rancher` / `rancher_dashboard` — login `POST /v3-public/localProviders/local?action=login` (detection `/rancherversion` and `/dashboard/`) — `rancher.go`
- [x] `portainer` — login `POST /api/auth` (detection `/api/system/status`; `/api/users/admin/check` is setup state, not login) — `portainer.go`
- [x] `keycloak` — login `POST /realms/master/protocol/openid-connect/token` (legacy `/auth/realms/master/...`; detection `/.well-known/openid-configuration`) — `keycloak.go`
- [x] `guacamole` / `guacamole-login` — login `POST /guacamole/api/tokens` (detection page `/guacamole/`) — `guacamole.go`
- [x] `kibana` — login `POST /internal/security/login` with `kbn-xsrf` (detection `/api/status`; historical default `elastic:changeme`) — `kibana.go`
- [x] `opensearch-dashboards` — login `POST /auth/login` (root detection; demo default `admin:admin`) — `opensearch_dashboards.go`
- [x] `prometheus` — Basic Auth on `/api/v1/status/buildinfo` only when that path challenges; an open buildinfo is not a hit — `prometheus.go`
- [x] `vault` — login `POST /v1/auth/userpass/login/{username}` (`/v1/sys/health` is health, not a login) — `vault.go`
- [x] `consul` — Basic Auth on `/v1/agent/self` only when that path challenges; an open agent API is not a hit — `consul.go`
- [x] `minio` — Basic Auth on `/minio/health/live` only when that path challenges; an open health check is not a hit — `minio.go`
- [x] `rabbitmq-management` — Basic Auth on `/api/overview` only when that path challenges; factory `guest:guest` — `rabbitmq_management.go`
- [x] `traefik-dashboard` — Basic Auth on `/api/overview` only when that path challenges; an open dashboard is not a hit — `traefik.go`
- [x] `docker-registry` — Basic Auth on `/v2/` only when that path challenges; an open registry is not a hit — `docker_registry.go`
- [x] `tomcat` — Basic Auth on `/manager/html`, not `/` — `tomcat.go`
- [x] `teamcity` — Basic Auth on `/app/rest/server` only when that path challenges; an open REST API is not a hit — `teamcity.go`
- [x] `splunk` — login `POST /en-US/account/login` (detection `/`) — `splunk.go`
- [x] `confluence` — login `POST /dologin.action` (page `/login.action`) — `confluence.go`
- [x] `wordpress` — login `POST /wp-login.php` (detection `/wp-json/wp/v2/`) — `wordpress.go`

### Enterprise and file-transfer portals

- [x] `exchange` — login `POST /owa/auth.owa` (detection `/owa/`; technology `exchange_server`) — `exchange.go`
- [x] `sharepoint` — login `POST /_layouts/15/Authenticate.aspx` (detection `/_layouts/`) — `sharepoint.go`
- [x] `adfs` — login `POST /adfs/ls/` (detection `/adfs/ls`) — `adfs.go`
- [x] `adcs-web-enrollment` — `/certsrv/` is HTTP Basic Auth when the enrollment site challenges — `adcs_web_enrollment.go`
- [x] `zimbra` — `/zimbra/` — `zimbra.go`
- [x] `roundcube` — login `POST /` with `_task=login` — `roundcube.go`
- [x] `sap-netweaver` — Basic Auth on `/sap/bc/gui/sap/its/webgui` only when that path challenges (detection `/sap/public/info` is public) — `sapnetweaver.go`
- [x] `coldfusion` — login `POST /CFIDE/administrator/enter.cfm` (detection `/CFIDE/administrator/`) — `coldfusion.go`
- [x] `sitecore` — `/sitecore/login` — `sitecore.go`
- [x] `kentico` — login `POST /CMSPages/logon.aspx` (detection `/CMSPages/GetResource.ashx`; technology `kentico-cms`) — `kentico.go`
- [x] `adobe_experience_manager` — login `POST /libs/granite/core/content/login.html/j_security_check` — `aem.go`
- [x] `craftcms` — `/admin/login` — `craftcms.go`
- [x] `solarwinds-whd` — `/helpdesk/WebObjects/Helpdesk.woa` — `solarwinds_whd.go`
- [x] `manageengine` — login `POST /j_security_check` (detection marker `/showlogin.cc`) — `manageengine.go`
- [x] `papercut` — `/app` — `papercut.go`
- [x] `screenconnect` — login `POST /Login` (detection `/SetupWizard.aspx`; the template does not POST to that path) — `screenconnect.go`
- [x] `simplehelp` — `/technician` — `simplehelp.go`
- [x] `veeam_enterprise_manager_web` — `/login.aspx` — `veeam.go`
- [x] `commvault` — login `POST /webconsole/api/Login` (root detection) — `commvault.go`
- [x] `quest-kace` — login `POST /admin` (technology `quest-kace-sma`) — `quest_kace.go`
- [x] `nakivo` — `/c/login` — `nakivo.go`
- [x] `moveit` — login `POST /human.aspx` with `transaction=signon` (plain signon only) — `moveit.go`
- [x] `crushftp` — login `POST /WebInterface/function/` with `command=login` (detection `/WebInterface/`) — `crushftp.go`
- [x] `cleo` — `/Synchronization` is a fingerprint endpoint, not a password form. No template — `cleo.go`
- [x] `goanywhere` — login `POST /goanywhere/auth/login` (detection `/goanywhere/`) — `goanywhere.go`
- [x] `beyondtrust-pra` — login `POST /login/login` (detection marker `/appliance`) — `beyondtrust_pra.go`
- [x] `vmware-horizon` — login `POST /portal/webclient/index.html` — `vmware_horizon.go`
- [x] `oracle_primavera_p6` — login `POST /p6/action/j_security_check` (detection `/p6/action/login`) — `oracle_primavera_p6.go`
- [x] `oracle_primavera_unifier` — login `POST /bluedoor/j_security_check` (detection `/bluedoor` is the login page, not SOAP) — `oracle_primavera_unifier.go`
- [x] `oracle-otm` — HTML login at `/GC3/glog.webserver.servlet.umt.Login`, not SOAP. The detection fixture does not include the username or password field names, so no template — `oracle_otm.go`
- [x] `oracle_ats` — login `POST /olt/LoginSubmit.do` (detection `/olt` is the login page, not SOAP) — `oracle_ats.go`
- [x] `oracle_commerce` — detected from `X-ATG-Version` and `ATG_SESSION_ID`, not a login form and not SOAP. No template — `oracle_commerce.go`
- [x] `oracle-service-cloud` — detected from `/ci/about` and RightNow markers, not a login form and not SOAP. No template — `oracle_service_cloud.go`
- [x] `oracle_simphony` — `/EGateway/EGateway.asmx` is a SOAP service description, not a password form. No template — `oracle_simphony.go`
- [x] `telerik-report-server` — `/Account/Login` — `telerik_report_server.go`
- [x] `wsus` — `/ClientWebService/client.asmx` is a service endpoint, not a password form. No template — `wsus.go`
- [x] `sccm-mp` — `/sms_mp/.sms_aut?mplist` is a service endpoint, not a password form. No template — `sccm.go`

### Data and BI consoles

- [x] `metabase` — login `POST /api/session` (UI `/auth/login`; detection `/api/session/properties`) — `metabase.go`
- [x] `superset` — login `POST /login/` (detection `/api/v1/info`) — `superset.go`
- [x] `redash` — login `POST /login` (detection `/api/session`) — `redash.go`
- [x] `airflow` — login `POST /login/` (detection `/api/v1/health`) — `airflow.go`
- [x] `mlflow` — `/api/2.0/mlflow/experiments/search` is Basic Auth only when that path challenges; an open search is not a hit — `mlflow.go`
- [x] `backstage` — Basic Auth on `/.backstage/health/v1/readiness` only when that path challenges; an open health check is not a hit — `backstage.go`
- [x] `doccano` — login `POST /v1/auth-token` (UI `/auth/login`) — `doccano.go`
- [x] `redis_commander` — Basic Auth on `/` only when the root page challenges; an open UI is not a hit — `redis_commander.go`
- [x] `clickhouse-http` — Basic Auth on `/?query=SELECT+version()` only when that path challenges; factory user `default` with an empty password — `clickhouse.go`
- [x] `arangodb` — Basic Auth on `/_api/version` only when that path challenges; historical `root` with an empty password — `arangodb.go`
- [x] `cockroachdb` — Basic Auth on `/api/v2/nodes/` only when that path challenges; an open console API is not a hit — `cockroachdb.go`
- [x] `yugabytedb` — Basic Auth on `/api/v1/version` only when that path challenges; an open master API is not a hit — `yugabytedb.go`
- [x] `tidb` — Basic Auth on `/status` only when that path challenges; an open status page is not a hit — `tidb.go`
- [x] `elasticsearch` — Basic Auth on `/` only when that path challenges; historical `elastic:changeme` and `elastic:elastic`. Use the native plugin for the service port — `elasticsearch.go`
- [x] `opensearch` — Basic Auth on `/` only when that path challenges; security-plugin demo default `admin:admin`. Use the native plugin for the service port — `opensearch.go`
- [x] `couchdb` — Basic Auth on `/` only when that path challenges; historical `admin:admin`. An open admin party is not a hit. Use the native plugin for the service port — `couchdb.go`

### AI and notebook UIs

- [x] `jupyterhub` — `/hub/login` — `jupyter.go`
- [x] `jupyter-notebook` / `jupyterlab` — detected from `/api` and `/lab`. Auth is a token or an empty token, not a password form. No template — `jupyter.go`
- [x] `open_webui` — login `POST /api/v1/auths/signin` (detection `/api/config`) — `open_webui.go`
- [x] `dify` — login `POST /console/api/login` (detection `/console/api/setup` is setup state, not a login) — `dify.go`
- [x] `flowise` — `/api/v1/version` is an open version API by default. Basic Auth only when that path challenges; an open version API is not a hit — `flowise.go`
- [x] `langflow` — `/api/v1/version` is an open version API. Login is `POST /api/v1/login`; a hit requires an `access_token` — `langflow.go`
- [x] `langfuse` — `/api/public/health` is open. Login is `POST /api/auth/callback/credentials`; a hit requires a redirect that is not an error — `langfuse.go`
- [x] `gradio` — `/config` is an open app config. Login is `POST /login` when auth is enabled; a hit requires a redirect that leaves `/login` — `gradio.go`
- [x] `streamlit` — `/_stcore/health` is an open health check, not a password form. No template — `streamlit.go`
- [x] `anythingllm` — `/api/utils/metrics` is an open metrics API. Login is `POST /api/request-token`; a hit requires a `token` — `anythingllm.go`
- [x] `ollama` — `/api/version` is an open version API, not a password form. No template — `ollama.go`
- [x] `localai` — `/system` is an open system endpoint, not a password form. No template — `localai.go`
- [x] `tgi` — `/info` and `/metrics` are open info endpoints, not a password form. No template — `tgi.go`
- [x] `triton` — `/v2` is an open version endpoint, not a password form. No template — `triton.go`
- [x] `ray` — `/api/version` is an open version API, not a password form. No template — `ray.go`
- [x] `weaviate` — `/v1/meta` is an open meta endpoint. Auth, when enabled, is an API key, not a password form. No template — `weaviate.go`
- [x] `chromadb` — `/api/v1/heartbeat` is open by default. Basic Auth only when that path challenges; an open heartbeat is not a hit — `chromadb.go`
- [x] `pinecone` — detected from Pinecone API headers. Auth is an API key, not a password form. No template — `pinecone.go`
- [x] `litellm` — `/health/liveliness` is an open liveness check, not a password form. No template — `litellm.go`

## Order

1. Template schema, Nerva match, and one executor test.
2. Form logins Nerva already pins: FortiGate, PAN-OS, Sophos, WatchGuard, Zyxel, Citrix, Ivanti, phpMyAdmin, Adminer, pgAdmin, Grafana, Jenkins, GitLab, Guacamole, Confluence, Roundcube, ColdFusion, Sitecore, PaperCut, CrushFTP, QNAP, Synology, iLO.
3. Basic Auth products already named in `extractAppIdentifiers`, with the real manager path (Tomcat `/manager/html`, RabbitMQ `/api/overview`, Nexus, Artifactory, Traefik, Prometheus).
4. Everything else in the lists above, one product per template, after the login request is confirmed against that fingerprinter's fixture in `nerva/testdata/` or `*_test.go`.
