//! Wraps IronRDP's ClientConnector state machine for WASM export.
//!
//! The connector is a state machine that steps through the RDP connection
//! handshake: X.224 negotiation -> TLS upgrade -> NLA/CredSSP -> MCS -> connected.
//!
//! Each step consumes input bytes and produces output bytes + next state.
//! The Go host drives the loop, performing actual I/O between steps.

use core::net::SocketAddr;

use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_connector::sspi::credssp::TsRequest;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, Config, ConnectionResult, ConnectorErrorKind,
    Credentials, DesktopSize, Sequence, ServerName, State,
};
use ironrdp_pdu::ironrdp_core::WriteBuf;
use ironrdp_pdu::nego;
use serde::Deserialize;

use crate::host_io;

// State constants returned to Go (must match Go stateNeedSend etc.)
pub const STATE_NEED_SEND: u32 = 1;
pub const STATE_NEED_RECV: u32 = 2;
pub const STATE_NEED_TLS_UPGRADE: u32 = 3;
pub const STATE_CONNECTED: u32 = 4;
pub const STATE_ERROR: u32 = 5;

/// Config received from Go host as JSON.
#[derive(Deserialize)]
pub struct ConnectorConfig {
    /// Target server address (host:port) - used for CredSSP server name.
    pub server: String,
    pub username: String,
    pub password: String,
    pub domain: String,
    /// When true, skip NLA/CredSSP authentication (for non-NLA session connections).
    #[serde(default)]
    pub skip_auth: bool,
    /// When true, request Restricted Admin Mode in the X.224 negotiation. The server,
    /// if it supports it, performs a credential-less network logon — enabling
    /// pass-the-hash (the NTLM exchange authenticates with the hash regardless of
    /// CredSSP delegation mode).
    ///
    /// NOTE: ironrdp-connector hardcodes CredSspMode::WithCredentials, so the
    /// delegated TSCredentials still carry the (hash-prefixed) password; a
    /// Restricted-Admin server ignores them and logs on via the network identity.
    #[serde(default)]
    pub restricted_admin: bool,
    /// When true, continue the connector past CredSSP all the way to a full
    /// ConnectionResult (needed to create an interactive session). When false
    /// (auth-only Test), the connector short-circuits once auth is confirmed.
    #[serde(default)]
    pub full_session: bool,
}

/// Internal phase of the connector.
#[derive(Debug)]
enum Phase {
    /// Driving the IronRDP ClientConnector state machine.
    Connector,
    /// TLS upgrade requested; waiting for Go to complete it.
    WaitingTlsUpgrade,
    /// CredSSP phase; driving NLA authentication via sspi-rs NTLMv2.
    Credssp,
    /// Successfully connected.
    Connected,
    /// An error occurred.
    Error(String),
}

/// Holds the connector state between calls from Go.
///
/// The Go host drives the state machine by calling `step()` repeatedly:
/// 1. step() with empty input -> gets NEED_SEND + X.224 connection request bytes
/// 2. Go sends bytes to server, reads response
/// 3. step() with server response -> gets NEED_TLS_UPGRADE
/// 4. Go upgrades to TLS
/// 5. step() with empty input -> CredSSP init -> gets NEED_SEND + first TsRequest
/// 6. ... CredSSP NTLM negotiate/challenge/authenticate rounds
/// 7. CredSSP done -> continues through MCS, licensing, capabilities, finalization
/// 8. Eventually returns CONNECTED or ERROR
pub struct ConnectorHandle {
    connector: ClientConnector,
    phase: Phase,
    /// Banner captured during handshake.
    banner: String,
    /// Whether we need input from Go on the next call.
    needs_input: bool,
    /// CredSSP sequence state, active during NLA phase.
    credssp_sequence: Option<CredsspSequence>,
    /// Server address (host:port) for CredSSP server name resolution.
    server_addr: String,
    /// Connection result extracted when connector reaches Connected state.
    /// Consumed by `take_connection_result()` to create a SessionHandle.
    connection_result: Option<ConnectionResult>,
    /// Request Restricted Admin Mode by patching the outbound X.224 nego request.
    restricted_admin: bool,
    /// Continue the connector to a full session after CredSSP (vs auth-only).
    full_session: bool,
    /// Set once the X.224 negotiation request has been patched, so we only ever
    /// patch the single outbound Connection Request.
    nego_patched: bool,
}

impl ConnectorHandle {
    /// Create a new connector from JSON config.
    pub fn new(config_bytes: &[u8]) -> Result<Self, String> {
        let config: ConnectorConfig =
            serde_json::from_slice(config_bytes).map_err(|e| format!("parse config: {}", e))?;

        let domain = if config.domain.is_empty() {
            None
        } else {
            Some(config.domain.clone())
        };

        // When skip_auth is set, disable CredSSP and use empty credentials.
        // This allows connecting to RDP servers with NLA disabled (e.g., for
        // sticky keys detection where we only need to reach the login screen).
        let credentials = if config.skip_auth {
            Credentials::UsernamePassword {
                username: String::new(),
                password: String::new(),
            }
        } else {
            Credentials::UsernamePassword {
                username: config.username.clone(),
                password: config.password.clone(),
            }
        };

        let ironrdp_config = Config {
            desktop_size: DesktopSize {
                width: 1024,
                height: 768,
            },
            desktop_scale_factor: 100,
            enable_tls: true,
            enable_credssp: !config.skip_auth,
            credentials,
            domain,
            client_build: 0,
            client_name: "brutus".to_string(),
            keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0x0409, // US English
            ime_file_name: String::new(),
            bitmap: None,
            dig_product_id: String::new(),
            client_dir: String::new(),
            platform: ironrdp_pdu::rdp::capability_sets::MajorPlatformType::UNSPECIFIED,
            hardware_id: None,
            request_data: None,
            autologon: !config.skip_auth,
            enable_audio_playback: false,
            performance_flags: ironrdp_pdu::rdp::client_info::PerformanceFlags::default(),
            license_cache: None,
            timezone_info: ironrdp_pdu::rdp::client_info::TimezoneInfo::default(),
            enable_server_pointer: false,
            pointer_software_rendering: false,
        };

        // Use a dummy client address for the PDU (Go handles real networking)
        let client_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let connector = ClientConnector::new(ironrdp_config, client_addr);

        Ok(ConnectorHandle {
            connector,
            phase: Phase::Connector,
            banner: String::new(),
            needs_input: false,
            credssp_sequence: None,
            server_addr: config.server,
            connection_result: None,
            restricted_admin: config.restricted_admin,
            full_session: config.full_session,
            nego_patched: false,
        })
    }

    /// Drive the connector one step.
    ///
    /// Returns (state_code, output_bytes).
    /// Go calls this repeatedly, providing input data when state was NEED_RECV.
    pub fn step(&mut self, input: &[u8]) -> (u32, Vec<u8>) {
        match &self.phase {
            Phase::Connected => return (STATE_CONNECTED, self.banner.as_bytes().to_vec()),
            Phase::Error(msg) => return (STATE_ERROR, msg.as_bytes().to_vec()),
            _ => {}
        }

        match self.do_step(input) {
            Ok((state, output)) => (state, output),
            Err(e) => {
                let msg = e.clone();
                self.phase = Phase::Error(e);
                (STATE_ERROR, msg.into_bytes())
            }
        }
    }

    fn do_step(&mut self, input: &[u8]) -> Result<(u32, Vec<u8>), String> {
        match self.phase {
            Phase::Connector => self.step_connector(input),
            Phase::WaitingTlsUpgrade => {
                // Go has completed TLS upgrade. Now mark it as done in the connector
                // and continue stepping.
                self.connector.mark_security_upgrade_as_done();
                self.phase = Phase::Connector;

                // Check if we need to do CredSSP
                if self.connector.should_perform_credssp() {
                    return self.step_credssp_init();
                }

                // Continue with normal connector stepping
                self.step_connector(&[])
            }
            Phase::Credssp => self.step_credssp(input),
            Phase::Connected => Ok((STATE_CONNECTED, self.banner.as_bytes().to_vec())),
            Phase::Error(ref msg) => Ok((STATE_ERROR, msg.as_bytes().to_vec())),
        }
    }

    /// Maximum internal iterations before returning an error.
    /// WASM has a limited call stack (~1000 frames), so we use a bounded loop
    /// instead of recursion to advance the connector when no output or PDU hint
    /// is produced by a step.
    const MAX_STEP_ITERATIONS: usize = 50;

    /// Step the IronRDP ClientConnector state machine.
    ///
    /// Uses a bounded loop (max 50 iterations) instead of recursion to handle
    /// cases where the connector needs multiple internal steps without producing
    /// output or a PDU hint. This avoids stack overflow in WASM's limited
    /// call stack.
    fn step_connector(&mut self, input: &[u8]) -> Result<(u32, Vec<u8>), String> {
        let mut current_input = input;
        let empty: &[u8] = &[];

        for _ in 0..Self::MAX_STEP_ITERATIONS {
            let mut output = WriteBuf::new();

            // If the connector needs input, call step with input.
            // Otherwise use step_no_input to generate outbound data.
            // When needs_input is true but we have no data yet, tell Go to
            // read from the server first (NEED_RECV) instead of passing
            // empty bytes to IronRDP which would cause a decode error.
            let _written = if current_input.is_empty() && self.needs_input {
                // We expect server data but Go hasn't provided it yet.
                return Ok((STATE_NEED_RECV, Vec::new()));
            } else if current_input.is_empty() {
                self.connector
                    .step_no_input(&mut output)
                    .map_err(|e| self.classify_connector_error(&e))?
            } else {
                self.needs_input = false;
                self.connector
                    .step(current_input, &mut output)
                    .map_err(|e| self.classify_connector_error(&e))?
            };

            // Check if security upgrade is needed (TLS)
            if self.connector.should_perform_security_upgrade() {
                self.phase = Phase::WaitingTlsUpgrade;
                return Ok((STATE_NEED_TLS_UPGRADE, Vec::new()));
            }

            // Check if CredSSP is needed
            if self.connector.should_perform_credssp() {
                return self.step_credssp_init();
            }

            // Check if connected
            if self.connector.state.is_terminal() {
                self.banner = format!(
                    "RDP server, state: {}",
                    self.connector.state().name()
                );
                // Extract the ConnectionResult from the Connected state.
                // ClientConnectorState derives Default (with Consumed variant),
                // so std::mem::take replaces it with Consumed and gives us the
                // Connected { result } variant to destructure.
                let state = std::mem::take(&mut self.connector.state);
                if let ClientConnectorState::Connected { result } = state {
                    self.connection_result = Some(result);
                }
                self.phase = Phase::Connected;
                return Ok((STATE_CONNECTED, self.banner.as_bytes().to_vec()));
            }

            // Check if we produced output to send
            let mut out_bytes = output.filled().to_vec();
            if !out_bytes.is_empty() {
                // Restricted Admin Mode is negotiated via a flag in the X.224
                // Connection Request. ironrdp-connector hardcodes the request flags
                // to empty, so we patch the single outbound nego request here.
                if self.restricted_admin && !self.nego_patched && set_restricted_admin_flag(&mut out_bytes) {
                    self.nego_patched = true;
                }
                // Only expect server data if the connector has a PDU hint
                // (meaning it's waiting for a specific response). One-way messages
                // like MCS Erect Domain Request don't get responses.
                self.needs_input = self.connector.next_pdu_hint().is_some();
                return Ok((STATE_NEED_SEND, out_bytes));
            }

            // Check if we need more input (hint available means we expect data)
            if self.connector.next_pdu_hint().is_some() {
                self.needs_input = true;
                return Ok((STATE_NEED_RECV, Vec::new()));
            }

            // No output, no hint -- loop again with empty input to advance
            current_input = empty;
        }

        Err("connector step exceeded internal iteration limit".to_string())
    }

    /// Extract the selected_protocol from the connector's CredSSP state.
    fn get_selected_protocol(&self) -> Result<nego::SecurityProtocol, String> {
        match &self.connector.state {
            ClientConnectorState::Credssp { selected_protocol } => Ok(*selected_protocol),
            other => Err(format!(
                "authentication failed: credssp: unexpected connector state: {}",
                other.name()
            )),
        }
    }

    /// Initialize the CredSSP sequence with real NTLMv2 authentication.
    ///
    /// Retrieves the TLS server public key via host function, creates a
    /// CredsspSequence with NTLMv2 auth, processes the initial (empty) TsRequest
    /// to generate the NTLM Negotiate message, and returns it for sending.
    fn step_credssp_init(&mut self) -> Result<(u32, Vec<u8>), String> {
        // Get the selected protocol from the connector state
        let selected_protocol = self.get_selected_protocol()?;

        // Get server TLS public key from Go host
        let server_public_key = host_io::get_tls_server_pubkey().map_err(|e| {
            format!(
                "authentication failed: credssp: failed to get server public key: {}",
                e
            )
        })?;

        // Extract credentials and domain from the connector config
        let credentials = self.connector.config.credentials.clone();
        let domain = self.connector.config.domain.as_deref();

        // Build server name from the target server address (ServerName strips the port)
        let server_name = ServerName::new(self.server_addr.clone());

        // Initialize the CredSSP sequence with NTLMv2 (no Kerberos config)
        let (credssp_seq, initial_ts_request) = CredsspSequence::init(
            credentials,
            domain,
            selected_protocol,
            server_name,
            server_public_key,
            None, // No Kerberos - use NTLM
        )
        .map_err(|e| format!("authentication failed: credssp init: {}", e))?;

        self.credssp_sequence = Some(credssp_seq);
        self.phase = Phase::Credssp;

        // Process the initial (empty) TsRequest to generate NTLM Negotiate message
        self.process_credssp_ts_request(initial_ts_request)
    }

    /// Process a TsRequest through the CredSSP generator and encode the output.
    ///
    /// The generator pattern used by sspi-rs may yield NetworkRequest for
    /// Kerberos KDC communication. For NTLMv2, the generator completes
    /// synchronously without network requests.
    fn process_credssp_ts_request(
        &mut self,
        ts_request: TsRequest,
    ) -> Result<(u32, Vec<u8>), String> {
        // Phase 1: Run the generator to get the client state.
        // We need to scope the mutable borrow of credssp_sequence so we can
        // use it again for handle_process_result.
        let client_state = {
            let credssp = self
                .credssp_sequence
                .as_mut()
                .ok_or("authentication failed: credssp sequence not initialized")?;

            let mut generator = credssp.process_ts_request(ts_request);
            match generator.start() {
                GeneratorState::Completed(result) => result.map_err(|e| {
                    format!("authentication failed: credssp: {}", e)
                })?,
                GeneratorState::Suspended(_network_request) => {
                    // For NTLMv2, the generator should not suspend (no network needed).
                    // Kerberos would need KDC communication which we don't support in WASM.
                    return Err(
                        "authentication failed: credssp: unexpected network request (Kerberos not supported in WASM)"
                            .to_string(),
                    );
                }
            }
            // generator is dropped here, releasing the mutable borrow
        };

        // Phase 2: Handle the result and produce output bytes.
        let mut output = WriteBuf::new();
        {
            let credssp = self
                .credssp_sequence
                .as_mut()
                .ok_or("authentication failed: credssp sequence not initialized")?;

            credssp
                .handle_process_result(client_state, &mut output)
                .map_err(|e| format!("authentication failed: credssp: {}", e))?;
        }

        // Phase 3: Check if CredSSP is complete and determine next action.
        let is_finished = self
            .credssp_sequence
            .as_ref()
            .map(|cs| cs.next_pdu_hint().is_none())
            .unwrap_or(true);

        if is_finished {
            // CredSSP sequence is complete
            self.credssp_sequence = None;
            self.connector.mark_credssp_as_done();
            self.phase = Phase::Connector;

            // If there's output from the final message, send it first
            let out_bytes = output.filled().to_vec();
            if !out_bytes.is_empty() {
                // We need to send the final CredSSP message, then the Go side
                // will call step() again which will continue with the connector
                return Ok((STATE_NEED_SEND, out_bytes));
            }

            // No final output, continue directly with connector
            return self.step_connector(&[]);
        }

        // CredSSP still in progress - check if we have output to send
        let out_bytes = output.filled().to_vec();
        if !out_bytes.is_empty() {
            return Ok((STATE_NEED_SEND, out_bytes));
        }

        // Need more input from server
        Ok((STATE_NEED_RECV, Vec::new()))
    }

    /// Step the CredSSP sequence with server input.
    ///
    /// Decodes the server's TsRequest or EarlyUserAuthResult, processes it,
    /// and returns the next action (NEED_SEND/NEED_RECV/continue to connector).
    fn step_credssp(&mut self, input: &[u8]) -> Result<(u32, Vec<u8>), String> {
        let credssp = self
            .credssp_sequence
            .as_mut()
            .ok_or("authentication failed: credssp sequence not initialized")?;

        // Decode the server message
        let ts_request_opt = credssp
            .decode_server_message(input)
            .map_err(|e| format!("authentication failed: credssp: {}", e))?;

        match ts_request_opt {
            Some(ts_request) => {
                // Server sent a TsRequest - process it
                self.process_credssp_ts_request(ts_request)
            }
            None => {
                // EarlyUserAuthResult::Success received — authentication succeeded.
                if self.full_session {
                    // Interactive session: continue the connector through MCS/GCC,
                    // licensing, and capabilities to obtain a full ConnectionResult.
                    self.credssp_sequence = None;
                    self.connector.mark_credssp_as_done();
                    self.phase = Phase::Connector;
                    self.step_connector(&[])
                } else {
                    // Auth-only testing: stop here. The server confirmed credentials.
                    self.phase = Phase::Connected;
                    Ok((STATE_CONNECTED, Vec::new()))
                }
            }
        }
    }

    /// Take the connection result out of this handle (consuming it).
    /// Returns None if the connector hasn't reached Connected state yet,
    /// or if the result was already taken.
    pub fn take_connection_result(&mut self) -> Option<ConnectionResult> {
        self.connection_result.take()
    }

    /// Classify connector errors into auth failure vs connection errors.
    /// The error strings are used by Go's ClassifyAuthError with rdpAuthIndicators.
    fn classify_connector_error(
        &self,
        err: &ironrdp_connector::ConnectorError,
    ) -> String {
        let kind = &err.kind;
        match kind {
            ConnectorErrorKind::Credssp(_) => {
                format!("authentication failed: credssp: {}", err)
            }
            ConnectorErrorKind::AccessDenied => {
                "authentication failed: access denied".to_string()
            }
            ConnectorErrorKind::Negotiation(failure) => {
                format!("authentication failed: negotiation: {}", failure)
            }
            _ => format!("connection error: {}", err),
        }
    }
}

/// Patch a TPKT-framed X.224 Connection Request to set the
/// RESTRICTED_ADMIN_MODE_REQUIRED flag in its trailing RDP_NEG_REQ structure.
///
/// The RDP_NEG_REQ is always the final 8 bytes of the X.224 Connection Request
/// (it follows the optional cookie/routing token; ironrdp does not emit the
/// optional correlation-info structure that would come after it). We validate
/// the type byte (0x01 = TYPE_RDP_NEG_REQ) and the 8-byte length field before
/// mutating, and return false (no-op) if the buffer does not look like a
/// negotiation request.
fn set_restricted_admin_flag(buf: &mut [u8]) -> bool {
    const TYPE_RDP_NEG_REQ: u8 = 0x01;
    const RESTRICTED_ADMIN_MODE_REQUIRED: u8 = 0x01;

    if buf.len() < 8 {
        return false;
    }
    let off = buf.len() - 8;
    if buf[off] != TYPE_RDP_NEG_REQ {
        return false;
    }
    let neg_len = u16::from_le_bytes([buf[off + 2], buf[off + 3]]);
    if neg_len != 8 {
        return false;
    }
    buf[off + 1] |= RESTRICTED_ADMIN_MODE_REQUIRED;
    true
}

#[cfg(test)]
mod tests {
    use super::set_restricted_admin_flag;

    // A representative cookie-less X.224 Connection Request: TPKT(4) + LI + CR
    // header(6) + RDP_NEG_REQ(8). The NEG_REQ flags byte is at index 12.
    fn sample_cr() -> Vec<u8> {
        vec![
            0x03, 0x00, 0x00, 0x13, // TPKT
            0x0E, // X.224 LI
            0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, // CR header
            0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP_NEG_REQ
        ]
    }

    #[test]
    fn sets_flag_on_valid_request() {
        let mut cr = sample_cr();
        assert!(set_restricted_admin_flag(&mut cr));
        assert_eq!(cr[12], 0x01, "RESTRICTED_ADMIN_MODE_REQUIRED set");
    }

    #[test]
    fn is_idempotent() {
        let mut cr = sample_cr();
        assert!(set_restricted_admin_flag(&mut cr));
        assert!(set_restricted_admin_flag(&mut cr));
        assert_eq!(cr[12], 0x01, "flag stays set, no duplicate bits");
    }

    #[test]
    fn preserves_existing_flags() {
        let mut cr = sample_cr();
        cr[12] = 0x08; // CORRELATION_INFO_PRESENT
        assert!(set_restricted_admin_flag(&mut cr));
        assert_eq!(cr[12], 0x09, "ORs in the restricted-admin bit");
    }

    #[test]
    fn rejects_non_negotiation_buffer() {
        // Trailing 8 bytes do not start with TYPE_RDP_NEG_REQ.
        let mut buf = vec![0u8; 16];
        assert!(!set_restricted_admin_flag(&mut buf));
    }

    #[test]
    fn rejects_short_buffer() {
        let mut buf = vec![0x01, 0x00, 0x08];
        assert!(!set_restricted_admin_flag(&mut buf));
    }
}
