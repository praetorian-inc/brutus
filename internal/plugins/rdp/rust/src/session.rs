//! Session management for non-NLA RDP connections.
//!
//! After the connector reaches the Connected state, a SessionHandle wraps
//! IronRDP's ActiveStage to drive the graphical session: processing server
//! frames, decoding screen updates, and sending keyboard input.

use ironrdp_connector::connection_activation::{
    ConnectionActivationSequence, ConnectionActivationState,
};
use ironrdp_connector::{ConnectionResult, Sequence};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database as InputDatabase, MouseButton, MousePosition, Operation, Scancode};
use ironrdp_pdu::ironrdp_core::WriteBuf;
use ironrdp_pdu::Action;
use ironrdp_session::fast_path;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};

// State constants returned to Go (must match Go session state constants)
#[allow(dead_code)]
pub const STATE_SESSION_READY: u32 = 20;
pub const STATE_FRAME_AVAILABLE: u32 = 21;
pub const STATE_INPUT_SENT: u32 = 22;
pub const STATE_SESSION_ERROR: u32 = 25;
pub const STATE_SESSION_NEED_SEND: u32 = 26;
pub const STATE_SESSION_NEED_RECV: u32 = 27;

/// Holds an active RDP session after the connector handshake completes.
///
/// The Go host drives this by:
/// 1. Calling `process_server_data()` with bytes received from the server
/// 2. Sending any response bytes back to the server
/// 3. Calling `send_key()` to inject keyboard input
/// 4. Calling `get_frame_rgba()` to read the decoded framebuffer
pub struct SessionHandle {
    active_stage: ActiveStage,
    image: DecodedImage,
    input_db: InputDatabase,
    width: u16,
    height: u16,
    frame_updated: bool,
    /// In-flight Deactivation-Reactivation Sequence, when the server has asked for
    /// one. While this is Some, incoming server data is routed to the sequence
    /// instead of the ActiveStage (see step_reactivation).
    reactivation: Option<Box<ConnectionActivationSequence>>,
    /// Host round-trips spent in the current reactivation, bounded so a server that
    /// never finalizes cannot keep the scan in reactivation indefinitely.
    reactivation_steps: u32,
}

impl SessionHandle {
    /// Create a new session from a completed connection result.
    pub fn new(
        connection_result: ConnectionResult,
        width: u16,
        height: u16,
    ) -> Result<Self, String> {
        let image = DecodedImage::new(PixelFormat::RgbA32, width, height);
        let active_stage = ActiveStage::new(connection_result);
        let input_db = InputDatabase::new();

        Ok(SessionHandle {
            active_stage,
            image,
            input_db,
            width,
            height,
            frame_updated: false,
            reactivation: None,
            reactivation_steps: 0,
        })
    }

    /// Process incoming server data. Returns (state_code, output_bytes_to_send).
    ///
    /// The first byte of input determines FastPath vs X224 framing via
    /// `Action::from_fp_output_header`.
    pub fn process_server_data(&mut self, input: &[u8]) -> (u32, Vec<u8>) {
        if input.is_empty() {
            return (STATE_SESSION_NEED_RECV, Vec::new());
        }

        // A Deactivation-Reactivation Sequence is in flight: the server is
        // re-running Capability Exchange and Connection Finalization, so this data
        // belongs to that sequence and NOT to the ActiveStage.
        if self.reactivation.is_some() {
            return self.step_reactivation(input);
        }

        // Determine action from first byte
        let action = match Action::from_fp_output_header(input[0]) {
            Ok(a) => a,
            Err(_) => {
                return (
                    STATE_SESSION_ERROR,
                    b"invalid frame action byte".to_vec(),
                );
            }
        };

        match self.active_stage.process(&mut self.image, action, input) {
            Ok(outputs) => {
                let mut response_bytes = Vec::new();
                for output_item in outputs {
                    match output_item {
                        ActiveStageOutput::ResponseFrame(frame) => {
                            response_bytes.extend_from_slice(&frame);
                        }
                        ActiveStageOutput::GraphicsUpdate(_) => {
                            self.frame_updated = true;
                        }
                        ActiveStageOutput::Terminate(reason) => {
                            return (
                                STATE_SESSION_ERROR,
                                format!("session terminated: {}", reason).into_bytes(),
                            );
                        }
                        ActiveStageOutput::DeactivateAll(activation) => {
                            // Server-initiated Deactivation-Reactivation Sequence
                            // (MS-RDPBCGR 1.3.1.3). This is a NORMAL event, not a
                            // failure: a server sends it when it switches desktops,
                            // which on a pre-auth logon session is exactly what
                            // happens when sethc.exe/utilman.exe launches a console
                            // on the secure desktop -- the case this scanner exists
                            // to detect. Treating it as fatal killed the session
                            // mid-scan and left the host reading a torn-down
                            // ActiveStage. Take the sequence and drive it instead;
                            // the server sends Demand Active next.
                            self.reactivation = Some(activation);
                            self.reactivation_steps = 0;
                            // Deliberately NOT breaking: IronRDP can emit further
                            // items in this same batch and a trailing ResponseFrame
                            // still has to reach the wire. The post-loop check
                            // below takes precedence over the frame decision.
                            continue;
                        }
                        _ => {} // PointerDefault, PointerHidden, PointerPosition, PointerBitmap
                    }
                }

                // Flush anything already queued before switching to the
                // reactivation sequence, so no response frame is dropped.
                if self.reactivation.is_some() {
                    if !response_bytes.is_empty() {
                        return (STATE_SESSION_NEED_SEND, response_bytes);
                    }
                    return (STATE_SESSION_NEED_RECV, Vec::new());
                }

                if !response_bytes.is_empty() {
                    return (STATE_SESSION_NEED_SEND, response_bytes);
                }

                if self.frame_updated {
                    (STATE_FRAME_AVAILABLE, Vec::new())
                } else {
                    (STATE_SESSION_NEED_RECV, Vec::new())
                }
            }
            Err(e) => (
                STATE_SESSION_ERROR,
                format!("session error: {}", e).into_bytes(),
            ),
        }
    }

    /// Maximum host round-trips allowed for one Deactivation-Reactivation Sequence.
    /// The host deadline already bounds wall-clock time; this bounds the work.
    const MAX_REACTIVATION_STEPS: u32 = 64;

    /// Drive one step of the Deactivation-Reactivation Sequence (MS-RDPBCGR 1.3.1.3).
    ///
    /// This deliberately reuses the existing NEED_SEND/NEED_RECV states rather than
    /// adding new ones: the host pump already loops on those, writing what we return
    /// and feeding back the next server PDU, so reactivation needs no host-side
    /// protocol change.
    ///
    /// On finalization the server may hand back a DIFFERENT desktop size, so the
    /// DecodedImage and the fast-path processor are rebuilt for the new geometry.
    fn step_reactivation(&mut self, input: &[u8]) -> (u32, Vec<u8>) {
        self.reactivation_steps += 1;
        if self.reactivation_steps > Self::MAX_REACTIVATION_STEPS {
            self.reactivation = None;
            return (
                STATE_SESSION_ERROR,
                b"reactivation did not finalize within step budget".to_vec(),
            );
        }

        let activation = match self.reactivation.as_mut() {
            Some(a) => a,
            None => {
                return (
                    STATE_SESSION_ERROR,
                    b"reactivation stepped with no sequence in flight".to_vec(),
                );
            }
        };

        let mut output = WriteBuf::new();
        if let Err(e) = activation.step(input, &mut output) {
            self.reactivation = None;
            return (
                STATE_SESSION_ERROR,
                format!("reactivation failed: {}", e).into_bytes(),
            );
        }

        if let ConnectionActivationState::Finalized {
            io_channel_id,
            user_channel_id,
            desktop_size,
            enable_server_pointer,
            pointer_software_rendering,
        } = activation.connection_activation_state()
        {
            // A reactivation may come back at a DIFFERENT desktop size. The host
            // cannot follow that: it keeps the width/height it passed to
            // session_new and discards the dimensions session_get_frame reports
            // (captureFrame reads the packed value only to test non-zero). A
            // resized framebuffer would therefore be diffed against the baseline
            // using stale geometry -- misaligned pixels, and a verdict built on
            // them. Refuse instead: this surfaces as INDETERMINATE, which is
            // honest, where a misaligned diff is a coin-flip in both directions.
            // The secure-desktop switch this scanner targets is same-resolution,
            // so this is the rare path. Threading live geometry through
            // captureFrame and the analysis calls is the real fix and is larger
            // than this change.
            if desktop_size.width != self.width || desktop_size.height != self.height {
                self.reactivation = None;
                return (
                    STATE_SESSION_ERROR,
                    format!(
                        "reactivation changed desktop size {}x{} -> {}x{}; host geometry is fixed",
                        self.width, self.height, desktop_size.width, desktop_size.height
                    )
                    .into_bytes(),
                );
            }

            // Same geometry, but the deactivation invalidated the old contents, so
            // start from a clean buffer rather than decoding onto stale pixels.
            self.image = DecodedImage::new(PixelFormat::RgbA32, self.width, self.height);

            self.active_stage.set_fastpath_processor(
                fast_path::ProcessorBuilder {
                    io_channel_id,
                    user_channel_id,
                    enable_server_pointer,
                    pointer_software_rendering,
                }
                .build(),
            );
            self.active_stage
                .set_enable_server_pointer(enable_server_pointer);

            self.reactivation = None;
            self.reactivation_steps = 0;
            // Deliberately NOT reporting a frame here. The replacement DecodedImage
            // is freshly allocated and therefore ZEROED: announcing it would hand
            // the host a perfectly black framebuffer that reads as a successful
            // capture -- the fabricated-backdoor shape guarded against on the host
            // side. The server's next GraphicsUpdate sets this honestly.
            self.frame_updated = false;
        }

        let out_bytes = output.filled().to_vec();
        if !out_bytes.is_empty() {
            return (STATE_SESSION_NEED_SEND, out_bytes);
        }
        (STATE_SESSION_NEED_RECV, Vec::new())
    }

    /// Send a keyboard key press or release. Returns (state_code, output_bytes_to_send).
    pub fn send_key(&mut self, scancode: u16, pressed: bool) -> (u32, Vec<u8>) {
        // The ActiveStage is mid-renegotiation: its channels and capabilities are
        // being rebuilt, so encoding input against it now is not a keystroke the
        // server will act on. Refuse rather than inject into an unready stage --
        // the host maps this to a visible INDETERMINATE instead of a scan that
        // silently pressed nothing and then read a screen as if it had.
        if self.reactivation.is_some() {
            return (
                STATE_SESSION_ERROR,
                b"input attempted while reactivation is in flight".to_vec(),
            );
        }

        let sc = Scancode::from_u16(scancode);
        let operation = if pressed {
            Operation::KeyPressed(sc)
        } else {
            Operation::KeyReleased(sc)
        };

        let events = self.input_db.apply(std::iter::once(operation));

        match self
            .active_stage
            .process_fastpath_input(&mut self.image, &events)
        {
            Ok(outputs) => {
                let mut response_bytes = Vec::new();
                for output_item in outputs {
                    if let ActiveStageOutput::ResponseFrame(frame) = output_item {
                        response_bytes.extend_from_slice(&frame);
                    }
                }
                (STATE_INPUT_SENT, response_bytes)
            }
            Err(e) => (
                STATE_SESSION_ERROR,
                format!("input error: {}", e).into_bytes(),
            ),
        }
    }

    /// Send a mouse event. Returns (state_code, output_bytes_to_send).
    ///
    /// button: 0=none (move only), 1=left, 2=right, 3=middle
    /// event_type: 0=move, 1=button press, 2=button release
    pub fn send_mouse(
        &mut self,
        x: u16,
        y: u16,
        button: u32,
        event_type: u32,
    ) -> (u32, Vec<u8>) {
        // The ActiveStage is mid-renegotiation: its channels and capabilities are
        // being rebuilt, so encoding input against it now is not a keystroke the
        // server will act on. Refuse rather than inject into an unready stage --
        // the host maps this to a visible INDETERMINATE instead of a scan that
        // silently pressed nothing and then read a screen as if it had.
        if self.reactivation.is_some() {
            return (
                STATE_SESSION_ERROR,
                b"input attempted while reactivation is in flight".to_vec(),
            );
        }

        let mut operations = vec![Operation::MouseMove(MousePosition { x, y })];

        let mouse_btn = match button {
            1 => Some(MouseButton::Left),
            2 => Some(MouseButton::Right),
            3 => Some(MouseButton::Middle),
            _ => None,
        };

        if let Some(btn) = mouse_btn {
            match event_type {
                1 => operations.push(Operation::MouseButtonPressed(btn)),
                2 => operations.push(Operation::MouseButtonReleased(btn)),
                _ => {} // move only
            }
        }

        let events = self.input_db.apply(operations.into_iter());

        match self
            .active_stage
            .process_fastpath_input(&mut self.image, &events)
        {
            Ok(outputs) => {
                let mut response_bytes = Vec::new();
                for output_item in outputs {
                    if let ActiveStageOutput::ResponseFrame(frame) = output_item {
                        response_bytes.extend_from_slice(&frame);
                    }
                }
                (STATE_INPUT_SENT, response_bytes)
            }
            Err(e) => (
                STATE_SESSION_ERROR,
                format!("mouse input error: {}", e).into_bytes(),
            ),
        }
    }

    /// Get the current framebuffer as RGBA pixel data.
    pub fn get_frame_rgba(&self) -> &[u8] {
        self.image.data()
    }

    /// Check and reset the frame-updated flag.
    #[allow(dead_code)]
    pub fn take_frame_updated(&mut self) -> bool {
        let was_updated = self.frame_updated;
        self.frame_updated = false;
        was_updated
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }
}
