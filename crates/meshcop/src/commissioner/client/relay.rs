//! Joiner relay payloads sent from the handle.

use crate::{
    Result,
    meshcop::{self, CommissionerOperation},
};

use super::{
    Commissioner,
    requests::{UNASSIGNED_MESSAGE_ID, UNASSIGNED_TOKEN},
};

impl Commissioner {
    /// Sends a UDP payload to a proxied joiner.
    pub async fn send_to_joiner(&self, joiner_id: &[u8], port: u16, payload: &[u8]) -> Result<()> {
        let (message_id, token) = (UNASSIGNED_MESSAGE_ID, UNASSIGNED_TOKEN);
        let request = meshcop::relay_tx_request(message_id, token, joiner_id, port, 0, payload)?;
        self.execute_no_response(CommissionerOperation::SendToJoiner, request)
            .await
    }
}
