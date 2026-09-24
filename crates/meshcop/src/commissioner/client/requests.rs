//! Request submission from the handle to the session driver, plus the
//! mesh-local prefix cache used for ALOC routing.

use std::net::Ipv6Addr;

use tokio::sync::{mpsc, oneshot};

use crate::{
    Result,
    dataset::Dataset,
    error::Error,
    meshcop::{self, CoapMessage, CommissionerOperation},
};

use super::super::types::{DatasetFlags, Destination};
use super::{
    Commissioner, aloc_address, check_state_response, driver::Command, driver::Outbound,
    require_success_response,
};

/// Message ID of a request under construction; the driver assigns the real
/// one when it sends the request.
pub(super) const UNASSIGNED_MESSAGE_ID: u16 = 0;
/// Token of a request under construction; the driver assigns the real one.
pub(super) const UNASSIGNED_TOKEN: [u8; 0] = [];

impl Commissioner {
    /// Sends a raw MeshCoP request and returns its response.
    ///
    /// This is the escape hatch for MeshCoP resources without a typed method.
    /// The session assigns the message ID and token, retransmits a
    /// confirmable request, and matches the response, exactly as for the typed
    /// operations. A [`Destination::Mesh`] request travels through the border
    /// agent's UDP proxy and is answered through UDP_RX. The response is
    /// returned whatever its code; the call fails with [`Error::Timeout`] if
    /// no response arrives.
    pub async fn request(
        &self,
        destination: Destination,
        request: CoapMessage,
    ) -> Result<CoapMessage> {
        self.submit(Outbound {
            message: request,
            destination,
            expect_response: true,
            label: "request",
        })
        .await?
        .ok_or(Error::InvalidState("MeshCoP exchange produced no response"))
    }

    /// Submits a request to the driver and waits for its outcome.
    ///
    /// Dropping the returned future withdraws the request: a queued request
    /// is never sent, and a sent one stops being retransmitted and frees its
    /// place for the next request.
    async fn submit(&self, request: Outbound) -> Result<Option<CoapMessage>> {
        let id = self.shared.next_exchange_id();
        let (reply, response) = oneshot::channel();
        self.send_command(Command::Exchange { id, request, reply })?;
        let _withdraw = WithdrawOnDrop {
            commands: &self.commands,
            id,
        };
        response.await.map_err(|_| Error::SessionClosed)?
    }

    /// Returns the cached mesh-local prefix, fetching it from the active
    /// dataset when needed.
    async fn require_mesh_local_prefix(&self) -> Result<[u8; 8]> {
        let generation = {
            let cache = self.shared.mesh_local_prefix();
            if let Some(prefix) = cache.prefix {
                return Ok(prefix);
            }
            cache.generation
        };
        let raw = self
            .get_raw_active_dataset(DatasetFlags::MESH_LOCAL_PREFIX)
            .await?;
        let dataset = Dataset::from_bytes(&raw)?;
        let prefix = dataset.mesh_local_prefix()?.ok_or(Error::InvalidState(
            "active dataset does not include the mesh-local prefix",
        ))?;
        if prefix[0] != 0xfd {
            return Err(Error::Dataset(
                "mesh-local prefix must be within fd00::/8".to_string(),
            ));
        }
        let mut cache = self.shared.mesh_local_prefix();
        // A dataset change during the fetch may have moved the prefix; use
        // what was read, but only cache it if nothing invalidated it since.
        if cache.generation == generation {
            cache.prefix = Some(prefix);
        }
        Ok(prefix)
    }

    /// Returns the anycast address of the Thread leader.
    pub(super) async fn leader_aloc(&self) -> Result<Ipv6Addr> {
        let prefix = self.require_mesh_local_prefix().await?;
        Ok(aloc_address(prefix, meshcop::LEADER_ALOC16))
    }

    /// Returns the anycast address of the Primary Backbone Router.
    pub(super) async fn primary_bbr_aloc(&self) -> Result<Ipv6Addr> {
        let prefix = self.require_mesh_local_prefix().await?;
        Ok(aloc_address(prefix, meshcop::PRIMARY_BBR_ALOC16))
    }

    pub(super) async fn execute_state_operation(
        &self,
        operation: CommissionerOperation,
        request: CoapMessage,
        state_mandatory: bool,
    ) -> Result<()> {
        let response = self.execute_meshcop(operation, request).await?;
        check_state_response(&response, state_mandatory)
    }

    /// Executes a direct border-agent exchange and returns the response.
    pub(super) async fn execute_meshcop(
        &self,
        operation: CommissionerOperation,
        request: CoapMessage,
    ) -> Result<CoapMessage> {
        self.execute(operation, request, Destination::BorderAgent, true)
            .await?
            .ok_or(Error::InvalidState("MeshCoP exchange produced no response"))
            .and_then(require_success_response)
    }

    /// Executes a UDP-proxied exchange and returns the inner response.
    pub(super) async fn execute_proxied(
        &self,
        operation: CommissionerOperation,
        request: CoapMessage,
        destination: Ipv6Addr,
    ) -> Result<CoapMessage> {
        self.execute(operation, request, mesh_management(destination), true)
            .await?
            .ok_or(Error::InvalidState("MeshCoP exchange produced no response"))
            .and_then(require_success_response)
    }

    /// Executes a proxied command, waiting for a response only when the inner
    /// request is confirmable.
    pub(super) async fn execute_proxied_command(
        &self,
        operation: CommissionerOperation,
        request: CoapMessage,
        destination: Ipv6Addr,
    ) -> Result<()> {
        let wait_for_response = request.ty == meshcop::CoapType::Confirmable;
        match self
            .execute(
                operation,
                request,
                mesh_management(destination),
                wait_for_response,
            )
            .await?
        {
            Some(response) => check_state_response(&response, false),
            None => Ok(()),
        }
    }

    /// Sends a direct request without waiting for any response.
    pub(super) async fn execute_no_response(
        &self,
        operation: CommissionerOperation,
        request: CoapMessage,
    ) -> Result<()> {
        self.execute(operation, request, Destination::BorderAgent, false)
            .await
            .map(|_| ())
    }

    async fn execute(
        &self,
        operation: CommissionerOperation,
        request: CoapMessage,
        destination: Destination,
        expect_response: bool,
    ) -> Result<Option<CoapMessage>> {
        self.submit(Outbound {
            message: request,
            destination,
            expect_response,
            label: operation.label(),
        })
        .await
    }
}

/// Routes to the Thread management port of a mesh destination.
const fn mesh_management(address: Ipv6Addr) -> Destination {
    Destination::Mesh {
        address,
        port: meshcop::DEFAULT_MM_PORT,
    }
}

/// Withdraws a submitted request when its caller stops waiting for it.
///
/// It also fires after the outcome has arrived; the driver has forgotten the
/// request by then, so the withdrawal does nothing.
struct WithdrawOnDrop<'a> {
    commands: &'a mpsc::UnboundedSender<Command>,
    id: u64,
}

impl Drop for WithdrawOnDrop<'_> {
    fn drop(&mut self) {
        // The driver may already have stopped; then there is nothing to
        // withdraw.
        let _ = self.commands.send(Command::Withdraw(self.id));
    }
}
