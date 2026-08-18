//! Scan, query, and managed-device commands routed through the UDP proxy.

use std::net::Ipv6Addr;

use crate::{
    Result,
    error::Error,
    meshcop::{self, CommissionerOperation},
    tlv::TlvSet,
};

use super::Commissioner;

impl Commissioner {
    /// Starts an announce-begin operation on `destination`.
    ///
    /// Multicast destinations use non-confirmable signaling and return as soon
    /// as the request is forwarded.
    pub async fn announce_begin(
        &mut self,
        channel_mask: u32,
        count: u8,
        period_ms: u16,
        destination: Ipv6Addr,
    ) -> Result<()> {
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::announce_begin_request(
            message_id,
            token,
            session_id,
            channel_mask,
            count,
            period_ms,
            !destination.is_multicast(),
        )?;
        self.execute_proxied_command(CommissionerOperation::AnnounceBegin, request, destination)
            .await
    }

    /// Starts a PAN ID query on `destination`.
    ///
    /// Conflicts are reported through
    /// [`CommissionerEvent::PanIdConflict`](super::super::CommissionerEvent::PanIdConflict).
    pub async fn pan_id_query(
        &mut self,
        channel_mask: u32,
        pan_id: u16,
        destination: Ipv6Addr,
    ) -> Result<()> {
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::pan_id_query_request(
            message_id,
            token,
            session_id,
            channel_mask,
            pan_id,
            !destination.is_multicast(),
        )?;
        self.execute_proxied_command(CommissionerOperation::PanIdQuery, request, destination)
            .await
    }

    /// Starts an energy scan on `destination`.
    ///
    /// Reports are delivered through
    /// [`CommissionerEvent::EnergyReport`](super::super::CommissionerEvent::EnergyReport).
    pub async fn energy_scan(
        &mut self,
        channel_mask: u32,
        count: u8,
        period_ms: u16,
        scan_duration_ms: u16,
        destination: Ipv6Addr,
    ) -> Result<()> {
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::energy_scan_request(
            message_id,
            token,
            session_id,
            meshcop::EnergyScanRequest {
                channel_mask,
                count,
                period_ms,
                scan_duration_ms,
                confirmable: !destination.is_multicast(),
            },
        )?;
        self.execute_proxied_command(CommissionerOperation::EnergyScan, request, destination)
            .await
    }

    /// Registers multicast listeners through the Primary Backbone Router.
    pub async fn register_multicast_listener(
        &mut self,
        addresses: &[String],
        timeout: u32,
    ) -> Result<u8> {
        let session_id = self.session_id_required()?;
        let addresses = addresses
            .iter()
            .map(|address| {
                address
                    .parse::<Ipv6Addr>()
                    .map_err(|_| Error::Dataset(format!("{address} is not a valid IPv6 address")))
            })
            .collect::<Result<Vec<_>>>()?;
        let pbbr = self.primary_bbr_aloc().await?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::multicast_listener_request(
            message_id, token, session_id, &addresses, timeout,
        )?;
        let response = self
            .execute_proxied(
                CommissionerOperation::RegisterMulticastListener,
                request,
                pbbr,
            )
            .await?;
        let tlvs = TlvSet::parse(&response.payload)?;
        let status = tlvs
            .last_value(meshcop::THREAD_TLV_STATUS)
            .ok_or(Error::InvalidState("MLR response did not include status"))?;
        match status {
            [status] => Ok(*status),
            _ => Err(Error::Dataset("MLR Status TLV must be 1 byte".to_string())),
        }
    }

    /// Commands a device to reenroll.
    ///
    /// The request is forwarded to `destination` through the UDP proxy.
    /// Multicast destinations use non-confirmable signaling and return as soon
    /// as the request is forwarded.
    pub async fn command_reenroll(&mut self, destination: Ipv6Addr) -> Result<()> {
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::session_command_request(
            CommissionerOperation::Reenroll,
            message_id,
            token,
            session_id,
            !destination.is_multicast(),
        )?;
        self.execute_proxied_command(CommissionerOperation::Reenroll, request, destination)
            .await
    }

    /// Commands a device to reset from the current domain.
    ///
    /// The request is forwarded to `destination` through the UDP proxy.
    pub async fn command_domain_reset(&mut self, destination: Ipv6Addr) -> Result<()> {
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::session_command_request(
            CommissionerOperation::DomainReset,
            message_id,
            token,
            session_id,
            !destination.is_multicast(),
        )?;
        self.execute_proxied_command(CommissionerOperation::DomainReset, request, destination)
            .await
    }

    /// Commands a device to migrate to a designated network.
    ///
    /// The request is forwarded to `destination` through the UDP proxy.
    pub async fn command_migrate(
        &mut self,
        destination: Ipv6Addr,
        designated_network: &str,
    ) -> Result<()> {
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::migrate_request(
            message_id,
            token,
            session_id,
            designated_network,
            !destination.is_multicast(),
        )?;
        self.execute_proxied_command(CommissionerOperation::Migrate, request, destination)
            .await
    }
}
