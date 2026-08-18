//! Operational, commissioner, and Backbone Router dataset operations.

use crate::{
    Result,
    dataset::{ActiveOperationalDataset, Dataset, PendingOperationalDataset},
    error::Error,
    meshcop::{self, CommissionerOperation},
};

use super::super::types::{CommissionerDatasetFlags, DatasetFlags};
use super::{
    Commissioner, check_state_response, require_dataset_tlvs, strip_managed_commissioner_tlvs,
};

impl Commissioner {
    /// Gets the active operational dataset.
    pub async fn get_active_dataset(
        &mut self,
        flags: DatasetFlags,
    ) -> Result<ActiveOperationalDataset> {
        Dataset::from_bytes(&self.get_raw_active_dataset(flags).await?)
    }

    /// Gets the pending operational dataset.
    pub async fn get_pending_dataset(
        &mut self,
        flags: DatasetFlags,
    ) -> Result<PendingOperationalDataset> {
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::dataset_get_request(
            CommissionerOperation::GetPendingDataset,
            message_id,
            token,
            &meshcop::pending_dataset_tlv_types(flags.bits()),
        )?;
        let response = self
            .execute_meshcop(CommissionerOperation::GetPendingDataset, request)
            .await?;
        Dataset::from_bytes(&response.payload)
    }

    /// Gets raw active operational dataset TLVs.
    pub async fn get_raw_active_dataset(&mut self, flags: DatasetFlags) -> Result<Vec<u8>> {
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::dataset_get_request(
            CommissionerOperation::GetActiveDataset,
            message_id,
            token,
            &meshcop::active_dataset_tlv_types(flags.bits()),
        )?;
        let response = self
            .execute_meshcop(CommissionerOperation::GetActiveDataset, request)
            .await?;
        Ok(response.payload)
    }

    /// Sets the active operational dataset.
    ///
    /// The Active Timestamp TLV is mandatory.
    pub async fn set_active_dataset(&mut self, dataset: &ActiveOperationalDataset) -> Result<()> {
        require_dataset_tlvs(
            dataset,
            &[(crate::dataset::TLV_ACTIVE_TIMESTAMP, "Active Timestamp")],
        )?;
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::dataset_set_request(
            CommissionerOperation::SetActiveDataset,
            message_id,
            token,
            session_id,
            dataset,
        )?;
        self.execute_state_operation(CommissionerOperation::SetActiveDataset, request, true)
            .await
    }

    /// Sets the pending operational dataset.
    ///
    /// The Active Timestamp, Pending Timestamp, and Delay Timer TLVs are
    /// mandatory.
    pub async fn set_pending_dataset(&mut self, dataset: &PendingOperationalDataset) -> Result<()> {
        require_dataset_tlvs(
            dataset,
            &[
                (crate::dataset::TLV_ACTIVE_TIMESTAMP, "Active Timestamp"),
                (crate::dataset::TLV_PENDING_TIMESTAMP, "Pending Timestamp"),
                (crate::dataset::TLV_DELAY_TIMER, "Delay Timer"),
            ],
        )?;
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::dataset_set_request(
            CommissionerOperation::SetPendingDataset,
            message_id,
            token,
            session_id,
            dataset,
        )?;
        self.execute_state_operation(CommissionerOperation::SetPendingDataset, request, true)
            .await
    }

    /// Securely disseminates a pending dataset through the Primary BBR.
    ///
    /// The Pending Timestamp (carried in the Secure Dissemination TLV) and
    /// Delay Timer TLVs are mandatory.
    pub async fn set_secure_pending_dataset(
        &mut self,
        max_retrieval_timer: u32,
        dataset: &PendingOperationalDataset,
    ) -> Result<()> {
        require_dataset_tlvs(
            dataset,
            &[
                (crate::dataset::TLV_PENDING_TIMESTAMP, "Pending Timestamp"),
                (crate::dataset::TLV_DELAY_TIMER, "Delay Timer"),
            ],
        )?;
        let session_id = self.session_id_required()?;
        let pbbr = self.primary_bbr_aloc().await?;
        let retrieval_uri = format!("coaps://[{pbbr}]{}", meshcop::uri::MGMT_PENDING_GET);
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::secure_pending_set_request(
            message_id,
            token,
            session_id,
            max_retrieval_timer,
            &retrieval_uri,
            dataset,
        )?;
        let response = self
            .execute_proxied(
                CommissionerOperation::SetSecurePendingDataset,
                request,
                pbbr,
            )
            .await?;
        check_state_response(&response, true)
    }

    /// Gets the commissioner dataset from the leader.
    pub async fn get_commissioner_dataset(
        &mut self,
        flags: CommissionerDatasetFlags,
    ) -> Result<Dataset> {
        let leader = self.leader_aloc().await?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::dataset_get_request(
            CommissionerOperation::GetCommissionerDataset,
            message_id,
            token,
            &meshcop::commissioner_dataset_tlv_types(flags.bits()),
        )?;
        let response = self
            .execute_proxied(
                CommissionerOperation::GetCommissionerDataset,
                request,
                leader,
            )
            .await?;
        Dataset::from_bytes(&response.payload)
    }

    /// Sets the commissioner dataset on the leader.
    ///
    /// The Commissioner Session ID and Border Agent Locator TLVs are managed
    /// by the protocol and are removed from `dataset` before sending.
    pub async fn set_commissioner_dataset(&mut self, dataset: &Dataset) -> Result<()> {
        let session_id = self.session_id_required()?;
        let dataset = strip_managed_commissioner_tlvs(dataset);
        if dataset.entries().is_empty() {
            return Err(Error::Dataset(
                "commissioner dataset has no settable TLVs".to_string(),
            ));
        }
        let leader = self.leader_aloc().await?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::dataset_set_request(
            CommissionerOperation::SetCommissionerDataset,
            message_id,
            token,
            session_id,
            &dataset,
        )?;
        let response = self
            .execute_proxied(
                CommissionerOperation::SetCommissionerDataset,
                request,
                leader,
            )
            .await?;
        check_state_response(&response, true)
    }

    /// Adds a joiner to the network steering data.
    ///
    /// The current steering data is fetched from the leader, the joiner ID is
    /// added to its Bloom filter, and the result is written back through
    /// MGMT_COMMISSIONER_SET. PSKd provisioning stays with the configured
    /// [`JoinerHandler`](super::super::JoinerHandler).
    pub async fn enable_joiner(&mut self, joiner_id: &[u8; 8]) -> Result<()> {
        let current = self
            .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
            .await?;
        let mut steering_data = current
            .raw(meshcop::TLV_STEERING_DATA)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        crate::crypto::add_joiner_to_steering_data(&mut steering_data, joiner_id);
        let mut dataset = Dataset::default();
        dataset.set_raw(meshcop::TLV_STEERING_DATA, steering_data);
        self.set_commissioner_dataset(&dataset).await
    }

    /// Opens steering to every joiner, or closes it for all joiners.
    pub async fn enable_all_joiners(&mut self, enable: bool) -> Result<()> {
        let steering_data = if enable { vec![0xff] } else { vec![0x00] };
        let mut dataset = Dataset::default();
        dataset.set_raw(meshcop::TLV_STEERING_DATA, steering_data);
        self.set_commissioner_dataset(&dataset).await
    }

    /// Gets the Backbone Router dataset.
    pub async fn get_bbr_dataset(&mut self, flags: CommissionerDatasetFlags) -> Result<Dataset> {
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::dataset_get_request(
            CommissionerOperation::GetBbrDataset,
            message_id,
            token,
            &meshcop::commissioner_dataset_tlv_types(flags.bits()),
        )?;
        let response = self
            .execute_meshcop(CommissionerOperation::GetBbrDataset, request)
            .await?;
        Dataset::from_bytes(&response.payload)
    }

    /// Sets the Backbone Router dataset.
    pub async fn set_bbr_dataset(&mut self, dataset: &Dataset) -> Result<()> {
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::dataset_set_request(
            CommissionerOperation::SetBbrDataset,
            message_id,
            token,
            session_id,
            dataset,
        )?;
        self.execute_state_operation(CommissionerOperation::SetBbrDataset, request, true)
            .await
    }
}
