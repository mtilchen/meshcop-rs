//! Commissioner configuration.

use std::time::Duration;

use zeroize::Zeroize;

use crate::{
    Result,
    crypto::{Pskc, pskc_from_active_dataset},
    dataset::Dataset,
    error::Error,
};

const MIN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const MAX_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(45);
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(40);
const DEFAULT_DOMAIN_NAME: &str = "Thread";

/// Commissioner configuration.
#[derive(Clone)]
pub struct CommissionerConfig {
    /// Human-readable commissioner ID.
    pub commissioner_id: String,
    /// PSKc for non-CCM commissioner authentication.
    pub pskc: Pskc,
    /// Cadence applications should use when scheduling commissioner
    /// keep-alives.
    ///
    /// The library does not spawn a background task; applications that keep a
    /// session active must drive [`super::Commissioner::keep_alive`] at this
    /// interval or use an event loop that does so. Values from 30 through 45
    /// seconds are accepted, matching the reference commissioner.
    pub keepalive_interval: Duration,
    /// Domain name reserved for future CCM flows.
    pub domain_name: String,
    /// CCM enable flag reserved for future token/certificate flows.
    pub enable_ccm: bool,
}

impl core::fmt::Debug for CommissionerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommissionerConfig")
            .field("commissioner_id", &self.commissioner_id)
            .field("pskc", &"<redacted>")
            .field("keepalive_interval", &self.keepalive_interval)
            .field("domain_name", &self.domain_name)
            .field("enable_ccm", &self.enable_ccm)
            .finish()
    }
}

impl CommissionerConfig {
    /// Starts building a commissioner configuration.
    pub fn builder(commissioner_id: impl Into<String>) -> CommissionerConfigBuilder {
        CommissionerConfigBuilder::new(commissioner_id)
    }

    /// Creates a PSKc-based commissioner config.
    pub fn pskc(commissioner_id: impl Into<String>, pskc: impl Into<Pskc>) -> Self {
        Self {
            commissioner_id: commissioner_id.into(),
            pskc: pskc.into(),
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            domain_name: DEFAULT_DOMAIN_NAME.to_string(),
            enable_ccm: false,
        }
    }

    /// Creates a config by extracting PSKc from a dataset.
    pub fn from_dataset(commissioner_id: impl Into<String>, dataset: &Dataset) -> Result<Self> {
        Ok(Self::pskc(
            commissioner_id,
            pskc_from_active_dataset(dataset)?,
        ))
    }

    /// Validates the config's bounded fields (currently just the keep-alive
    /// interval, which must fall within the 30-45 second range the reference
    /// commissioner uses). [`super::Commissioner::connect`] calls this
    /// internally; callers may also use it to fail fast before connecting.
    pub fn validate(&self) -> Result<()> {
        if !(MIN_KEEPALIVE_INTERVAL..=MAX_KEEPALIVE_INTERVAL).contains(&self.keepalive_interval) {
            return Err(Error::Configuration(
                "keepalive interval must be between 30 and 45 seconds",
            ));
        }
        Ok(())
    }
}

/// Builder for a validated [`CommissionerConfig`].
pub struct CommissionerConfigBuilder {
    commissioner_id: String,
    pskc: Option<Pskc>,
    keepalive_interval: Duration,
    domain_name: String,
    enable_ccm: bool,
}

impl CommissionerConfigBuilder {
    fn new(commissioner_id: impl Into<String>) -> Self {
        Self {
            commissioner_id: commissioner_id.into(),
            pskc: None,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            domain_name: DEFAULT_DOMAIN_NAME.to_string(),
            enable_ccm: false,
        }
    }

    /// Sets the PSKc used to authenticate the commissioner.
    pub fn pskc(mut self, pskc: Pskc) -> Self {
        self.pskc = Some(pskc);
        self
    }

    /// Extracts and sets the PSKc from an active operational dataset.
    pub fn from_dataset(mut self, dataset: &Dataset) -> Result<Self> {
        self.pskc = Some(pskc_from_active_dataset(dataset)?);
        Ok(self)
    }

    /// Sets the commissioner keep-alive interval.
    pub fn keepalive_interval(mut self, keepalive_interval: Duration) -> Self {
        self.keepalive_interval = keepalive_interval;
        self
    }

    /// Sets the Thread domain name.
    pub fn domain_name(mut self, domain_name: impl Into<String>) -> Self {
        self.domain_name = domain_name.into();
        self
    }

    /// Sets whether CCM authentication is enabled.
    pub fn enable_ccm(mut self, enable_ccm: bool) -> Self {
        self.enable_ccm = enable_ccm;
        self
    }

    /// Builds and validates the commissioner configuration.
    pub fn build(self) -> Result<CommissionerConfig> {
        let config = CommissionerConfig {
            commissioner_id: self.commissioner_id,
            pskc: self
                .pskc
                .ok_or(Error::Configuration("a PSKc is required"))?,
            keepalive_interval: self.keepalive_interval,
            domain_name: self.domain_name,
            enable_ccm: self.enable_ccm,
        };
        config.validate()?;
        Ok(config)
    }
}

impl Drop for CommissionerConfig {
    fn drop(&mut self) {
        self.commissioner_id.zeroize();
        self.domain_name.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MAX_PSKC_LEN;

    #[test]
    fn builder_constructs_a_valid_config() {
        let config = CommissionerConfig::builder("commissioner")
            .pskc(Pskc::new([0x42; MAX_PSKC_LEN]))
            .keepalive_interval(Duration::from_secs(35))
            .domain_name("example")
            .enable_ccm(false)
            .build()
            .unwrap();

        assert_eq!(config.commissioner_id, "commissioner");
        assert_eq!(config.pskc.as_bytes(), &[0x42; MAX_PSKC_LEN]);
        assert_eq!(config.keepalive_interval, Duration::from_secs(35));
        assert_eq!(config.domain_name, "example");
        assert!(!config.enable_ccm);
    }

    #[test]
    fn builder_rejects_an_invalid_keepalive_interval() {
        let result = CommissionerConfig::builder("commissioner")
            .pskc(Pskc::new([0x42; MAX_PSKC_LEN]))
            .keepalive_interval(Duration::from_secs(29))
            .build();

        assert!(matches!(
            result,
            Err(Error::Configuration(
                "keepalive interval must be between 30 and 45 seconds"
            ))
        ));
    }

    #[test]
    fn builder_extracts_pskc_from_a_dataset() {
        let dataset = Dataset::from_hex("0410000102030405060708090a0b0c0d0e0f").unwrap();
        let config = CommissionerConfig::builder("commissioner")
            .from_dataset(&dataset)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            config.pskc.as_bytes(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn builder_requires_a_pskc() {
        assert!(matches!(
            CommissionerConfig::builder("commissioner").build(),
            Err(Error::Configuration("a PSKc is required"))
        ));
    }

    #[test]
    fn config_debug_redacts_the_pskc() {
        let config = CommissionerConfig::pskc("commissioner", [0xab; MAX_PSKC_LEN]);
        let rendered = format!("{config:?}");

        assert_eq!(
            rendered,
            "CommissionerConfig { commissioner_id: \"commissioner\", pskc: \"<redacted>\", \
             keepalive_interval: 40s, domain_name: \"Thread\", enable_ccm: false }"
        );
    }
}
