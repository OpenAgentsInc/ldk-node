// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Runtime provenance for the OpenAgentsInc `ldk-node` fork.
//!
//! These constants give downstream demo harnesses a narrow compile-time marker
//! that this node runtime was built against the owned `rust-lightning` fork.

/// The OpenAgentsInc `ldk-node` fork repository used for this runtime.
pub const LDK_NODE_FORK_URL: &str = "https://github.com/OpenAgentsInc/ldk-node";

/// The compiled `ldk-node` crate version.
pub const LDK_NODE_CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The OpenAgentsInc `rust-lightning` fork repository used for LDK crates.
pub const RUST_LIGHTNING_FORK_URL: &str = "https://github.com/OpenAgentsInc/rust-lightning";

/// The pinned OpenAgentsInc `rust-lightning` revision used by this fork.
pub const RUST_LIGHTNING_FORK_REV: &str = "a602dda5663c2cfe2ede5754c9bdfe0301aa7e56";

/// Whether this fork is intentionally built against OpenAgentsInc `rust-lightning`.
pub const USES_OPENAGENTS_RUST_LIGHTNING_FORK: bool = true;

/// Whether the fork enables the `simple_taproot_musig2` LDK dependency feature.
pub const SIMPLE_TAPROOT_MUSIG2_FEATURE_ENABLED: bool = true;

/// Whether the fork enables the BOLT simple-close message path needed by simple-taproot channels.
pub const SIMPLE_CLOSE_FEATURE_ENABLED: bool = true;

/// Build provenance reported by the node runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProvenance {
	/// The `ldk-node` fork repository URL.
	pub ldk_node_fork_url: &'static str,
	/// The compiled `ldk-node` crate version.
	pub ldk_node_crate_version: &'static str,
	/// The `rust-lightning` fork repository URL.
	pub rust_lightning_fork_url: &'static str,
	/// The pinned `rust-lightning` fork revision.
	pub rust_lightning_fork_rev: &'static str,
	/// Whether this runtime is built against OpenAgentsInc `rust-lightning`.
	pub uses_openagents_rust_lightning_fork: bool,
	/// Whether the simple-taproot MuSig2 feature is enabled in the compiled runtime.
	pub simple_taproot_musig2_feature_enabled: bool,
	/// Whether the simple-close message path is enabled in the compiled runtime.
	pub simple_close_feature_enabled: bool,
}

/// Returns the fork provenance for this build.
pub fn runtime_provenance() -> RuntimeProvenance {
	RuntimeProvenance {
		ldk_node_fork_url: LDK_NODE_FORK_URL,
		ldk_node_crate_version: LDK_NODE_CRATE_VERSION,
		rust_lightning_fork_url: RUST_LIGHTNING_FORK_URL,
		rust_lightning_fork_rev: RUST_LIGHTNING_FORK_REV,
		uses_openagents_rust_lightning_fork: USES_OPENAGENTS_RUST_LIGHTNING_FORK,
		simple_taproot_musig2_feature_enabled: SIMPLE_TAPROOT_MUSIG2_FEATURE_ENABLED,
		simple_close_feature_enabled: SIMPLE_CLOSE_FEATURE_ENABLED,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reports_openagents_rust_lightning_fork_revision() {
		let _ = core::any::type_name::<lightning::ln::simple_taproot::SimpleTaprootNonceState>();
		let _ = core::any::type_name::<lightning::ln::taproot_asset::TaprootAssetChannelState>();
		let provenance = runtime_provenance();
		assert_eq!(provenance.ldk_node_fork_url, LDK_NODE_FORK_URL);
		assert_eq!(provenance.ldk_node_crate_version, LDK_NODE_CRATE_VERSION);
		assert_eq!(provenance.rust_lightning_fork_url, RUST_LIGHTNING_FORK_URL);
		assert_eq!(provenance.rust_lightning_fork_rev, RUST_LIGHTNING_FORK_REV);
		assert!(provenance.uses_openagents_rust_lightning_fork);
		assert!(provenance.simple_taproot_musig2_feature_enabled);
		assert!(provenance.simple_close_feature_enabled);
	}
}
