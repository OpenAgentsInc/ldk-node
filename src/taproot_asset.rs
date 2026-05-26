#![allow(missing_docs)]

//! Experimental Taproot Asset channel APIs for the OpenAgentsInc fork.
//!
//! This module is deliberately opt-in and bounded. It exposes the live node
//! runtime surfaces needed by `tap-ldk` while keeping normal BTC-only `ldk-node`
//! behavior unchanged by default.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::io::ErrorKind;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};
use bitcoin::taproot::{LeafVersion, TapNodeHash};
use bitcoin::ScriptBuf;
use lightning::chain::transaction::OutPoint as LdkOutPoint;
use lightning::ln::msgs::DecodeError;
use lightning::ln::taproot_asset::{
	single_asset_channel_type, TaprootAssetChannelDescriptor, TaprootAssetChannelState,
	TaprootAssetChannelStateError, TaprootAssetFundingAllocation, TaprootAssetFundingExpectations,
	TaprootAssetFundingOutput, TaprootAssetFundingProofMaterial, TaprootAssetFundingRequest,
	TaprootAssetHtlcMetadata, TaprootAssetHtlcMetadataError, TaprootAssetHtlcMetadataExpectation,
	TaprootAssetMonitorAuxBlob, TaprootAssetMonitorAuxBlobError, TAPROOT_ASSET_ID_LEN,
};
use lightning::ln::types::ChannelId;
use lightning::ln::wire::Type;
use lightning::util::persist::KVStoreSync;
use lightning::util::ser::{LengthLimitedRead, Writeable, Writer};
use lightning_types::features::InitFeatures;
use serde::{Deserialize, Serialize};
use taproot_assets_core::verify::proof::verify_inclusion_proof;
use taproot_assets_core::verify::taproot_proof::TapCommitment;
use taproot_assets_core::{OpsError, TaprootOps};
use taproot_assets_types::asset::SerializedKey;
use taproot_assets_types::commitment::TapCommitmentVersion;
use taproot_assets_types::proof::Proof as TaprootAssetProof;

use crate::config::ExperimentalChannelConfig;
use crate::hex_utils;
use crate::types::{ChannelManager, DynStore};

const TAPROOT_ASSET_PRIMARY_NAMESPACE: &str = "taproot_asset";
const TAPROOT_ASSET_SECONDARY_NAMESPACE: &str = "runtime";
const TAPROOT_ASSET_STATE_KEY: &str = "state";
const TAPROOT_ASSET_AUX_FEATURE_BITS_TLV: u64 = 65_545;
const TAPROOT_ASSET_AUX_FEATURE_BITS_VALUE: [u8; 3] = [0, 1, 0x0a];

pub const TAP_MESSAGE_TYPE_BASE_OFFSET: u16 = 32_768 + 20_116;
pub const TAP_CHANNEL_MESSAGE_TYPE_OFFSET: u16 = TAP_MESSAGE_TYPE_BASE_OFFSET + 256;
pub const TX_ASSET_INPUT_PROOF_TYPE: u16 = TAP_CHANNEL_MESSAGE_TYPE_OFFSET;
pub const TX_ASSET_OUTPUT_PROOF_TYPE: u16 = TAP_CHANNEL_MESSAGE_TYPE_OFFSET + 1;
pub const ASSET_FUNDING_CREATED_TYPE: u16 = TAP_CHANNEL_MESSAGE_TYPE_OFFSET + 2;
pub const ASSET_FUNDING_ACCEPTED_TYPE: u16 = TAP_CHANNEL_MESSAGE_TYPE_OFFSET + 3;
pub const RFQ_REQUEST_TYPE: u16 = TAP_CHANNEL_MESSAGE_TYPE_OFFSET + 64;
pub const RFQ_ACCEPT_TYPE: u16 = TAP_CHANNEL_MESSAGE_TYPE_OFFSET + 65;
pub const RFQ_REJECT_TYPE: u16 = TAP_CHANNEL_MESSAGE_TYPE_OFFSET + 66;
pub const ASSET_HTLC_BLOB_TYPE: u16 = TAP_CHANNEL_MESSAGE_TYPE_OFFSET + 96;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum TaprootAssetMessageKind {
	TxAssetInputProof,
	TxAssetOutputProof,
	AssetFundingCreated,
	AssetFundingAccepted,
	RfqRequest,
	RfqAccept,
	RfqReject,
	AssetHtlcBlob,
}

impl TaprootAssetMessageKind {
	pub fn message_type(self) -> u16 {
		match self {
			Self::TxAssetInputProof => TX_ASSET_INPUT_PROOF_TYPE,
			Self::TxAssetOutputProof => TX_ASSET_OUTPUT_PROOF_TYPE,
			Self::AssetFundingCreated => ASSET_FUNDING_CREATED_TYPE,
			Self::AssetFundingAccepted => ASSET_FUNDING_ACCEPTED_TYPE,
			Self::RfqRequest => RFQ_REQUEST_TYPE,
			Self::RfqAccept => RFQ_ACCEPT_TYPE,
			Self::RfqReject => RFQ_REJECT_TYPE,
			Self::AssetHtlcBlob => ASSET_HTLC_BLOB_TYPE,
		}
	}

	pub fn from_message_type(message_type: u16) -> Option<Self> {
		match message_type {
			TX_ASSET_INPUT_PROOF_TYPE => Some(Self::TxAssetInputProof),
			TX_ASSET_OUTPUT_PROOF_TYPE => Some(Self::TxAssetOutputProof),
			ASSET_FUNDING_CREATED_TYPE => Some(Self::AssetFundingCreated),
			ASSET_FUNDING_ACCEPTED_TYPE => Some(Self::AssetFundingAccepted),
			RFQ_REQUEST_TYPE => Some(Self::RfqRequest),
			RFQ_ACCEPT_TYPE => Some(Self::RfqAccept),
			RFQ_REJECT_TYPE => Some(Self::RfqReject),
			ASSET_HTLC_BLOB_TYPE => Some(Self::AssetHtlcBlob),
			_ => None,
		}
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TaprootAssetWireMessage {
	pub kind: TaprootAssetMessageKind,
	pub payload: Vec<u8>,
}

impl Writeable for TaprootAssetWireMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), bitcoin::io::Error> {
		w.write_all(&self.payload)
	}
}

impl Type for TaprootAssetWireMessage {
	fn type_id(&self) -> u16 {
		self.kind.message_type()
	}
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaprootAssetQueuedMessage {
	pub counterparty_node_id: String,
	pub kind: TaprootAssetMessageKind,
	pub payload_len: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaprootAssetReceivedMessage {
	pub sender_node_id: String,
	pub kind: TaprootAssetMessageKind,
	pub payload: Vec<u8>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TaprootAssetChannelOpenRequest {
	pub counterparty_node_id: PublicKey,
	pub channel_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub pending_channel_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub funding_outpoint: LdkOutPoint,
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub genesis_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub group_key: Option<[u8; TAPROOT_ASSET_ID_LEN]>,
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	pub proof_root_sum: u64,
	pub output_commitment: [u8; TAPROOT_ASSET_ID_LEN],
	pub local_amount: u64,
	pub remote_amount: u64,
	pub complete_fragment_count: u16,
	pub expected_fragment_count: u16,
	pub monitor_aux: TaprootAssetMonitorAuxRequest,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TaprootAssetMonitorAuxRequest {
	pub state_digest: [u8; TAPROOT_ASSET_ID_LEN],
	pub nonce_digest: [u8; TAPROOT_ASSET_ID_LEN],
	pub signature_digest: [u8; TAPROOT_ASSET_ID_LEN],
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TaprootAssetPaymentDirection {
	LocalToRemote,
	RemoteToLocal,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TaprootAssetPaymentMetadata {
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub asset_amount: u64,
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	pub proof_root_sum: u64,
	pub quote_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub payment_hash: [u8; TAPROOT_ASSET_ID_LEN],
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TaprootAssetPaymentRequest {
	pub channel_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub payment_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub direction: TaprootAssetPaymentDirection,
	pub expected: TaprootAssetPaymentMetadata,
	pub metadata: Option<TaprootAssetPaymentMetadata>,
	pub quote_accepted: bool,
	pub now_unix_seconds: u64,
	pub quote_expiry_unix_seconds: u64,
	pub monitor_aux: Option<TaprootAssetMonitorAuxRequest>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaprootAssetChannelStatus {
	pub channel_id: String,
	pub counterparty_node_id: String,
	pub funding_outpoint: String,
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub local_balance: u64,
	pub remote_balance: u64,
	pub total_amount: u64,
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	pub proof_root_sum: u64,
	pub latest_commitment_number: u64,
	pub funding_accepted: bool,
	pub monitor_aux_persisted: bool,
	pub closed: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaprootAssetPaymentStatus {
	pub payment_id: String,
	pub channel_id: String,
	pub direction: String,
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub asset_amount: u64,
	pub quote_id: [u8; TAPROOT_ASSET_ID_LEN],
	pub payment_hash: [u8; TAPROOT_ASSET_ID_LEN],
	pub status: String,
	pub latest_commitment_number: u64,
	pub local_balance_after: u64,
	pub remote_balance_after: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum TaprootAssetRuntimeEvent {
	MessageReceived {
		sender_node_id: String,
		kind: TaprootAssetMessageKind,
	},
	MessageQueued {
		counterparty_node_id: String,
		kind: TaprootAssetMessageKind,
	},
	FundingAccepted {
		channel_id: String,
		asset_id: [u8; TAPROOT_ASSET_ID_LEN],
		total_amount: u64,
	},
	CommitmentAdvanced {
		channel_id: String,
		commitment_number: u64,
		local_balance: u64,
		remote_balance: u64,
	},
	HtlcAdded {
		payment_id: String,
		channel_id: String,
		asset_amount: u64,
	},
	HtlcSettled {
		payment_id: String,
		channel_id: String,
	},
	HtlcFailed {
		payment_id: String,
		channel_id: String,
		reason: String,
	},
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct TaprootAssetPersistedState {
	channels: BTreeMap<String, TaprootAssetChannelStatus>,
	payments: BTreeMap<String, TaprootAssetPaymentStatus>,
	received_messages: Vec<TaprootAssetReceivedMessage>,
	events: Vec<TaprootAssetRuntimeEvent>,
}

impl Default for TaprootAssetPersistedState {
	fn default() -> Self {
		Self {
			channels: BTreeMap::new(),
			payments: BTreeMap::new(),
			received_messages: Vec::new(),
			events: Vec::new(),
		}
	}
}

#[derive(Debug)]
pub enum TaprootAssetError {
	NotEnabled,
	InvalidChannelConfig,
	PersistenceFailed,
	DuplicateChannel,
	UnknownChannel,
	DuplicatePayment,
	MissingAssetMetadata,
	MissingMonitorAuxState,
	MissingChannelManager,
	TaprootAssetProof(String),
	ChannelManager(String),
	LdkChannelState(TaprootAssetChannelStateError),
	LdkHtlc(TaprootAssetHtlcMetadataError),
	LdkMonitor(TaprootAssetMonitorAuxBlobError),
	DecodeFailed,
}

impl fmt::Display for TaprootAssetError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::NotEnabled => write!(f, "Taproot Asset support is not enabled"),
			Self::InvalidChannelConfig => write!(f, "invalid Taproot Asset channel config"),
			Self::PersistenceFailed => write!(f, "Taproot Asset state persistence failed"),
			Self::DuplicateChannel => write!(f, "duplicate Taproot Asset channel"),
			Self::UnknownChannel => write!(f, "unknown Taproot Asset channel"),
			Self::DuplicatePayment => write!(f, "duplicate Taproot Asset payment"),
			Self::MissingAssetMetadata => write!(f, "missing Taproot Asset HTLC metadata"),
			Self::MissingMonitorAuxState => write!(f, "missing Taproot Asset monitor aux state"),
			Self::MissingChannelManager => {
				write!(f, "missing Taproot Asset channel manager bridge")
			},
			Self::TaprootAssetProof(err) => write!(f, "Taproot Asset proof error: {err}"),
			Self::ChannelManager(err) => write!(f, "LDK channel manager error: {err}"),
			Self::LdkChannelState(err) => write!(f, "LDK Taproot Asset channel error: {err:?}"),
			Self::LdkHtlc(err) => write!(f, "LDK Taproot Asset HTLC error: {err:?}"),
			Self::LdkMonitor(err) => write!(f, "LDK Taproot Asset monitor error: {err:?}"),
			Self::DecodeFailed => write!(f, "Taproot Asset message decode failed"),
		}
	}
}

impl std::error::Error for TaprootAssetError {}

pub struct TaprootAsset {
	manager: Arc<TaprootAssetManager>,
	local_node_id: PublicKey,
}

impl TaprootAsset {
	pub(crate) fn new(manager: Arc<TaprootAssetManager>, local_node_id: PublicKey) -> Self {
		Self { manager, local_node_id }
	}

	pub fn send_message(
		&self, counterparty_node_id: PublicKey, kind: TaprootAssetMessageKind, payload: Vec<u8>,
	) -> Result<TaprootAssetQueuedMessage, TaprootAssetError> {
		self.manager.queue_message(counterparty_node_id, kind, payload)
	}

	pub fn list_received_messages(&self) -> Vec<TaprootAssetReceivedMessage> {
		self.manager.list_received_messages()
	}

	pub fn open_channel(
		&self, request: TaprootAssetChannelOpenRequest,
	) -> Result<TaprootAssetChannelStatus, TaprootAssetError> {
		self.manager.open_channel(self.local_node_id, request)
	}

	pub fn send_payment(
		&self, request: TaprootAssetPaymentRequest,
	) -> Result<TaprootAssetPaymentStatus, TaprootAssetError> {
		self.manager.apply_payment(request)
	}

	pub fn receive_payment(
		&self, request: TaprootAssetPaymentRequest,
	) -> Result<TaprootAssetPaymentStatus, TaprootAssetError> {
		self.manager.apply_payment(request)
	}

	pub fn list_channels(&self) -> Vec<TaprootAssetChannelStatus> {
		self.manager.list_channels()
	}

	pub fn list_payments(&self) -> Vec<TaprootAssetPaymentStatus> {
		self.manager.list_payments()
	}

	pub fn list_events(&self) -> Vec<TaprootAssetRuntimeEvent> {
		self.manager.list_events()
	}
}

pub(crate) struct TaprootAssetManager {
	enabled: bool,
	config: ExperimentalChannelConfig,
	kv_store: Arc<DynStore>,
	channel_manager: Option<Arc<ChannelManager>>,
	state: Mutex<TaprootAssetPersistedState>,
	pending_messages: Mutex<VecDeque<(PublicKey, TaprootAssetWireMessage)>>,
}

impl TaprootAssetManager {
	#[cfg(test)]
	pub(crate) fn new(config: ExperimentalChannelConfig, kv_store: Arc<DynStore>) -> Self {
		Self::new_inner(config, kv_store, None)
	}

	pub(crate) fn with_channel_manager(
		config: ExperimentalChannelConfig, kv_store: Arc<DynStore>,
		channel_manager: Arc<ChannelManager>,
	) -> Self {
		Self::new_inner(config, kv_store, Some(channel_manager))
	}

	fn new_inner(
		config: ExperimentalChannelConfig, kv_store: Arc<DynStore>,
		channel_manager: Option<Arc<ChannelManager>>,
	) -> Self {
		let state = KVStoreSync::read(
			&*kv_store,
			TAPROOT_ASSET_PRIMARY_NAMESPACE,
			TAPROOT_ASSET_SECONDARY_NAMESPACE,
			TAPROOT_ASSET_STATE_KEY,
		)
		.ok()
		.and_then(|raw| serde_json::from_slice::<TaprootAssetPersistedState>(&raw).ok())
		.unwrap_or_default();
		Self {
			enabled: config.negotiate_taproot_asset_channels,
			config,
			kv_store,
			channel_manager,
			state: Mutex::new(state),
			pending_messages: Mutex::new(VecDeque::new()),
		}
	}

	pub(crate) fn read_message<R: LengthLimitedRead>(
		&self, message_type: u16, buffer: &mut R,
	) -> Result<Option<TaprootAssetWireMessage>, DecodeError> {
		if !self.enabled {
			return Ok(None);
		}
		let Some(kind) = TaprootAssetMessageKind::from_message_type(message_type) else {
			return Ok(None);
		};
		let remaining = buffer.remaining_bytes();
		if remaining > usize::MAX as u64 {
			return Err(DecodeError::BadLengthDescriptor);
		}
		let mut payload = vec![0u8; remaining as usize];
		buffer.read_exact(&mut payload).map_err(|err| match err.kind() {
			ErrorKind::UnexpectedEof => DecodeError::ShortRead,
			kind => DecodeError::Io(kind),
		})?;
		Ok(Some(TaprootAssetWireMessage { kind, payload }))
	}

	pub(crate) fn handle_message(
		&self, msg: TaprootAssetWireMessage, sender_node_id: PublicKey,
	) -> Result<(), lightning::ln::msgs::LightningError> {
		self.record_received_message(sender_node_id, msg.clone()).map_err(|err| {
			lightning::ln::msgs::LightningError {
				err: err.to_string(),
				action: lightning::ln::msgs::ErrorAction::IgnoreError,
			}
		})?;

		if msg.kind == TaprootAssetMessageKind::AssetFundingCreated {
			self.bind_asset_funding_created(sender_node_id, &msg.payload).map_err(|err| {
				lightning::ln::msgs::LightningError {
					err: err.to_string(),
					action: lightning::ln::msgs::ErrorAction::IgnoreError,
				}
			})?;
		}

		if let Some(ack_payload) = funding_ack_for_output_proof(&msg).map_err(|err| {
			lightning::ln::msgs::LightningError {
				err: err.to_string(),
				action: lightning::ln::msgs::ErrorAction::IgnoreError,
			}
		})? {
			self.queue_message(
				sender_node_id,
				TaprootAssetMessageKind::AssetFundingAccepted,
				ack_payload,
			)
			.map_err(|err| lightning::ln::msgs::LightningError {
				err: err.to_string(),
				action: lightning::ln::msgs::ErrorAction::IgnoreError,
			})?;
		}

		Ok(())
	}

	pub(crate) fn get_and_clear_pending_messages(
		&self,
	) -> Vec<(PublicKey, TaprootAssetWireMessage)> {
		self.pending_messages.lock().expect("lock").drain(..).collect()
	}

	fn bind_asset_funding_created(
		&self, sender_node_id: PublicKey, payload: &[u8],
	) -> Result<(), TaprootAssetError> {
		let fields = parse_asset_funding_created_fields(payload)?;
		let tapscript_root = derive_asset_funding_tapscript_root(&fields.outputs)?;
		let channel_manager =
			self.channel_manager.as_ref().ok_or(TaprootAssetError::MissingChannelManager)?;
		channel_manager
			.set_pending_simple_taproot_tapscript_root(
				ChannelId(fields.pending_channel_id),
				sender_node_id,
				tapscript_root,
			)
			.map_err(|err| TaprootAssetError::ChannelManager(format!("{err:?}")))
	}

	fn queue_message(
		&self, counterparty_node_id: PublicKey, kind: TaprootAssetMessageKind, payload: Vec<u8>,
	) -> Result<TaprootAssetQueuedMessage, TaprootAssetError> {
		self.ensure_enabled()?;
		let queued = TaprootAssetQueuedMessage {
			counterparty_node_id: counterparty_node_id.to_string(),
			kind,
			payload_len: payload.len(),
		};
		self.pending_messages
			.lock()
			.expect("lock")
			.push_back((counterparty_node_id, TaprootAssetWireMessage { kind, payload }));
		let mut state = self.state.lock().expect("lock");
		state.events.push(TaprootAssetRuntimeEvent::MessageQueued {
			counterparty_node_id: queued.counterparty_node_id.clone(),
			kind,
		});
		self.persist_locked(&state)?;
		Ok(queued)
	}

	fn record_received_message(
		&self, sender_node_id: PublicKey, msg: TaprootAssetWireMessage,
	) -> Result<(), TaprootAssetError> {
		self.ensure_enabled()?;
		let mut state = self.state.lock().expect("lock");
		state.received_messages.push(TaprootAssetReceivedMessage {
			sender_node_id: sender_node_id.to_string(),
			kind: msg.kind,
			payload: msg.payload,
		});
		state.events.push(TaprootAssetRuntimeEvent::MessageReceived {
			sender_node_id: sender_node_id.to_string(),
			kind: msg.kind,
		});
		self.persist_locked(&state)
	}

	fn open_channel(
		&self, local_node_id: PublicKey, request: TaprootAssetChannelOpenRequest,
	) -> Result<TaprootAssetChannelStatus, TaprootAssetError> {
		self.ensure_enabled()?;
		let channel_id = ChannelId::from_bytes(request.channel_id);
		let channel_id_key = hex_utils::to_string(&request.channel_id);
		let descriptor = TaprootAssetChannelDescriptor::new(request.asset_id, 1)
			.map_err(|_| TaprootAssetError::InvalidChannelConfig)?;
		let ldk_request = TaprootAssetFundingRequest {
			pending_channel_id: ChannelId::from_bytes(request.pending_channel_id),
			descriptor,
			funding_outpoint: request.funding_outpoint,
			local_peer_id: local_node_id,
			remote_peer_id: request.counterparty_node_id,
			proof_material: TaprootAssetFundingProofMaterial {
				asset_id: request.asset_id,
				genesis_id: request.genesis_id,
				group_key: request.group_key,
				proof_root_hash: request.proof_root_hash,
				proof_root_sum: request.proof_root_sum,
				complete_fragment_count: request.complete_fragment_count,
				expected_fragment_count: request.expected_fragment_count,
			},
			funding_output: TaprootAssetFundingOutput {
				outpoint: request.funding_outpoint,
				asset_id: request.asset_id,
				taproot_asset_root_hash: request.proof_root_hash,
				taproot_asset_root_sum: request.proof_root_sum,
				output_commitment: request.output_commitment,
			},
			expectations: TaprootAssetFundingExpectations {
				asset_id: request.asset_id,
				genesis_id: request.genesis_id,
				group_key: request.group_key,
				proof_root_hash: request.proof_root_hash,
				output_commitment: request.output_commitment,
				total_amount: request
					.local_amount
					.checked_add(request.remote_amount)
					.ok_or(TaprootAssetError::InvalidChannelConfig)?,
			},
			allocation: TaprootAssetFundingAllocation {
				local_amount: request.local_amount,
				remote_amount: request.remote_amount,
			},
		};
		let ldk_state = TaprootAssetChannelState::from_funding_request(
			&self.local_features(),
			&self.local_features(),
			&single_asset_channel_type(),
			channel_id,
			&ldk_request,
		)
		.map_err(TaprootAssetError::LdkChannelState)?;
		let aux_blob = TaprootAssetMonitorAuxBlob::new(
			channel_id,
			request.asset_id,
			0,
			request.local_amount,
			request.remote_amount,
			request.monitor_aux.state_digest,
			request.proof_root_hash,
			request.proof_root_sum,
			request.monitor_aux.nonce_digest,
			request.monitor_aux.signature_digest,
		)
		.map_err(TaprootAssetError::LdkMonitor)?;
		ldk_state
			.require_current_monitor_aux_blob(Some(&aux_blob), request.monitor_aux.state_digest)
			.map_err(TaprootAssetError::LdkChannelState)?;

		let status = TaprootAssetChannelStatus {
			channel_id: channel_id_key.clone(),
			counterparty_node_id: request.counterparty_node_id.to_string(),
			funding_outpoint: request.funding_outpoint.to_string(),
			asset_id: request.asset_id,
			local_balance: request.local_amount,
			remote_balance: request.remote_amount,
			total_amount: request.local_amount + request.remote_amount,
			proof_root_hash: request.proof_root_hash,
			proof_root_sum: request.proof_root_sum,
			latest_commitment_number: 0,
			funding_accepted: true,
			monitor_aux_persisted: true,
			closed: false,
		};
		let mut state = self.state.lock().expect("lock");
		if state.channels.contains_key(&channel_id_key) {
			return Err(TaprootAssetError::DuplicateChannel);
		}
		state.channels.insert(channel_id_key.clone(), status.clone());
		state.events.push(TaprootAssetRuntimeEvent::FundingAccepted {
			channel_id: channel_id_key,
			asset_id: request.asset_id,
			total_amount: status.total_amount,
		});
		self.persist_locked(&state)?;
		Ok(status)
	}

	fn apply_payment(
		&self, request: TaprootAssetPaymentRequest,
	) -> Result<TaprootAssetPaymentStatus, TaprootAssetError> {
		self.ensure_enabled()?;
		let payment_id = hex_utils::to_string(&request.payment_id);
		let channel_id = hex_utils::to_string(&request.channel_id);
		let metadata = request.metadata.ok_or(TaprootAssetError::MissingAssetMetadata)?;
		let monitor_aux = request.monitor_aux.ok_or(TaprootAssetError::MissingMonitorAuxState)?;
		let metadata = TaprootAssetHtlcMetadata::new(
			metadata.asset_id,
			metadata.asset_amount,
			metadata.proof_root_hash,
			metadata.proof_root_sum,
			metadata.quote_id,
			metadata.payment_hash,
		)
		.map_err(TaprootAssetError::LdkHtlc)?;

		let mut state = self.state.lock().expect("lock");
		if state.payments.contains_key(&payment_id) {
			return Err(TaprootAssetError::DuplicatePayment);
		}
		let current =
			state.channels.get(&channel_id).cloned().ok_or(TaprootAssetError::UnknownChannel)?;
		let mut ldk_state = current.to_ldk_state()?;
		let expected = TaprootAssetHtlcMetadataExpectation {
			asset_id: request.expected.asset_id,
			asset_amount: request.expected.asset_amount,
			proof_root_hash: request.expected.proof_root_hash,
			proof_root_sum: request.expected.proof_root_sum,
			quote_id: request.expected.quote_id,
			payment_hash: request.expected.payment_hash,
			quote_accepted: request.quote_accepted,
			now_unix_seconds: request.now_unix_seconds,
			quote_expiry_unix_seconds: request.quote_expiry_unix_seconds,
		};
		ldk_state
			.validate_htlc_metadata(Some(&metadata), &expected)
			.map_err(TaprootAssetError::LdkChannelState)?;

		let next_commitment = current.latest_commitment_number + 1;
		let (local_to_remote, remote_to_local) = match request.direction {
			TaprootAssetPaymentDirection::LocalToRemote => (request.expected.asset_amount, 0),
			TaprootAssetPaymentDirection::RemoteToLocal => (0, request.expected.asset_amount),
		};
		let local_after_send = current.local_balance.checked_sub(local_to_remote).ok_or(
			TaprootAssetError::LdkChannelState(TaprootAssetChannelStateError::AmountMismatch),
		)?;
		let remote_after_send = current.remote_balance.checked_sub(remote_to_local).ok_or(
			TaprootAssetError::LdkChannelState(TaprootAssetChannelStateError::AmountMismatch),
		)?;
		let local_balance = local_after_send.checked_add(remote_to_local).ok_or(
			TaprootAssetError::LdkChannelState(TaprootAssetChannelStateError::AmountMismatch),
		)?;
		let remote_balance = remote_after_send.checked_add(local_to_remote).ok_or(
			TaprootAssetError::LdkChannelState(TaprootAssetChannelStateError::AmountMismatch),
		)?;
		let aux_blob = TaprootAssetMonitorAuxBlob::new(
			ChannelId::from_bytes(request.channel_id),
			current.asset_id,
			next_commitment,
			local_balance,
			remote_balance,
			monitor_aux.state_digest,
			current.proof_root_hash,
			current.proof_root_sum,
			monitor_aux.nonce_digest,
			monitor_aux.signature_digest,
		)
		.map_err(TaprootAssetError::LdkMonitor)?;
		ldk_state
			.apply_commitment_update(
				next_commitment,
				local_to_remote,
				remote_to_local,
				monitor_aux.state_digest,
				Some(&aux_blob),
			)
			.map_err(TaprootAssetError::LdkChannelState)?;

		let mut updated = current;
		updated.local_balance = local_balance;
		updated.remote_balance = remote_balance;
		updated.latest_commitment_number = next_commitment;
		updated.monitor_aux_persisted = true;
		let status = TaprootAssetPaymentStatus {
			payment_id: payment_id.clone(),
			channel_id: channel_id.clone(),
			direction: match request.direction {
				TaprootAssetPaymentDirection::LocalToRemote => "local_to_remote".to_owned(),
				TaprootAssetPaymentDirection::RemoteToLocal => "remote_to_local".to_owned(),
			},
			asset_id: request.expected.asset_id,
			asset_amount: request.expected.asset_amount,
			quote_id: request.expected.quote_id,
			payment_hash: request.expected.payment_hash,
			status: "settled".to_owned(),
			latest_commitment_number: next_commitment,
			local_balance_after: local_balance,
			remote_balance_after: remote_balance,
		};
		state.channels.insert(channel_id.clone(), updated);
		state.payments.insert(payment_id.clone(), status.clone());
		state.events.push(TaprootAssetRuntimeEvent::HtlcAdded {
			payment_id: payment_id.clone(),
			channel_id: channel_id.clone(),
			asset_amount: request.expected.asset_amount,
		});
		state.events.push(TaprootAssetRuntimeEvent::CommitmentAdvanced {
			channel_id: channel_id.clone(),
			commitment_number: next_commitment,
			local_balance,
			remote_balance,
		});
		state.events.push(TaprootAssetRuntimeEvent::HtlcSettled { payment_id, channel_id });
		self.persist_locked(&state)?;
		Ok(status)
	}

	fn list_received_messages(&self) -> Vec<TaprootAssetReceivedMessage> {
		self.state.lock().expect("lock").received_messages.clone()
	}

	fn list_channels(&self) -> Vec<TaprootAssetChannelStatus> {
		self.state.lock().expect("lock").channels.values().cloned().collect()
	}

	fn list_payments(&self) -> Vec<TaprootAssetPaymentStatus> {
		self.state.lock().expect("lock").payments.values().cloned().collect()
	}

	fn list_events(&self) -> Vec<TaprootAssetRuntimeEvent> {
		self.state.lock().expect("lock").events.clone()
	}

	fn ensure_enabled(&self) -> Result<(), TaprootAssetError> {
		if !self.enabled || !self.config.is_valid() {
			return Err(TaprootAssetError::NotEnabled);
		}
		Ok(())
	}

	pub(crate) fn local_features(&self) -> InitFeatures {
		let mut features = InitFeatures::empty();
		if self.config.negotiate_simple_taproot_channels {
			features.set_static_remote_key_optional();
			features.set_channel_type_optional();
			features.set_simple_taproot_staging_optional();
		}
		if self.config.negotiate_taproot_asset_channels {
			features.set_taproot_asset_channel_optional();
		}
		features
	}

	pub(crate) fn custom_message_features(&self) -> InitFeatures {
		let mut features = InitFeatures::empty();
		if self.config.negotiate_simple_taproot_channels {
			features.set_simple_taproot_staging_optional();
		}
		if self.config.negotiate_taproot_asset_channels {
			features.set_taproot_asset_channel_optional();
		}
		features
	}

	pub(crate) fn custom_init_tlvs(&self) -> Vec<(u64, Vec<u8>)> {
		if self.config.negotiate_taproot_asset_channels {
			vec![(
				TAPROOT_ASSET_AUX_FEATURE_BITS_TLV,
				TAPROOT_ASSET_AUX_FEATURE_BITS_VALUE.to_vec(),
			)]
		} else {
			Vec::new()
		}
	}

	fn persist_locked(&self, state: &TaprootAssetPersistedState) -> Result<(), TaprootAssetError> {
		let raw = serde_json::to_vec(state).map_err(|_| TaprootAssetError::PersistenceFailed)?;
		KVStoreSync::write(
			&*self.kv_store,
			TAPROOT_ASSET_PRIMARY_NAMESPACE,
			TAPROOT_ASSET_SECONDARY_NAMESPACE,
			TAPROOT_ASSET_STATE_KEY,
			raw,
		)
		.map_err(|_| TaprootAssetError::PersistenceFailed)
	}
}

impl TaprootAssetChannelStatus {
	fn to_ldk_state(&self) -> Result<TaprootAssetChannelState, TaprootAssetError> {
		let asset_id = self.asset_id;
		let descriptor = TaprootAssetChannelDescriptor::new(asset_id, 1)
			.map_err(|_| TaprootAssetError::InvalidChannelConfig)?;
		let channel_id = parse_hex_32(&self.channel_id).map(ChannelId::from_bytes)?;
		let funding_outpoint = parse_ldk_outpoint(&self.funding_outpoint)?;
		Ok(TaprootAssetChannelState {
			descriptor,
			channel_id,
			funding_outpoint,
			local_balance: self.local_balance,
			remote_balance: self.remote_balance,
			total_amount: self.total_amount,
			proof_root_hash: self.proof_root_hash,
			proof_root_sum: self.proof_root_sum,
			latest_commitment_number: self.latest_commitment_number,
			closed: self.closed,
		})
	}
}

fn parse_hex_32(value: &str) -> Result<[u8; TAPROOT_ASSET_ID_LEN], TaprootAssetError> {
	if value.len() != TAPROOT_ASSET_ID_LEN * 2 {
		return Err(TaprootAssetError::InvalidChannelConfig);
	}
	let mut out = [0u8; TAPROOT_ASSET_ID_LEN];
	for (idx, byte) in out.iter_mut().enumerate() {
		let start = idx * 2;
		*byte = u8::from_str_radix(&value[start..start + 2], 16)
			.map_err(|_| TaprootAssetError::InvalidChannelConfig)?;
	}
	Ok(out)
}

fn parse_ldk_outpoint(value: &str) -> Result<LdkOutPoint, TaprootAssetError> {
	let (txid, index) = value.rsplit_once(':').ok_or(TaprootAssetError::InvalidChannelConfig)?;
	Ok(LdkOutPoint {
		txid: txid.parse().map_err(|_| TaprootAssetError::InvalidChannelConfig)?,
		index: index.parse().map_err(|_| TaprootAssetError::InvalidChannelConfig)?,
	})
}

fn funding_ack_for_output_proof(
	msg: &TaprootAssetWireMessage,
) -> Result<Option<Vec<u8>>, TaprootAssetError> {
	if msg.kind != TaprootAssetMessageKind::TxAssetOutputProof {
		return Ok(None);
	}

	let fields = parse_asset_output_proof_fields(&msg.payload)?;
	if !fields.last {
		return Ok(None);
	}

	Ok(Some(encode_asset_funding_ack(fields.pending_channel_id, true)))
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct AssetOutputProofFields {
	pending_channel_id: [u8; TAPROOT_ASSET_ID_LEN],
	last: bool,
}

fn parse_asset_output_proof_fields(
	payload: &[u8],
) -> Result<AssetOutputProofFields, TaprootAssetError> {
	let mut offset = 0usize;
	let mut pending_channel_id = None;
	let mut last = None;

	while offset < payload.len() {
		let record_type = read_bigsize(payload, &mut offset)?;
		let record_len = read_bigsize(payload, &mut offset)?;
		if record_len > usize::MAX as u64 {
			return Err(TaprootAssetError::DecodeFailed);
		}
		let record_len = record_len as usize;
		let record_end = offset.checked_add(record_len).ok_or(TaprootAssetError::DecodeFailed)?;
		if record_end > payload.len() {
			return Err(TaprootAssetError::DecodeFailed);
		}
		let record_value = &payload[offset..record_end];
		offset = record_end;

		match record_type {
			0 if record_value.len() == TAPROOT_ASSET_ID_LEN => {
				let mut id = [0u8; TAPROOT_ASSET_ID_LEN];
				id.copy_from_slice(record_value);
				pending_channel_id = Some(id);
			},
			2 if record_value.len() == 1 => match record_value[0] {
				0 => last = Some(false),
				1 => last = Some(true),
				_ => return Err(TaprootAssetError::DecodeFailed),
			},
			_ => {},
		}
	}

	Ok(AssetOutputProofFields {
		pending_channel_id: pending_channel_id.ok_or(TaprootAssetError::DecodeFailed)?,
		last: last.unwrap_or(false),
	})
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AssetFundingCreatedFields {
	pending_channel_id: [u8; TAPROOT_ASSET_ID_LEN],
	outputs: Vec<AssetFundingOutputProof>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AssetFundingOutputProof {
	proof: TaprootAssetProof,
}

fn parse_asset_funding_created_fields(
	payload: &[u8],
) -> Result<AssetFundingCreatedFields, TaprootAssetError> {
	let mut offset = 0usize;
	let mut pending_channel_id = None;
	let mut outputs = None;

	while offset < payload.len() {
		let record_type = read_bigsize(payload, &mut offset)?;
		let record_len = read_bigsize(payload, &mut offset)?;
		if record_len > usize::MAX as u64 {
			return Err(TaprootAssetError::DecodeFailed);
		}
		let record_len = record_len as usize;
		let record_end = offset.checked_add(record_len).ok_or(TaprootAssetError::DecodeFailed)?;
		if record_end > payload.len() {
			return Err(TaprootAssetError::DecodeFailed);
		}
		let record_value = &payload[offset..record_end];
		offset = record_end;

		match record_type {
			0 if record_value.len() == TAPROOT_ASSET_ID_LEN => {
				let mut id = [0u8; TAPROOT_ASSET_ID_LEN];
				id.copy_from_slice(record_value);
				pending_channel_id = Some(id);
			},
			1 => outputs = Some(parse_asset_output_list(record_value)?),
			typ if typ % 2 == 1 => {},
			_ => return Err(TaprootAssetError::DecodeFailed),
		}
	}

	let outputs = outputs.ok_or(TaprootAssetError::DecodeFailed)?;
	if outputs.is_empty() {
		return Err(TaprootAssetError::DecodeFailed);
	}
	Ok(AssetFundingCreatedFields {
		pending_channel_id: pending_channel_id.ok_or(TaprootAssetError::DecodeFailed)?,
		outputs,
	})
}

fn parse_asset_output_list(
	payload: &[u8],
) -> Result<Vec<AssetFundingOutputProof>, TaprootAssetError> {
	let mut offset = 0usize;
	let output_count = read_bigsize(payload, &mut offset)?;
	if output_count == 0 || output_count > 16 {
		return Err(TaprootAssetError::DecodeFailed);
	}
	let mut outputs = Vec::with_capacity(output_count as usize);
	for _ in 0..output_count {
		let output_len = read_bigsize(payload, &mut offset)?;
		if output_len > usize::MAX as u64 {
			return Err(TaprootAssetError::DecodeFailed);
		}
		let output_len = output_len as usize;
		let output_end = offset.checked_add(output_len).ok_or(TaprootAssetError::DecodeFailed)?;
		if output_end > payload.len() {
			return Err(TaprootAssetError::DecodeFailed);
		}
		outputs.push(parse_asset_output(&payload[offset..output_end])?);
		offset = output_end;
	}
	if offset != payload.len() {
		return Err(TaprootAssetError::DecodeFailed);
	}
	Ok(outputs)
}

fn parse_asset_output(payload: &[u8]) -> Result<AssetFundingOutputProof, TaprootAssetError> {
	let mut offset = 0usize;
	let mut proof = None;

	while offset < payload.len() {
		let record_type = read_bigsize(payload, &mut offset)?;
		let record_len = read_bigsize(payload, &mut offset)?;
		if record_len > usize::MAX as u64 {
			return Err(TaprootAssetError::DecodeFailed);
		}
		let record_len = record_len as usize;
		let record_end = offset.checked_add(record_len).ok_or(TaprootAssetError::DecodeFailed)?;
		if record_end > payload.len() {
			return Err(TaprootAssetError::DecodeFailed);
		}
		let record_value = &payload[offset..record_end];
		offset = record_end;

		match record_type {
			0 if record_value.len() == TAPROOT_ASSET_ID_LEN => {},
			1 if record_value.len() == 8 => {},
			2 => {
				proof = Some(
					TaprootAssetProof::from_bytes(record_value)
						.map_err(|err| TaprootAssetError::TaprootAssetProof(err.to_string()))?,
				);
			},
			typ if typ % 2 == 1 => {},
			_ => return Err(TaprootAssetError::DecodeFailed),
		}
	}

	Ok(AssetFundingOutputProof { proof: proof.ok_or(TaprootAssetError::DecodeFailed)? })
}

fn derive_asset_funding_tapscript_root(
	outputs: &[AssetFundingOutputProof],
) -> Result<[u8; 32], TaprootAssetError> {
	let ops = BitcoinTaprootOps::new();
	let mut root = None;
	for output in outputs {
		let commitment = verify_inclusion_proof(&ops, &output.proof)
			.map_err(|err| TaprootAssetError::TaprootAssetProof(err.to_string()))?;
		let candidate = tap_commitment_tapscript_root(&commitment);
		match root {
			Some(existing) if existing != candidate => {
				return Err(TaprootAssetError::TaprootAssetProof(
					"asset funding outputs disagree on tapscript root".to_owned(),
				));
			},
			Some(_) => {},
			None => root = Some(candidate),
		}
	}
	root.ok_or(TaprootAssetError::DecodeFailed)
}

fn tap_commitment_tapscript_root(commitment: &TapCommitment) -> [u8; 32] {
	let mut script = Vec::with_capacity(73);
	match commitment.version {
		TapCommitmentVersion::V0 | TapCommitmentVersion::V1 => {
			script.push(commitment.version as u8);
			script.extend_from_slice(&sha256::Hash::hash(b"taproot-assets").to_byte_array());
			script.extend_from_slice(&commitment.root_hash);
			script.extend_from_slice(&commitment.root_sum.to_be_bytes());
		},
		TapCommitmentVersion::V2 => {
			script.extend_from_slice(&sha256::Hash::hash(b"taproot-assets:194243").to_byte_array());
			script.push(commitment.version as u8);
			script.extend_from_slice(&commitment.root_hash);
			script.extend_from_slice(&commitment.root_sum.to_be_bytes());
		},
	}
	TapNodeHash::from_script(ScriptBuf::from_bytes(script).as_script(), LeafVersion::TapScript)
		.to_byte_array()
}

#[derive(Debug)]
struct BitcoinTaprootOps {
	secp: Secp256k1<bitcoin::secp256k1::VerifyOnly>,
}

impl BitcoinTaprootOps {
	fn new() -> Self {
		Self { secp: Secp256k1::verification_only() }
	}
}

impl TaprootOps for BitcoinTaprootOps {
	type PubKey = PublicKey;

	fn parse_group_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError> {
		PublicKey::from_slice(&key.bytes).map_err(|_| OpsError::InvalidRawGroupKey)
	}

	fn parse_internal_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError> {
		PublicKey::from_slice(&key.bytes).map_err(|_| OpsError::InvalidInternalKey)
	}

	fn add_tweak(&self, pubkey: &Self::PubKey, tweak: [u8; 32]) -> Result<Self::PubKey, OpsError> {
		let tweak = Scalar::from_be_bytes(tweak).map_err(|_| OpsError::AssetIdTweakOutOfRange)?;
		pubkey.add_exp_tweak(&self.secp, &tweak).map_err(|_| OpsError::InvalidGroupKeyTweak)
	}

	fn taproot_output_key(
		&self, internal_key: &Self::PubKey, tapscript_root: Option<[u8; 32]>,
	) -> Result<SerializedKey, OpsError> {
		let merkle_root = tapscript_root.map(TapNodeHash::from_byte_array);
		let (xonly_key, _) = internal_key.x_only_public_key();
		let (tweaked, parity) = xonly_key.tap_tweak(&self.secp, merkle_root);
		let output_key = PublicKey::from_x_only_public_key(tweaked.to_x_only_public_key(), parity);

		Ok(SerializedKey { bytes: output_key.serialize() })
	}
}

fn encode_asset_funding_ack(
	pending_channel_id: [u8; TAPROOT_ASSET_ID_LEN], accept: bool,
) -> Vec<u8> {
	let mut payload = Vec::with_capacity(37);
	payload.push(0);
	payload.push(TAPROOT_ASSET_ID_LEN as u8);
	payload.extend_from_slice(&pending_channel_id);
	payload.push(1);
	payload.push(1);
	payload.push(u8::from(accept));
	payload
}

fn read_bigsize(payload: &[u8], offset: &mut usize) -> Result<u64, TaprootAssetError> {
	let Some(first) = payload.get(*offset).copied() else {
		return Err(TaprootAssetError::DecodeFailed);
	};
	*offset += 1;

	match first {
		0x00..=0xfc => Ok(first as u64),
		0xfd => {
			let bytes = read_fixed::<2>(payload, offset)?;
			Ok(u16::from_be_bytes(bytes) as u64)
		},
		0xfe => {
			let bytes = read_fixed::<4>(payload, offset)?;
			Ok(u32::from_be_bytes(bytes) as u64)
		},
		0xff => {
			let bytes = read_fixed::<8>(payload, offset)?;
			Ok(u64::from_be_bytes(bytes))
		},
	}
}

fn read_fixed<const N: usize>(
	payload: &[u8], offset: &mut usize,
) -> Result<[u8; N], TaprootAssetError> {
	let end = offset.checked_add(N).ok_or(TaprootAssetError::DecodeFailed)?;
	if end > payload.len() {
		return Err(TaprootAssetError::DecodeFailed);
	}
	let mut bytes = [0u8; N];
	bytes.copy_from_slice(&payload[*offset..end]);
	*offset = end;
	Ok(bytes)
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use bitcoin::Txid;

	use crate::io::test_utils::InMemoryStore;
	use crate::types::DynStoreWrapper;

	use super::*;

	fn manager(enabled: bool) -> Arc<TaprootAssetManager> {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let config = ExperimentalChannelConfig {
			negotiate_simple_taproot_channels: enabled,
			negotiate_taproot_asset_channels: enabled,
		};
		Arc::new(TaprootAssetManager::new(config, store))
	}

	fn peer(seed: u8) -> PublicKey {
		let secp = Secp256k1::signing_only();
		let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
		PublicKey::from_secret_key(&secp, &secret)
	}

	fn nonzero(seed: u8) -> [u8; 32] {
		[seed; 32]
	}

	fn open_request() -> TaprootAssetChannelOpenRequest {
		TaprootAssetChannelOpenRequest {
			counterparty_node_id: peer(3),
			channel_id: nonzero(4),
			pending_channel_id: nonzero(5),
			funding_outpoint: LdkOutPoint {
				txid: Txid::from_str(
					"1111111111111111111111111111111111111111111111111111111111111111",
				)
				.unwrap(),
				index: 0,
			},
			asset_id: nonzero(7),
			genesis_id: nonzero(8),
			group_key: None,
			proof_root_hash: nonzero(9),
			proof_root_sum: 1_000,
			output_commitment: nonzero(10),
			local_amount: 700,
			remote_amount: 300,
			complete_fragment_count: 2,
			expected_fragment_count: 2,
			monitor_aux: TaprootAssetMonitorAuxRequest {
				state_digest: nonzero(11),
				nonce_digest: nonzero(12),
				signature_digest: nonzero(13),
			},
		}
	}

	fn asset_output_proof_payload(pending_channel_id: [u8; 32], last: bool) -> Vec<u8> {
		let mut payload = Vec::new();
		payload.push(0);
		payload.push(32);
		payload.extend_from_slice(&pending_channel_id);
		payload.push(2);
		payload.push(1);
		payload.push(u8::from(last));
		payload
	}

	fn payment_request(direction: TaprootAssetPaymentDirection) -> TaprootAssetPaymentRequest {
		let metadata = TaprootAssetPaymentMetadata {
			asset_id: nonzero(7),
			asset_amount: 125,
			proof_root_hash: nonzero(9),
			proof_root_sum: 1_000,
			quote_id: nonzero(14),
			payment_hash: nonzero(15),
		};
		TaprootAssetPaymentRequest {
			channel_id: nonzero(4),
			payment_id: nonzero(16),
			direction,
			expected: metadata,
			metadata: Some(metadata),
			quote_accepted: true,
			now_unix_seconds: 10,
			quote_expiry_unix_seconds: 20,
			monitor_aux: Some(TaprootAssetMonitorAuxRequest {
				state_digest: nonzero(17),
				nonce_digest: nonzero(18),
				signature_digest: nonzero(19),
			}),
		}
	}

	#[test]
	fn disabled_manager_rejects_asset_runtime_calls() {
		let manager = manager(false);

		assert!(matches!(
			manager.queue_message(peer(3), TaprootAssetMessageKind::RfqRequest, vec![1]),
			Err(TaprootAssetError::NotEnabled)
		));
		assert!(matches!(
			manager.open_channel(peer(2), open_request()),
			Err(TaprootAssetError::NotEnabled)
		));
	}

	#[test]
	fn custom_messages_queue_and_record_incoming() {
		let manager = manager(true);

		let queued = manager
			.queue_message(peer(3), TaprootAssetMessageKind::TxAssetInputProof, vec![1, 2, 3])
			.unwrap();
		assert_eq!(queued.payload_len, 3);
		let pending = manager.get_and_clear_pending_messages();
		assert_eq!(pending.len(), 1);
		assert_eq!(pending[0].1.type_id(), TX_ASSET_INPUT_PROOF_TYPE);

		manager
			.record_received_message(
				peer(3),
				TaprootAssetWireMessage {
					kind: TaprootAssetMessageKind::RfqAccept,
					payload: vec![42],
				},
			)
			.unwrap();
		assert_eq!(manager.list_received_messages().len(), 1);
	}

	#[test]
	fn asset_output_proof_ack_matches_lightning_labs_tlv_shape() {
		let pending_channel_id = nonzero(5);

		let ack = encode_asset_funding_ack(pending_channel_id, true);

		assert_eq!(ack.len(), 37);
		assert_eq!(&ack[..2], &[0, 32]);
		assert_eq!(&ack[2..34], pending_channel_id.as_slice());
		assert_eq!(&ack[34..], &[1, 1, 1]);
	}

	#[test]
	fn tap_commitment_tapscript_root_uses_lightning_labs_leaf_shape() {
		let commitment = TapCommitment {
			version: TapCommitmentVersion::V2,
			root_hash: nonzero(7),
			root_sum: 42,
		};
		let root = tap_commitment_tapscript_root(&commitment);

		let mut expected_script = Vec::new();
		expected_script
			.extend_from_slice(&sha256::Hash::hash(b"taproot-assets:194243").to_byte_array());
		expected_script.push(2);
		expected_script.extend_from_slice(&nonzero(7));
		expected_script.extend_from_slice(&42u64.to_be_bytes());
		assert_eq!(
			root,
			TapNodeHash::from_script(
				ScriptBuf::from_bytes(expected_script).as_script(),
				LeafVersion::TapScript
			)
			.to_byte_array()
		);
	}

	#[test]
	fn last_asset_output_proof_queues_funding_ack() {
		let manager = manager(true);
		let pending_channel_id = nonzero(5);

		manager
			.handle_message(
				TaprootAssetWireMessage {
					kind: TaprootAssetMessageKind::TxAssetOutputProof,
					payload: asset_output_proof_payload(pending_channel_id, true),
				},
				peer(3),
			)
			.unwrap();

		assert_eq!(manager.list_received_messages().len(), 1);
		let pending = manager.get_and_clear_pending_messages();
		assert_eq!(pending.len(), 1);
		assert_eq!(pending[0].0, peer(3));
		assert_eq!(pending[0].1.kind, TaprootAssetMessageKind::AssetFundingAccepted);
		assert_eq!(pending[0].1.type_id(), ASSET_FUNDING_ACCEPTED_TYPE);
		assert_eq!(pending[0].1.payload, encode_asset_funding_ack(pending_channel_id, true));
	}

	#[test]
	fn non_last_asset_output_proof_does_not_ack() {
		let manager = manager(true);

		manager
			.handle_message(
				TaprootAssetWireMessage {
					kind: TaprootAssetMessageKind::TxAssetOutputProof,
					payload: asset_output_proof_payload(nonzero(5), false),
				},
				peer(3),
			)
			.unwrap();

		assert_eq!(manager.list_received_messages().len(), 1);
		assert!(manager.get_and_clear_pending_messages().is_empty());
	}

	#[test]
	fn advertised_custom_features_do_not_duplicate_base_channel_features() {
		let manager = manager(true);
		let features = manager.custom_message_features();

		assert!(features.supports_simple_taproot_staging());
		assert!(features.supports_taproot_asset_channel());
		assert!(!features.supports_static_remote_key());
		assert!(!features.supports_channel_type());
	}

	#[test]
	fn advertised_init_tlvs_include_lightning_labs_aux_features() {
		let enabled = manager(true);
		assert_eq!(enabled.custom_init_tlvs(), vec![(65_545, vec![0, 1, 0x0a])]);

		let disabled = manager(false);
		assert!(disabled.custom_init_tlvs().is_empty());
	}

	#[test]
	fn open_channel_reaches_ldk_funding_and_monitor_hooks() {
		let manager = manager(true);
		let status = manager.open_channel(peer(2), open_request()).unwrap();

		assert!(status.funding_accepted);
		assert!(status.monitor_aux_persisted);
		assert_eq!(status.local_balance, 700);
		assert_eq!(status.remote_balance, 300);
	}

	#[test]
	fn payment_reaches_ldk_htlc_and_commitment_hooks() {
		let manager = manager(true);
		manager.open_channel(peer(2), open_request()).unwrap();
		let status = manager
			.apply_payment(payment_request(TaprootAssetPaymentDirection::LocalToRemote))
			.unwrap();

		assert_eq!(status.status, "settled");
		assert_eq!(status.local_balance_after, 575);
		assert_eq!(status.remote_balance_after, 425);
		assert_eq!(manager.list_events().len(), 4);
	}

	#[test]
	fn negative_payment_cases_fail_before_state_advances() {
		let manager = manager(true);
		manager.open_channel(peer(2), open_request()).unwrap();

		let mut wrong_quote = payment_request(TaprootAssetPaymentDirection::LocalToRemote);
		wrong_quote.metadata.as_mut().unwrap().quote_id = nonzero(20);
		assert!(matches!(
			manager.apply_payment(wrong_quote),
			Err(TaprootAssetError::LdkChannelState(TaprootAssetChannelStateError::Htlc(
				TaprootAssetHtlcMetadataError::QuoteMismatch
			)))
		));

		let mut missing_metadata = payment_request(TaprootAssetPaymentDirection::LocalToRemote);
		missing_metadata.metadata = None;
		assert!(matches!(
			manager.apply_payment(missing_metadata),
			Err(TaprootAssetError::MissingAssetMetadata)
		));

		let mut missing_aux = payment_request(TaprootAssetPaymentDirection::LocalToRemote);
		missing_aux.monitor_aux = None;
		assert!(matches!(
			manager.apply_payment(missing_aux),
			Err(TaprootAssetError::MissingMonitorAuxState)
		));
	}
}
