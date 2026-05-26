// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::ops::Deref;
use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::LightningError;
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::CustomMessageReader;
use lightning::ln::wire::Type;
use lightning::util::logger::Logger;
use lightning::util::ser::{LengthLimitedRead, Writeable, Writer};
use lightning_liquidity::lsps0::ser::RawLSPSMessage;
use lightning_types::features::{InitFeatures, NodeFeatures};

use crate::liquidity::LiquiditySource;
use crate::taproot_asset::{TaprootAssetManager, TaprootAssetWireMessage};

#[derive(Debug)]
pub(crate) enum NodeCustomMessage {
	Liquidity(RawLSPSMessage),
	TaprootAsset(TaprootAssetWireMessage),
}

impl Writeable for NodeCustomMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), bitcoin::io::Error> {
		match self {
			Self::Liquidity(msg) => msg.write(w),
			Self::TaprootAsset(msg) => msg.write(w),
		}
	}
}

impl Type for NodeCustomMessage {
	fn type_id(&self) -> u16 {
		match self {
			Self::Liquidity(msg) => msg.type_id(),
			Self::TaprootAsset(msg) => msg.type_id(),
		}
	}
}

pub(crate) struct NodeCustomMessageHandler<L: Deref>
where
	L::Target: Logger,
{
	liquidity_source: Option<Arc<LiquiditySource<L>>>,
	taproot_asset_manager: Arc<TaprootAssetManager>,
}

impl<L: Deref> NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	pub(crate) fn new(
		liquidity_source: Option<Arc<LiquiditySource<L>>>,
		taproot_asset_manager: Arc<TaprootAssetManager>,
	) -> Self {
		Self { liquidity_source, taproot_asset_manager }
	}
}

impl<L: Deref> CustomMessageReader for NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	type CustomMessage = NodeCustomMessage;

	fn read<RD: LengthLimitedRead>(
		&self, message_type: u16, buffer: &mut RD,
	) -> Result<Option<Self::CustomMessage>, lightning::ln::msgs::DecodeError> {
		if let Some(liquidity_source) = self.liquidity_source.as_ref() {
			if let Some(msg) = liquidity_source.liquidity_manager().read(message_type, buffer)? {
				return Ok(Some(NodeCustomMessage::Liquidity(msg)));
			}
		}
		self.taproot_asset_manager
			.read_message(message_type, buffer)
			.map(|msg| msg.map(NodeCustomMessage::TaprootAsset))
	}
}

impl<L: Deref> CustomMessageHandler for NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	fn handle_custom_message(
		&self, msg: Self::CustomMessage, sender_node_id: PublicKey,
	) -> Result<(), LightningError> {
		match msg {
			NodeCustomMessage::Liquidity(msg) => {
				let Some(liquidity_source) = self.liquidity_source.as_ref() else {
					return Ok(());
				};
				liquidity_source.liquidity_manager().handle_custom_message(msg, sender_node_id)
			},
			NodeCustomMessage::TaprootAsset(msg) => {
				self.taproot_asset_manager.handle_message(msg, sender_node_id)
			},
		}
	}

	fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
		let mut pending = Vec::new();
		if let Some(liquidity_source) = self.liquidity_source.as_ref() {
			pending.extend(
				liquidity_source
					.liquidity_manager()
					.get_and_clear_pending_msg()
					.into_iter()
					.map(|(node_id, msg)| (node_id, NodeCustomMessage::Liquidity(msg))),
			);
		}
		pending.extend(
			self.taproot_asset_manager
				.get_and_clear_pending_messages()
				.into_iter()
				.map(|(node_id, msg)| (node_id, NodeCustomMessage::TaprootAsset(msg))),
		);
		pending
	}

	fn provided_node_features(&self) -> NodeFeatures {
		if let Some(liquidity_source) = self.liquidity_source.as_ref() {
			liquidity_source.liquidity_manager().provided_node_features()
		} else {
			NodeFeatures::empty()
		}
	}

	fn provided_init_features(&self, their_node_id: PublicKey) -> InitFeatures {
		let mut features = if let Some(liquidity_source) = self.liquidity_source.as_ref() {
			liquidity_source.liquidity_manager().provided_init_features(their_node_id)
		} else {
			InitFeatures::empty()
		};
		features |= self.taproot_asset_manager.local_features();
		features
	}

	fn peer_connected(
		&self, their_node_id: PublicKey, msg: &lightning::ln::msgs::Init, inbound: bool,
	) -> Result<(), ()> {
		if let Some(liquidity_source) = self.liquidity_source.as_ref() {
			liquidity_source.liquidity_manager().peer_connected(their_node_id, msg, inbound)
		} else {
			Ok(())
		}
	}

	fn peer_disconnected(&self, their_node_id: PublicKey) {
		if let Some(liquidity_source) = self.liquidity_source.as_ref() {
			liquidity_source.liquidity_manager().peer_disconnected(their_node_id)
		}
	}
}
