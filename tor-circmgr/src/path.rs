//! Code to construct paths through the Tor network
//!
//! TODO: I'm not sure this belongs in circmgr, but this is the best place
//! I can think of for now.  I'm also not sure this should be public.

pub mod dirpath;
pub mod exitpath;

use tor_chanmgr::ChanMgr;
use tor_linkspec::{ChanTarget, OwnedChanTarget, OwnedCircTarget};
use tor_netdir::{fallback::FallbackDir, Relay};
use tor_proto::channel::Channel;
use tor_proto::circuit::{CircParameters, ClientCirc};
use tor_rtcompat::Runtime;

use futures::task::SpawnExt;
use rand::{CryptoRng, Rng};
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

use crate::usage::ExitPolicy;
use crate::{Error, Result};

/// A list of Tor relays through the network.
pub struct TorPath<'a> {
    /// The inner TorPath state.
    inner: TorPathInner<'a>,
}

/// Non-public helper type to repersent the different kinds of Tor path.
///
/// (This is a separate type to avoid exposing its details to the user.)
enum TorPathInner<'a> {
    /// A single-hop path for use with a directory cache, when a relay is
    /// known.
    OneHop(Relay<'a>), // This could just be a routerstatus.
    /// A single-hop path for use with a directory cache, when we don't have
    /// a consensus.
    FallbackOneHop(&'a FallbackDir),
    /// A multi-hop path, containing one or more paths.
    Path(Vec<Relay<'a>>),
}

impl<'a> TorPath<'a> {
    /// Create a new one-hop path for use with a directory cache with a known
    /// relay.
    pub fn new_one_hop(relay: Relay<'a>) -> Self {
        Self {
            inner: TorPathInner::OneHop(relay),
        }
    }

    /// Create a new one-hop path for use with a directory cache when we don't
    /// have a consensus.
    pub fn new_fallback_one_hop(fallback_dir: &'a FallbackDir) -> Self {
        Self {
            inner: TorPathInner::FallbackOneHop(fallback_dir),
        }
    }

    /// Create a new multi-hop path with a given number of ordered relays.
    pub fn new_multihop(relays: impl IntoIterator<Item = Relay<'a>>) -> Self {
        Self {
            inner: TorPathInner::Path(relays.into_iter().collect()),
        }
    }

    /// Return the final relay in this path, if this is a path for use
    /// with exit circuits.
    fn exit_relay(&self) -> Option<&Relay<'a>> {
        match &self.inner {
            TorPathInner::Path(relays) if !relays.is_empty() => Some(&relays[relays.len() - 1]),
            _ => None,
        }
    }

    /// Return the exit policy of the final relay in this path, if this
    /// is a path for use with exit circuits.
    pub(crate) fn exit_policy(&self) -> Option<ExitPolicy> {
        self.exit_relay().map(ExitPolicy::from_relay)
    }

    /// Try to build a circuit corresponding to this path.
    pub async fn build_circuit<RNG, RT>(
        &self,
        rng: &mut RNG,
        runtime: &RT,
        chanmgr: &ChanMgr<RT>,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        RNG: Rng + CryptoRng,
        RT: Runtime,
    {
        let owned: OwnedPath = self.try_into()?;

        owned.build_circuit(rng, runtime, chanmgr, params).await
    }
}

/// A path composed entirely of owned components.
pub(crate) enum OwnedPath {
    /// A path where we only know how to make circuits via CREATE_FAST.
    ChannelOnly(OwnedChanTarget),
    /// A path of one or more hops created via normal Tor handshakes.
    Normal(Vec<OwnedCircTarget>),
}

impl<'a> TryFrom<&TorPath<'a>> for OwnedPath {
    type Error = crate::Error;
    fn try_from(p: &TorPath<'a>) -> Result<OwnedPath> {
        use TorPathInner::*;

        Ok(match &p.inner {
            FallbackOneHop(h) => OwnedPath::ChannelOnly(OwnedChanTarget::from_chan_target(*h)),
            OneHop(h) => OwnedPath::Normal(vec![OwnedCircTarget::from_circ_target(h)]),
            Path(p) if !p.is_empty() => {
                OwnedPath::Normal(p.iter().map(OwnedCircTarget::from_circ_target).collect())
            }
            Path(_) => {
                return Err(Error::NoRelays("Path with no entries!".into()));
            }
        })
    }
}

impl OwnedPath {
    /// Construct a circuit for this path.
    pub(crate) async fn build_circuit<RNG, RT>(
        self,
        rng: &mut RNG,
        runtime: &RT,
        chanmgr: &ChanMgr<RT>,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        RNG: Rng + CryptoRng,
        RT: Runtime,
    {
        let chan = self.get_channel(chanmgr).await?;
        let (pending_circ, reactor) = chan.new_circ(rng).await?;

        runtime.spawn(async {
            let _ = reactor.run().await;
        })?;

        match self {
            OwnedPath::ChannelOnly(_) => {
                let circ = pending_circ.create_firsthop_fast(rng, &params).await?;
                Ok(circ)
            }
            OwnedPath::Normal(p) => {
                assert!(!p.is_empty());
                let circ = pending_circ
                    .create_firsthop_ntor(rng, &p[0], &params)
                    .await?;
                for relay in p[1..].iter() {
                    circ.extend_ntor(rng, relay, params).await?;
                }
                Ok(circ)
            }
        }
    }

    /// Internal: Get the first hop of the path as a ChanTarget.
    fn first_hop(&self) -> Result<&(dyn ChanTarget + Sync)> {
        match self {
            OwnedPath::ChannelOnly(c) => Ok(c),
            OwnedPath::Normal(p) if p.is_empty() => {
                Err(Error::NoRelays("Path with no entries!".into()))
            }
            OwnedPath::Normal(p) => Ok(&p[0]),
        }
    }

    /// Internal: get or create a channel for the first hop of a path.
    async fn get_channel<R: Runtime>(&self, chanmgr: &ChanMgr<R>) -> Result<Arc<Channel>> {
        let first_hop = self.first_hop()?;
        let channel = chanmgr.get_or_launch(first_hop).await?;
        Ok(channel)
    }
}
