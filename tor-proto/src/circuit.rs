//! Multi-hop paths over the Tor network.

use crate::chancell::{
    msg::{self, ChanMsg},
    ChanCell, CircID,
};
use crate::channel::Channel;
use crate::crypto::cell::{ClientLayer, CryptInit};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::{Error, Result};

use futures::channel::mpsc;
use futures::io::{AsyncRead, AsyncWrite};
use futures::stream::StreamExt;

use rand::{CryptoRng, Rng};

use crate::crypto::cell::ClientCrypt;

/// A Circuit that we have constructed over the Tor network.
// TODO: I wish this weren't parameterized.
// TODO: need to send a destroy cell on drop
pub struct ClientCirc<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    id: CircID,
    channel: Channel<T>,
    // TODO: could use a SPSC channel here instead.
    input: mpsc::Receiver<ChanMsg>,
    crypto: ClientCrypt,
}

impl<T> ClientCirc<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Instantiate a new circuit object.
    pub(crate) fn new(id: CircID, channel: Channel<T>, input: mpsc::Receiver<ChanMsg>) -> Self {
        let crypto = ClientCrypt::new();
        ClientCirc {
            id,
            channel,
            input,
            crypto,
        }
    }

    /// Put a cell onto this circuit.
    ///
    /// This takes a raw cell; you may need to encrypt it.
    // TODO: This shouldn't be public.
    async fn send_msg(&mut self, msg: ChanMsg) -> Result<()> {
        let cell = ChanCell::new(self.id, msg);
        self.channel.send_cell(cell).await?;
        Ok(())
    }

    /// Read a cell from this circuit.
    ///
    /// This is a raw cell as sent on the channel: if it's a relay cell,
    /// it'll need to be decrypted.
    async fn read_msg(&mut self) -> Result<ChanMsg> {
        // XXXX handle close better?
        self.input.next().await.ok_or(Error::CircuitClosed)
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, a handshake object to perform
    /// the cryptographic cryptographic handshake, and a layer type to
    /// handle relay crypto after this hop is built.
    async fn create_impl<R, L, H, W>(
        &mut self,
        rng: &mut R,
        wrap: &W,
        key: &H::KeyType,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer + 'static,
        H: ClientHandshake,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
    {
        if self.crypto.n_layers() != 0 {
            return Err(Error::CircExtend("Circuit already extended."));
        }

        let (state, msg) = H::client1(rng, &key)?;
        let create_cell = wrap.to_chanmsg(msg);
        self.send_msg(create_cell).await?;
        let reply = self.read_msg().await?;

        let server_handshake = wrap.from_chanmsg(reply)?;
        let keygen = H::client2(state, server_handshake)?;

        let layer = L::construct(keygen)?;

        self.crypto.add_layer(Box::new(layer));
        Ok(())
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CRATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    pub async fn create_firsthop_fast<R>(&mut self, rng: &mut R) -> Result<()>
    where
        R: Rng + CryptoRng,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::fast::CreateFastClient;
        let wrap = CreateFastWrap;
        self.create_impl::<R, Tor1RelayCrypto, CreateFastClient, _>(rng, &wrap, &())
            .await
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target.
    pub async fn create_firsthop_ntor<R, Tg>(&mut self, rng: &mut R, target: &Tg) -> Result<()>
    where
        R: Rng + CryptoRng,
        Tg: tor_linkspec::ExtendTarget,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
        let wrap = Create2Wrap {
            handshake_type: 0x0002, // ntor
        };
        let key = NtorPublicKey {
            id: target.get_rsa_identity().clone(),
            pk: *target.get_ntor_onion_key(),
        };
        self.create_impl::<R, Tor1RelayCrypto, NtorClient, _>(rng, &wrap, &key)
            .await
    }
}

trait CreateHandshakeWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg;
    fn from_chanmsg(&self, msg: ChanMsg) -> Result<Vec<u8>>;
}

struct CreateFastWrap;
impl CreateHandshakeWrap for CreateFastWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        msg::CreateFast::new(bytes).into()
    }
    fn from_chanmsg(&self, msg: ChanMsg) -> Result<Vec<u8>> {
        match msg {
            ChanMsg::CreatedFast(m) => Ok(m.into_body()),
            ChanMsg::Destroy(_) => Err(Error::CircExtend(
                "Relay replied to CREATE_FAST with DESTROY.",
            )),
            _ => Err(Error::CircExtend(
                "Relay replied to CREATE_FAST with unexpected cell.",
            )),
        }
    }
}

struct Create2Wrap {
    handshake_type: u16,
}
impl CreateHandshakeWrap for Create2Wrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        msg::Create2::new(self.handshake_type, bytes).into()
    }
    fn from_chanmsg(&self, msg: ChanMsg) -> Result<Vec<u8>> {
        match msg {
            ChanMsg::Created2(m) => Ok(m.into_body()),
            ChanMsg::Destroy(_) => Err(Error::CircExtend("Relay replied to CREATE2 with DESTROY.")),
            _ => Err(Error::CircExtend(
                "Relay replied to CREATE2 with unexpected cell.",
            )),
        }
    }
}