//! Utilities for cryptographic purposes
//!
//! For now, this just has a workaround for some other libraries'
//! lack of full x509 support

use simple_asn1::{oid, ASN1Block, BigUint, OID};

/// Given an X.509 certificate, return its SubjectPublicKey if that key
/// is an RSA key.
///
/// WARNING: Does not validate the X.509 certificate at all!
///
/// XXXXX This is a massive kludge.
pub fn x509_extract_rsa_subject_kludge(der: &[u8]) -> Option<crate::pk::rsa::PublicKey> {
    //use ASN1Block::*;
    let blocks = simple_asn1::from_der(der).ok()?;
    let block = Asn1(blocks.get(0)?);
    // TBSCertificate
    let tbs_cert: Asn1<'_> = block.into_seq()?.get(0)?.into();
    // SubjectPublicKeyInfo
    let spki: Asn1<'_> = tbs_cert.into_seq()?.get(6)?.into();
    let spki_members = spki.into_seq()?;
    // Is it an RSA key?
    let algid: Asn1<'_> = spki_members.get(0)?.into();
    let oid: Asn1<'_> = algid.into_seq()?.get(0)?.into();
    oid.must_be_rsa_oid()?;

    // try to get the RSA key.
    let key: Asn1<'_> = spki_members.get(1)?.into();
    crate::pk::rsa::PublicKey::from_der(key.to_bitstr()?)
}

/// Helper to wrap a simple_asn1::Asn1Blcok and add more methods to it.
struct Asn1<'a>(&'a ASN1Block);
impl<'a> From<&'a ASN1Block> for Asn1<'a> {
    fn from(b: &'a ASN1Block) -> Asn1<'a> {
        Asn1(b)
    }
}
impl<'a> Asn1<'a> {
    /// If this block is a sequence, return a reference to its members.
    fn into_seq(self) -> Option<&'a [ASN1Block]> {
        match self.0 {
            ASN1Block::Sequence(_, ref s) => Some(s),
            _ => None,
        }
    }
    /// If this block is the OID for the RSA cipher, return Some(()); else
    /// return None.
    ///
    /// (It's not a great API, but it lets us use the ? operator
    /// easily above.)
    fn must_be_rsa_oid(self) -> Option<()> {
        let oid = match self.0 {
            ASN1Block::ObjectIdentifier(_, ref oid) => Some(oid),
            _ => None,
        }?;
        if oid == oid!(1, 2, 840, 113549, 1, 1, 1) {
            Some(())
        } else {
            None
        }
    }
    /// If this block is a BitString, return its bitstring value as a
    /// slice of bytes.
    fn to_bitstr(&self) -> Option<&[u8]> {
        match self.0 {
            ASN1Block::BitString(_, _, ref v) => Some(&v[..]),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    // A cert generated by chutney
    const CHUTNEY_CERT: &[u8] = include_bytes!("../testdata/tor.der");
    // current (Sep 2020) certificate for www.torproject.org
    const TPO_CERT: &[u8] = include_bytes!("../testdata/tpo.der");

    #[test]
    fn extract_rsa() {
        use super::*;
        use hex_literal::hex;
        let pk = x509_extract_rsa_subject_kludge(CHUTNEY_CERT).unwrap();
        assert_eq!(pk.bits(), 2048);
        assert!(pk.exponent_is(65537));
        assert_eq!(pk.to_der(), &hex!(
            "3082010a028201010097a08af777515b03d99702a7e25382438ac93c1ba89601ece7b9ce1a1c5667ba6b97ef6c489c9e269da5f42b70ce09d6cf8c91b77bed2c66885be394f5de1c2e0a7e6464f5c9bc988dd5f3fd495af77041b64c7546930d99f3a5183186a5f188baa8f7ad579083d3bff0ce6508d1961d4f5da26fd84d1a693f903c47b1cfb3f6910843eafbcebafff58e74e6e737e4517514746880cb1b5b4fbf75243ca713c0fbd50176595e8d6e4b9bffb5434479ccbe6ed5cf1e22982826b60123eec3064e84f657da88312dcc5258320d52cfa3dda9fe372db38ebb2448e0411a26d3a95a35de9d617f8bf9ff2d9a099bf8123763229a3cd0ccd5c3c812c36c710bc0d3510203010001")[..]);

        let pk = x509_extract_rsa_subject_kludge(TPO_CERT).unwrap();
        assert_eq!(pk.bits(), 4096);
        assert!(pk.exponent_is(65537));
        assert_eq!(pk.to_der(), &hex!("3082020a0282020100c61b75da1b7641e506c98ac8d46f2056f9d828672d84ddd274a8c696c8edff741f32cf880a28c142af51a3c6371f59889ac8dd6670bf3f4163a20fcc75b36e451de581a03a721d7ef44e544ae992f5bb68a6b20a0888d68e87b7facdf63b1101eee544eec1217dc4155fe851ae2756fe6467d7139741837249efc13cba74fec73e93533101507445ee68119c64a0cb6bea4d3d84a681aad998a857cbfc26b8e42c5531e345e29943e9841b34bdd63e833542a76c0a1d1831825003baddd4ccb2ecedd5bf255f4e4928f92f8e82430b9a0b9c6318405c6ab4b6d36a3205d0bb0d9a6894754a9b025de883a30dc69c84bdd514318f5d07b7fd355c6a57bccba99f8586c6627f2ff52a5e1ce76c5afe6408d0a91da1d899d4828821469661719ee8acbbbe1682188bac7787077a3276300240ec89e1ddeed4ff6814aab13d7e2e8b700255672f92c3554129912e52c4d92acaf702309f6a0db398c9b91ebcc8c579ee2db44c6bea052b026779bdf609695f01b9d2dce0a9f0701450d7404949588f0642f290221e374d806fa595d8206f6caef19d97d79408d5d31611a8b1cd3eb1f2a83e951fedfd11e7ca637e37720f25dbf8ce99eb499f94e79433e511f50e5579327af487e92f2a42d89687cb61c2b8d7a4be46c1ed3b8fbaf0bdbc0363a2f828e73237300729daff58e840e079270a31b64140cea7ba58efc3d9e96aa9075d0203010001")[..]);

        assert!(x509_extract_rsa_subject_kludge("hello world".as_bytes()).is_none());
    }
}
