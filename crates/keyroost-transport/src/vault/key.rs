//! The seam between the vault flows and a key: [`VaultKey`], and
//! [`CtapVaultKey`], the real key over CTAP.

use keyroost_ctap::client_pin::{
    get_pin_uv_auth_token_with_permissions, get_token, PinUvAuthToken, TokenSource,
};
use keyroost_ctap::cred_mgmt::CredentialManager;
use keyroost_ctap::get_assertion::{get_assertions, Assertion, GetAssertionRequest};
use keyroost_ctap::hmac_secret::{self, prf_salt};
use keyroost_ctap::large_blobs::{self, LargeBlobArray};
use keyroost_ctap::make_credential::{make_credential, MadeCredential, MakeCredentialRequest};
use keyroost_ctap::transport::CtapTransport;
use keyroost_ctap::{get_info, AuthenticatorInfo, CtapError};
use keyroost_vault::{PRF_INPUT, RP_ID, RP_NAME};
use zeroize::Zeroizing;

use super::{check_support, vault_name, StoredData, VaultCredential, VaultKeyError, VaultRef};

/// The key calls a vault flow makes. Every call is one CTAP exchange (or one
/// largeBlob read/write); the flows decide order, tokens and retries.
pub trait VaultKey {
    /// The key's getInfo, read when it was opened.
    fn info(&self) -> &AuthenticatorInfo;

    /// A pinUvAuthToken with `permissions`, bound to `rp_id` when given.
    fn pin_token(
        &mut self,
        pin: &str,
        permissions: u32,
        rp_id: Option<&str>,
    ) -> Result<PinUvAuthToken, CtapError>;

    /// A pinUvAuthToken from a fingerprint (CTAP 2.1 built-in user
    /// verification) with `permissions`, bound to `rp_id` when given.
    /// Refused with [`CtapError::Fingerprint`] and no finger asked when the
    /// key cannot give one (no fingerprint, a permission a finger cannot
    /// grant, no tries left); otherwise `on_finger` runs once, right before
    /// the key waits for the finger.
    fn uv_token(
        &mut self,
        permissions: u32,
        rp_id: Option<&str>,
        on_finger: &mut dyn FnMut(),
    ) -> Result<PinUvAuthToken, CtapError>;

    /// Make a discoverable vault credential (waits for a touch).
    fn make_credential(
        &mut self,
        token: &PinUvAuthToken,
        user_id: &[u8],
        name: &str,
    ) -> Result<MadeCredential, CtapError>;

    /// Assert every vault credential (`allow == None`) or the one given,
    /// asking for the hmac-secret output and the largeBlobKey (waits for a
    /// touch). No vault credential is an empty list.
    fn assertions(
        &mut self,
        token: &PinUvAuthToken,
        allow: Option<&[u8]>,
    ) -> Result<Vec<Assertion>, CtapError>;

    /// The vault credentials through credential management (no touch). No
    /// vault credential is an empty list; `stored` is left [`StoredData::Unknown`].
    fn credentials(&mut self, token: &PinUvAuthToken) -> Result<Vec<VaultCredential>, CtapError>;

    /// Delete one credential through credential management (no touch).
    fn delete_credential(
        &mut self,
        token: &PinUvAuthToken,
        credential_id: &[u8],
    ) -> Result<(), CtapError>;

    /// Read the key's whole largeBlob array (no PIN).
    fn read_blobs(&mut self) -> Result<LargeBlobArray, CtapError>;

    /// Write a serialized largeBlob array (with its checksum).
    fn write_blobs(&mut self, token: &PinUvAuthToken, serialized: &[u8]) -> Result<(), CtapError>;
}

/// "No credentials" from the key is an empty list, not a failure.
pub(crate) fn no_credentials_as_empty<T>(
    r: Result<Vec<T>, CtapError>,
) -> Result<Vec<T>, CtapError> {
    match r {
        Err(CtapError::NoCredentials) => Ok(Vec::new()),
        r => r,
    }
}

/// A real key over CTAP (USB HID or a smart-card reader).
pub struct CtapVaultKey<T: CtapTransport> {
    dev: T,
    info: AuthenticatorInfo,
}

impl<T: CtapTransport> CtapVaultKey<T> {
    /// Read the key's getInfo and refuse a key that cannot hold a vault
    /// ([`check_support`]) before anything else is sent.
    pub fn open(mut dev: T) -> Result<Self, VaultKeyError> {
        let info = get_info(&mut dev)?;
        check_support(&info)?;
        Ok(CtapVaultKey { dev, info })
    }

    /// The device underneath, for calls outside the vault flows.
    pub fn device(&mut self) -> &mut T {
        &mut self.dev
    }
}

fn random32() -> Result<[u8; 32], CtapError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| CtapError::Random)?;
    Ok(b)
}

impl<T: CtapTransport> VaultKey for CtapVaultKey<T> {
    fn info(&self) -> &AuthenticatorInfo {
        &self.info
    }

    fn pin_token(
        &mut self,
        pin: &str,
        permissions: u32,
        rp_id: Option<&str>,
    ) -> Result<PinUvAuthToken, CtapError> {
        get_pin_uv_auth_token_with_permissions(&mut self.dev, pin, permissions, rp_id)
    }

    fn uv_token(
        &mut self,
        permissions: u32,
        rp_id: Option<&str>,
        on_finger: &mut dyn FnMut(),
    ) -> Result<PinUvAuthToken, CtapError> {
        get_token(
            &mut self.dev,
            &self.info,
            TokenSource::Fingerprint,
            permissions,
            rp_id,
            on_finger,
        )
        .map(|(token, _)| token)
    }

    fn make_credential(
        &mut self,
        token: &PinUvAuthToken,
        user_id: &[u8],
        name: &str,
    ) -> Result<MadeCredential, CtapError> {
        let req = MakeCredentialRequest {
            client_data_hash: random32()?,
            rp_id: RP_ID,
            rp_name: RP_NAME,
            user_id,
            user_name: name,
            resident: true,
            cred_protect: Some(3),
            hmac_secret: true,
            large_blob_key: true,
            pin_uv_auth: Some(token),
        };
        make_credential(&mut self.dev, &self.info, &req)
    }

    fn assertions(
        &mut self,
        token: &PinUvAuthToken,
        allow: Option<&[u8]>,
    ) -> Result<Vec<Assertion>, CtapError> {
        let session = hmac_secret::begin(&mut self.dev, &self.info)?;
        let req = GetAssertionRequest {
            client_data_hash: random32()?,
            rp_id: RP_ID,
            allow,
            hmac: Some((&session, prf_salt(PRF_INPUT))),
            large_blob_key: true,
            up: true,
            pin_uv_auth: Some(token),
        };
        no_credentials_as_empty(get_assertions(&mut self.dev, &self.info, &req))
    }

    fn credentials(&mut self, token: &PinUvAuthToken) -> Result<Vec<VaultCredential>, CtapError> {
        let rp_hash = keyroost_proto::sha256::sha256(RP_ID.as_bytes());
        let mut mgr = CredentialManager::new(&mut self.dev, token.clone(), &self.info)?;
        let listed = no_credentials_as_empty(mgr.list_credentials(&rp_hash))?;
        Ok(listed
            .iter()
            .map(|c| VaultCredential {
                vault: VaultRef {
                    credential_id: c.credential_id.clone(),
                    name: vault_name(Some(&c.user.id), c.user.name.as_deref()),
                },
                large_blob_key: c.large_blob_key.map(Zeroizing::new),
                stored: StoredData::Unknown,
            })
            .collect())
    }

    fn delete_credential(
        &mut self,
        token: &PinUvAuthToken,
        credential_id: &[u8],
    ) -> Result<(), CtapError> {
        CredentialManager::new(&mut self.dev, token.clone(), &self.info)?.delete(credential_id)
    }

    fn read_blobs(&mut self) -> Result<LargeBlobArray, CtapError> {
        large_blobs::read(&mut self.dev, &self.info)
    }

    fn write_blobs(&mut self, token: &PinUvAuthToken, serialized: &[u8]) -> Result<(), CtapError> {
        large_blobs::write(&mut self.dev, &self.info, token, serialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyroost_ctap::cbor::{self, Value};
    use keyroost_ctap::cred_mgmt::CTAP2_CREDENTIAL_MANAGEMENT;

    /// Records every credential-management request and answers each with
    /// CTAP2_ERR_NO_CREDENTIALS.
    struct Recorder(Vec<Vec<u8>>);

    impl CtapTransport for Recorder {
        fn transact(&mut self, _cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            self.0.push(payload.to_vec());
            Ok(vec![0x2E])
        }
    }

    /// A request's subCommand and subCommandParams.
    fn sub_command(payload: &[u8]) -> (u64, Option<Value>) {
        assert_eq!(payload[0], CTAP2_CREDENTIAL_MANAGEMENT);
        let (Value::Map(entries), _) = cbor::decode(&payload[1..]).unwrap() else {
            panic!("a map");
        };
        let field = |k| {
            entries
                .iter()
                .find(|(key, _)| *key == Value::UInt(k))
                .map(|(_, v)| v.clone())
        };
        let Some(Value::UInt(sub)) = field(1) else {
            panic!("a subCommand");
        };
        (sub, field(2))
    }

    /// Credential management in the vault flows only ever names the vault
    /// RP: enumerateCredentialsBegin with its rpIdHash and deleteCredential,
    /// never getCredsMetadata or enumerateRPs, which CTAP 2.1 refuses under a
    /// token bound to an RP (6.8.2, 6.8.3). So a fingerprint token bound to
    /// the vault RP serves every credential-management step a flow takes.
    #[test]
    fn credential_management_names_only_the_vault_rp() {
        let info = AuthenticatorInfo {
            options: vec![("credMgmt".into(), true)],
            ..AuthenticatorInfo::default()
        };
        let mut key = CtapVaultKey {
            dev: Recorder(Vec::new()),
            info,
        };
        let token = PinUvAuthToken {
            protocol: 2,
            token: vec![7; 32],
        };
        assert!(key.credentials(&token).unwrap().is_empty());
        let _ = key.delete_credential(&token, &[1, 2, 3]);
        let sent = &key.dev.0;
        assert_eq!(sent.len(), 2);
        let rp_hash = keyroost_proto::sha256::sha256(RP_ID.as_bytes()).to_vec();
        assert_eq!(
            sub_command(&sent[0]),
            (
                0x04,
                Some(Value::Map(vec![(Value::UInt(1), Value::Bytes(rp_hash))]))
            )
        );
        assert_eq!(sub_command(&sent[1]).0, 0x06);
    }
}
