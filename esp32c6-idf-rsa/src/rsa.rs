//! RSA wrapper over mbedtls bundled in ESP-IDF.

use std::{
    ffi::{CStr, c_int},
    ptr,
};

use esp_idf_svc::sys;
use sealed::sealed;
use thiserror::Error;

use crate::wrap::{ErrorCode, Wrapped};

/// RSA wrapper over mbedtls bundled in ESP-IDF.
pub struct Rsa<const BITS: u16> {
    rsa_cx: Wrapped<sys::mbedtls_rsa_context>,
    rng_cx: Wrapped<sys::mbedtls_ctr_drbg_context>,
}

/// RSA keys exported by a context.
pub struct Keys<const BITS: u16> {
    n: Wrapped<sys::mbedtls_mpi>,
    d: Wrapped<sys::mbedtls_mpi>,
    e: Wrapped<sys::mbedtls_mpi>,
}

/// Marker trait for supported RSA key lengths.
#[sealed]
pub trait SupportedLength {}

#[sealed]
impl SupportedLength for Rsa<1024> {}
#[sealed]
impl SupportedLength for Rsa<2048> {}
#[sealed]
impl SupportedLength for Rsa<3072> {}
#[sealed]
impl SupportedLength for Rsa<4096> {}

#[derive(Debug, Error)]
pub enum Error {
    #[error("mbedtls_rsa_gen_key error {0}")]
    RsaGenKey(c_int),
    #[error("mbedtls_rsa_import error {0}")]
    RsaImport(c_int),
    #[error("mbedtls_rsa_check_pub_priv error {0}")]
    RsaCheckPubPriv(c_int),
    #[error("mbedtls_rsa_complete error {0}")]
    RsaComplete(c_int),
    #[error("mbedtls_ctr_drbg_seed error {0}")]
    RandomSeed(c_int),
    #[error("mbedtls_rsa_pkcs1_encrypt error {0}")]
    RsaPkcs1Encrypt(c_int),
    #[error("mbedtls_rsa_pkcs1_decrypt error {0}")]
    RsaPkcs1Decrypt(c_int),
    #[error("mbedtls_rsa_export error {0}")]
    RsaExport(c_int),
    #[error("mbedtls_rsa_set_padding error {0}")]
    RsaSetPadding(c_int),
    #[error("mbedtls_mpi_read_binary_le error {0}")]
    MpiReadBinaryLe(c_int),
    #[error("mbedtls_mpi_write_binary_le error {0}")]
    MpiWriteBinaryLe(c_int),
    #[error("mbedtls_mpi_copy error {0}")]
    MpiCopy(c_int),
    #[error("mbedtls_pk_setup error {0}")]
    PkSetup(c_int),
    #[error("mbedtls_pk_write_pubkey_pem error {0}")]
    PkWritePubkeyPem(c_int),
    #[error("mbedtls_pk_parse_public_key error {0}")]
    PkParsePublicKey(c_int),
    #[error("mbedtls_sha256 error {0}")]
    Sha256(c_int),
    #[error("mbedtls_rsa_rsassa_pss_sign error {0}")]
    RsaSsaPssSign(c_int),
    #[error("mbedtls_rsa_rsassa_pss_verify error {0}")]
    RsaSsaPssVerify(c_int),
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("operation unsupported")]
    Unsupported,
    #[error("allocation failed")]
    Alloc,
}

impl<const BITS: u16> Rsa<BITS>
where
    Rsa<BITS>: SupportedLength,
{
    /// Create a new RSA context with a starting random seed.
    pub fn new(seed: &CStr) -> Result<Self, Error> {
        // SAFETY
        //   - these init and free functions are safe to use this way,
        //     according to the docs.
        //   - `rng_cx` and `ent_cx` are initialized by the time we seed.
        unsafe {
            let rsa_cx =
                Wrapped::new(sys::mbedtls_rsa_init, sys::mbedtls_rsa_free);
            let mut ent_cx = Wrapped::new(
                sys::mbedtls_entropy_init,
                sys::mbedtls_entropy_free,
            );
            let mut rng_cx = Wrapped::new(
                sys::mbedtls_ctr_drbg_init,
                sys::mbedtls_ctr_drbg_free,
            );

            sys::mbedtls_ctr_drbg_seed(
                &raw mut *rng_cx,
                Some(sys::mbedtls_entropy_func),
                (&raw mut *ent_cx).cast(),
                seed.as_ptr(),
                seed.count_bytes(),
            )
            .into_result(0, Error::RandomSeed)?;

            Ok(Self { rsa_cx, rng_cx })
        }
    }

    /// Generates a new RSA key pair inside RSA context.
    pub fn generate_keys(&mut self) -> Result<(), Error> {
        // SAFETY: `rsa_cx` and `rng_cx` are init by this point.
        unsafe {
            sys::mbedtls_rsa_gen_key(
                &raw mut *self.rsa_cx,
                Some(sys::mbedtls_ctr_drbg_random),
                (&raw mut *self.rng_cx).cast(),
                BITS.into(),
                65537,
            )
            .into_result(0, Error::RsaGenKey)?;

            sys::mbedtls_rsa_check_pub_priv(
                &raw mut *self.rsa_cx,
                &raw mut *self.rsa_cx,
            )
            .into_result(0, Error::RsaCheckPubPriv)
        }
    }

    /// Import an RSA key pair into this RSA context.
    pub fn import_keys(&mut self, keys: Keys<BITS>) -> Result<(), Error> {
        // SAFETY:
        //   - rsa_cx is init because we have an exclusive reference to self.
        //   - keys is init because we hold it.
        unsafe {
            sys::mbedtls_rsa_import(
                &raw mut *self.rsa_cx,
                &raw const *keys.n,
                ptr::null(),
                ptr::null(),
                &raw const *keys.d,
                &raw const *keys.e,
            )
            .into_result(0, Error::RsaImport)?;

            sys::mbedtls_rsa_complete(&raw mut *self.rsa_cx)
                .into_result(0, Error::RsaComplete)
        }
    }

    /// Encrypts a message using this RSA context.
    ///
    /// The output buffer must be at least `BITS` bits long.
    pub fn encrypt<'a>(
        &mut self,
        plaintext: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        if ciphertext.len() < BITS as usize / 8 {
            return Err(Error::BufferTooSmall);
        }

        // SAFETY:
        //   - `rsa_cx` and `rng_cx` are init.
        //   - that's the correct random function.
        //   - we checked output has enough space above.
        unsafe {
            sys::mbedtls_rsa_pkcs1_encrypt(
                &raw mut *self.rsa_cx,
                Some(sys::mbedtls_ctr_drbg_random),
                (&raw mut *self.rng_cx).cast(),
                plaintext.len(),
                plaintext.as_ptr(),
                ciphertext.as_mut_ptr(),
            )
            .into_result(0, Error::RsaPkcs1Encrypt)?;

            Ok(ciphertext)
        }
    }

    /// Encrypts a message using this RSA context.
    ///
    /// This is a convenient wrapper around [`Rsa::encrypt`].
    pub fn encrypt_to_vec(
        &mut self,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0; BITS as usize / 8];
        self.encrypt(plaintext, &mut buf)?;
        Ok(buf)
    }

    /// Decrypts a message using this RSA context.
    ///
    /// The input buffer must be exactly `BITS` bits long.
    pub fn decrypt<'a>(
        &mut self,
        ciphertext: &[u8],
        plaintext: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        if ciphertext.len() < BITS as usize / 8 {
            return Err(Error::BufferTooSmall);
        }

        let mut olen = 0;

        // SAFETY: see `Rsa::encrypt`. also `olen` is trivially valid.
        unsafe {
            sys::mbedtls_rsa_pkcs1_decrypt(
                &raw mut *self.rsa_cx,
                Some(sys::mbedtls_ctr_drbg_random),
                (&raw mut *self.rng_cx).cast(),
                &raw mut olen,
                ciphertext.as_ptr(),
                plaintext.as_mut_ptr(),
                plaintext.len(),
            )
            .into_result(0, Error::RsaPkcs1Decrypt)?;

            Ok(&plaintext[..olen])
        }
    }

    /// Decrypts a message using this RSA context to a Vec.
    ///
    /// This is a convenient wrapper around [`Rsa::decrypt`].
    pub fn decrypt_to_vec(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // see https://stackoverflow.com/a/5586652 for the rationale behind
        // the buffer size
        let mut buf = vec![0; BITS as usize / 8 - 11];
        let len = self.decrypt(ciphertext, &mut buf)?.len();
        buf.truncate(len);
        Ok(buf)
    }

    /// Signs a message using this RSA context with PSS padding and SHA-256
    /// into an external buffer.
    pub fn sign<'a>(
        &mut self,
        message: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        unsafe {
            let mut hash = vec![0; 256 / 8];
            sys::mbedtls_sha256(
                message.as_ptr(),
                message.len(),
                hash.as_mut_ptr(),
                0,
            )
            .into_result(0, Error::Sha256)?;

            // set this for [`Rsa::sign`]
            sys::mbedtls_rsa_set_padding(
                &raw mut *self.rsa_cx,
                sys::MBEDTLS_RSA_PKCS_V21 as _,
                sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
            )
            .into_result(0, Error::RsaSetPadding)?;

            sys::mbedtls_rsa_rsassa_pss_sign(
                &raw mut *self.rsa_cx,
                Some(sys::mbedtls_ctr_drbg_random),
                (&raw mut *self.rng_cx).cast(),
                sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
                hash.len() as _,
                hash.as_ptr(),
                signature.as_mut_ptr(),
            )
            .into_result(0, Error::RsaSsaPssSign)?;

            Ok(signature)
        }
    }

    /// Signs a message using this RSA context with PSS padding and SHA-256
    /// into a [`Vec`].
    ///
    /// This is a convenient wrapper around [`Rsa::sign`].
    pub fn sign_to_vec(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0; BITS as usize / 8];
        self.sign(message, &mut sig)?;
        Ok(sig)
    }

    /// Exports the keys generated by this context, if they have already been
    /// generated before.
    pub fn export(&self) -> Result<Keys<BITS>, Error> {
        // SAFETY:
        //   - mbedtls_mpi_init and mbedtls_mpi_free are okay to use this way.
        //   - n, d, e are init by the time we export.
        unsafe {
            let mut n =
                Wrapped::new(sys::mbedtls_mpi_init, sys::mbedtls_mpi_free);
            let mut d =
                Wrapped::new(sys::mbedtls_mpi_init, sys::mbedtls_mpi_free);
            let mut e =
                Wrapped::new(sys::mbedtls_mpi_init, sys::mbedtls_mpi_free);

            match sys::mbedtls_rsa_export(
                &raw const *self.rsa_cx,
                &raw mut *n,
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut *d,
                &raw mut *e,
            ) {
                0 => Ok(Keys { n, d, e }),
                sys::MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED => {
                    Err(Error::Unsupported)
                }
                code => Err(Error::RsaExport(code)),
            }
        }
    }
}

impl<const BITS: u16> Keys<BITS> {
    /// Reads keys from buffers.
    pub fn read(
        n_buf: &[u8],
        d_buf: &[u8],
        e_buf: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            n: Self::read_buf(n_buf)?,
            d: Self::read_buf(d_buf)?,
            e: Self::read_buf(e_buf)?,
        })
    }

    /// Writes `n`, `d` and `e` values to external buffers.
    pub fn write(
        &self,
        n: &mut [u8],
        d: &mut [u8],
        e: &mut [u8],
    ) -> Result<(), Error> {
        if n.len() < BITS as usize / 8
            || d.len() < BITS as usize / 8
            || e.len() < BITS as usize / 8
        {
            return Err(Error::BufferTooSmall);
        }

        Self::write_buf(&self.n, n)?;
        Self::write_buf(&self.d, d)?;
        Self::write_buf(&self.e, e)?;
        Ok(())
    }

    /// Writes the PEM-formatted public key to an external buffer.
    pub fn write_pubkey_pem(&self, buf: &mut [u8]) -> Result<(), Error> {
        unsafe {
            let mut pk =
                Wrapped::new(sys::mbedtls_pk_init, sys::mbedtls_pk_free);

            sys::mbedtls_pk_setup(
                &raw mut *pk,
                sys::mbedtls_pk_info_from_type(
                    sys::mbedtls_pk_type_t_MBEDTLS_PK_RSA,
                ),
            )
            .into_result(0, Error::PkSetup)?;

            let pk_rsa = pk.private_pk_ctx.cast::<sys::mbedtls_rsa_context>();

            let mut n =
                Wrapped::new(sys::mbedtls_mpi_init, sys::mbedtls_mpi_free);
            let mut e =
                Wrapped::new(sys::mbedtls_mpi_init, sys::mbedtls_mpi_free);

            sys::mbedtls_mpi_copy(&raw mut *n, &raw const *self.n)
                .into_result(0, Error::MpiCopy)?;
            sys::mbedtls_mpi_copy(&raw mut *e, &raw const *self.e)
                .into_result(0, Error::MpiCopy)?;

            sys::mbedtls_rsa_import(
                &raw mut *pk_rsa,
                &raw const *n,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                &raw const *e,
            )
            .into_result(0, Error::RsaImport)?;

            sys::mbedtls_rsa_complete(&raw mut *pk_rsa)
                .into_result(0, Error::RsaComplete)?;

            sys::mbedtls_pk_write_pubkey_pem(
                &raw const *pk,
                buf.as_mut_ptr(),
                buf.len(),
            )
            .into_result(0, Error::PkWritePubkeyPem)
        }
    }

    /// Writes `n`, `d` and `e` values to external buffers.
    ///
    /// This is a convenient wrapper around [`Keys::write`].
    #[allow(clippy::type_complexity)]
    pub fn write_to_vec(&self) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
        let mut n = vec![0; BITS as usize / 8];
        let mut d = vec![0; BITS as usize / 8];
        let mut e = vec![0; BITS as usize / 8];
        self.write(&mut n, &mut d, &mut e)?;
        Ok((n, d, e))
    }

    /// Writes the PEM-formatted public key to a [`Vec`].
    pub fn write_pubkey_to_vec_pem(&self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0];
        while self.write_pubkey_pem(&mut buf).is_err() {
            buf.resize(buf.len() * 2, 0);
        }
        Ok(buf)
    }

    /// Reads a buffer into a [`sys::mbedtls_mpi`].
    fn read_buf(buf: &[u8]) -> Result<Wrapped<sys::mbedtls_mpi>, Error> {
        // SAFETY: mpi is init because of Wrapped.
        unsafe {
            let mut mpi =
                Wrapped::new(sys::mbedtls_mpi_init, sys::mbedtls_mpi_free);
            match sys::mbedtls_mpi_read_binary_le(
                &raw mut *mpi,
                buf.as_ptr(),
                buf.len(),
            ) {
                0 => Ok(mpi),
                sys::MBEDTLS_ERR_MPI_ALLOC_FAILED => Err(Error::Alloc),
                code => Err(Error::MpiReadBinaryLe(code)),
            }
        }
    }

    /// Writes a [`sys::mbedtls_mpi`] to a buffer.
    fn write_buf(
        mpi: &Wrapped<sys::mbedtls_mpi>,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        // SAFETY: mpi is init because of Wrapped.
        match unsafe {
            sys::mbedtls_mpi_write_binary_le(
                &raw const **mpi,
                buf.as_mut_ptr(),
                buf.len(),
            )
        } {
            0 => Ok(()),
            sys::MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL => Err(Error::BufferTooSmall),
            code => Err(Error::MpiWriteBinaryLe(code)),
        }
    }
}

/// Verifies a message using this RSA context with PSS padding and SHA-256.
pub fn verify(
    pubkey: &sys::mbedtls_pk_context,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    unsafe {
        let mut hash = vec![0; 256 / 8];
        sys::mbedtls_sha256(
            message.as_ptr(),
            message.len(),
            hash.as_mut_ptr(),
            0,
        )
        .into_result(0, Error::Sha256)?;

        sys::mbedtls_rsa_rsassa_pss_verify(
            pubkey.private_pk_ctx.cast(),
            sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
            hash.len() as _,
            hash.as_ptr(),
            signature.as_ptr(),
        )
        .into_result(0, Error::RsaSsaPssVerify)
    }
}
