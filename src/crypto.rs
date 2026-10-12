//! Encryption at rest (PRD R-CRY-1..3, DEVELOPMENT.md §7).
//!
//! Two key layers: a per-vault KEK held only in `keys_dir`, and a random
//! per-object DEK wrapped by the KEK and stored beside the object. Deleting
//! the wrapped DEK is what makes "deleted" mean something on a filesystem
//! that doesn't erase (crypto-shredding, F-8).
//!
//! Bodies are encrypted in 1 MiB chunks so the daemon never holds a whole
//! object in memory and never writes plaintext to disk (R-CRY-5):
//!
//! ```text
//! file  = prefix(8) ‖ chunk*
//! chunk = len(u32 BE) ‖ AES-256-GCM(DEK, nonce, aad, plaintext)
//! nonce = prefix(8) ‖ index(u32 BE)
//! aad   = handle ‖ index(u32 BE) ‖ final(1 byte: 0x00 / 0x01)
//! ```
//!
//! Exactly one chunk carries `final = 0x01`; it may be empty. The reader
//! rejects a missing final chunk (truncation), an index skew (reordering —
//! the index is in both nonce and AAD, so the tag fails), and anything after
//! the final chunk.

use std::io::{self, Read, Write};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::handle::Handle;

/// Plaintext bytes per chunk.
pub const CHUNK_SIZE: usize = 1 << 20;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const PREFIX_LEN: usize = 8;
const KEY_LEN: usize = 32;

/// Errors from the crypto layer. The `Display` strings never include key
/// material, plaintext, or handles.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    #[error("random number generator unavailable")]
    Rng(#[from] getrandom::Error),
    #[error(
        "authentication failed: ciphertext was modified, reordered, or belongs to another object"
    )]
    Authentication,
    #[error("ciphertext is truncated: no final chunk")]
    Truncated,
    #[error("unexpected data after the final chunk")]
    Trailing,
    #[error("chunk length field is impossible")]
    BadLength,
    #[error("object has too many chunks")]
    TooManyChunks,
    #[error("wrapped key has the wrong length")]
    BadWrappedKey,
}

/// A 256-bit key that wipes itself on drop and never prints.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    /// Fresh key from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(k.as_mut_slice())?;
        Ok(Self(k))
    }

    /// Wrap raw bytes (e.g. read from a key file).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Raw bytes, for writing a key file. Nowhere else.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new((&*self.0).into())
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key([redacted])")
    }
}

/// Per-vault key encryption key.
pub type Kek = Key;
/// Per-object data encryption key.
pub type Dek = Key;

type GcmNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

fn nonce(bytes: [u8; NONCE_LEN]) -> GcmNonce {
    GcmNonce::from(bytes)
}

fn random_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::fill(&mut n)?;
    Ok(n)
}

fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes = random_nonce()?;
    let ct = key
        .cipher()
        .encrypt(
            &self::nonce(nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Authentication)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open(key: &Key, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Authentication);
    }
    let (nonce_slice, ct) = sealed.split_at(NONCE_LEN);
    let nonce_bytes: [u8; NONCE_LEN] = nonce_slice
        .try_into()
        .map_err(|_| CryptoError::Authentication)?;
    key.cipher()
        .decrypt(&self::nonce(nonce_bytes), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Authentication)
}

const WRAP_AAD_SUFFIX: &[u8] = b"\0dek";
const META_AAD_SUFFIX: &[u8] = b"\0meta";

fn aad_for(handle: &Handle, suffix: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(handle.as_bytes().len() + suffix.len());
    aad.extend_from_slice(handle.as_bytes());
    aad.extend_from_slice(suffix);
    aad
}

/// Wrap a DEK under the vault KEK, bound to the object's handle.
pub fn wrap_dek(kek: &Kek, handle: &Handle, dek: &Dek) -> Result<Vec<u8>, CryptoError> {
    seal(kek, &aad_for(handle, WRAP_AAD_SUFFIX), dek.as_bytes())
}

/// Unwrap a DEK. Fails if the KEK is wrong, the bytes were modified, or the
/// wrapped key belongs to a different handle.
pub fn unwrap_dek(kek: &Kek, handle: &Handle, wrapped: &[u8]) -> Result<Dek, CryptoError> {
    let raw = Zeroizing::new(open(kek, &aad_for(handle, WRAP_AAD_SUFFIX), wrapped)?);
    let bytes: [u8; KEY_LEN] = raw
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadWrappedKey)?;
    Ok(Key::from_bytes(bytes))
}

/// Encrypt an object's small metadata record (name, labels, mime).
pub fn seal_meta(dek: &Dek, handle: &Handle, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    seal(dek, &aad_for(handle, META_AAD_SUFFIX), plaintext)
}

/// Decrypt an object's metadata record.
pub fn open_meta(dek: &Dek, handle: &Handle, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    open(dek, &aad_for(handle, META_AAD_SUFFIX), sealed)
}

fn chunk_nonce(prefix: [u8; PREFIX_LEN], index: u32) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..PREFIX_LEN].copy_from_slice(&prefix);
    n[PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    n
}

fn chunk_aad(handle: &Handle, index: u32, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(handle.as_bytes().len() + 5);
    aad.extend_from_slice(handle.as_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(is_final));
    aad
}

/// What a finished body write tells the caller: the plaintext digest for the
/// audit log and the size for the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyDigest {
    pub sha256: [u8; 32],
    pub size: u64,
    pub chunks: u32,
}

/// Streaming encryptor. Implements [`Write`]; call [`BodyWriter::finish`]
/// to emit the final chunk. Dropping without `finish` leaves a file the
/// reader rejects as truncated — which is the behaviour we want for an
/// aborted put.
pub struct BodyWriter<W: Write> {
    cipher: Aes256Gcm,
    handle: Handle,
    out: W,
    prefix: [u8; PREFIX_LEN],
    index: u32,
    buf: Vec<u8>,
    hasher: Sha256,
    size: u64,
}

impl<W: Write> std::fmt::Debug for BodyWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyWriter")
            .field("handle", &self.handle)
            .field("index", &self.index)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl<W: Write> BodyWriter<W> {
    /// Start a body: picks a random nonce prefix and writes it.
    pub fn new(dek: &Dek, handle: &Handle, mut out: W) -> Result<Self, CryptoError> {
        let mut prefix = [0u8; PREFIX_LEN];
        getrandom::fill(&mut prefix)?;
        out.write_all(&prefix)?;
        Ok(Self {
            cipher: dek.cipher(),
            handle: handle.clone(),
            out,
            prefix,
            index: 0,
            buf: Vec::with_capacity(CHUNK_SIZE),
            hasher: Sha256::new(),
            size: 0,
        })
    }

    fn emit(&mut self, is_final: bool) -> Result<(), CryptoError> {
        let n = nonce(chunk_nonce(self.prefix, self.index));
        let aad = chunk_aad(&self.handle, self.index, is_final);
        let ct = self
            .cipher
            .encrypt(
                &n,
                Payload {
                    msg: &self.buf,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?;
        let len = u32::try_from(ct.len()).map_err(|_| CryptoError::BadLength)?;
        self.out.write_all(&len.to_be_bytes())?;
        self.out.write_all(&ct)?;
        self.buf.clear();
        self.index = self
            .index
            .checked_add(1)
            .ok_or(CryptoError::TooManyChunks)?;
        Ok(())
    }

    /// Write the final chunk (possibly empty), flush, and return the digest
    /// plus the underlying writer.
    pub fn finish(mut self) -> Result<(W, BodyDigest), CryptoError> {
        self.emit(true)?;
        self.out.flush()?;
        let digest = BodyDigest {
            sha256: self.hasher.finalize().into(),
            size: self.size,
            chunks: self.index,
        };
        Ok((self.out, digest))
    }
}

impl<W: Write> Write for BodyWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            let room = CHUNK_SIZE - self.buf.len();
            let take = room.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            self.hasher.update(&rest[..take]);
            self.size += take as u64;
            rest = &rest[take..];
            if self.buf.len() == CHUNK_SIZE {
                self.emit(false).map_err(io::Error::other)?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Streaming decryptor. Yields plaintext chunks until the final one, then
/// confirms nothing follows.
pub struct BodyReader<R: Read> {
    cipher: Aes256Gcm,
    handle: Handle,
    inp: R,
    prefix: [u8; PREFIX_LEN],
    index: u32,
    done: bool,
}

impl<R: Read> std::fmt::Debug for BodyReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyReader")
            .field("handle", &self.handle)
            .field("index", &self.index)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<R: Read> BodyReader<R> {
    /// Open a body: reads the nonce prefix.
    pub fn new(dek: &Dek, handle: &Handle, mut inp: R) -> Result<Self, CryptoError> {
        let mut prefix = [0u8; PREFIX_LEN];
        inp.read_exact(&mut prefix)
            .map_err(|_| CryptoError::Truncated)?;
        Ok(Self {
            cipher: dek.cipher(),
            handle: handle.clone(),
            inp,
            prefix,
            index: 0,
            done: false,
        })
    }

    /// Next plaintext chunk, or `None` once the final chunk has been
    /// returned and the stream verified to end there.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, CryptoError> {
        if self.done {
            return Ok(None);
        }
        let mut len_buf = [0u8; 4];
        if let Err(e) = self.inp.read_exact(&mut len_buf) {
            return Err(if e.kind() == io::ErrorKind::UnexpectedEof {
                CryptoError::Truncated
            } else {
                CryptoError::Io(e)
            });
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if !(TAG_LEN..=CHUNK_SIZE + TAG_LEN).contains(&len) {
            return Err(CryptoError::BadLength);
        }
        let mut ct = vec![0u8; len];
        if let Err(e) = self.inp.read_exact(&mut ct) {
            return Err(if e.kind() == io::ErrorKind::UnexpectedEof {
                CryptoError::Truncated
            } else {
                CryptoError::Io(e)
            });
        }
        let n = nonce(chunk_nonce(self.prefix, self.index));
        // We don't know whether this chunk is final until it authenticates:
        // try the non-final AAD first (the common case), then the final one.
        // A forged flag can't pass either way because the flag is inside AAD.
        let non_final = chunk_aad(&self.handle, self.index, false);
        let as_non_final = self.cipher.decrypt(
            &n,
            Payload {
                msg: &ct,
                aad: &non_final,
            },
        );
        let plaintext = if let Ok(pt) = as_non_final {
            pt
        } else {
            let fin = chunk_aad(&self.handle, self.index, true);
            let pt = self
                .cipher
                .decrypt(
                    &n,
                    Payload {
                        msg: &ct,
                        aad: &fin,
                    },
                )
                .map_err(|_| CryptoError::Authentication)?;
            self.done = true;
            let mut probe = [0u8; 1];
            match self.inp.read(&mut probe) {
                Ok(0) => {}
                Ok(_) => return Err(CryptoError::Trailing),
                Err(e) => return Err(CryptoError::Io(e)),
            }
            pt
        };
        self.index = self
            .index
            .checked_add(1)
            .ok_or(CryptoError::TooManyChunks)?;
        Ok(Some(plaintext))
    }

    /// Read every chunk into one buffer. For small objects and tests only;
    /// the daemon streams.
    pub fn read_all(mut self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        while let Some(chunk) = self.next_chunk()? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// SHA-256 of a byte string, as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn handle() -> Handle {
        Handle::parse("v_0123456789ab").unwrap_or_else(|e| panic!("{e}"))
    }

    fn encrypt(dek: &Dek, h: &Handle, data: &[u8]) -> (Vec<u8>, BodyDigest) {
        let w = BodyWriter::new(dek, h, Vec::new()).unwrap_or_else(|e| panic!("{e}"));
        let mut w = w;
        // write in awkward pieces to exercise buffering
        for piece in data.chunks(300_007) {
            w.write_all(piece).unwrap_or_else(|e| panic!("{e}"));
        }
        w.finish().unwrap_or_else(|e| panic!("{e}"))
    }

    fn decrypt(dek: &Dek, h: &Handle, file: &[u8]) -> Result<Vec<u8>, CryptoError> {
        BodyReader::new(dek, h, file)?.read_all()
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn round_trip_various_sizes() {
        let dek = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        let h = handle();
        for n in [
            0,
            1,
            17,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            3 * CHUNK_SIZE + 5,
        ] {
            let data = pattern(n);
            let (file, digest) = encrypt(&dek, &h, &data);
            assert_eq!(digest.size as usize, n);
            assert_eq!(digest.sha256, <[u8; 32]>::from(Sha256::digest(&data)));
            let expected_chunks = (n / CHUNK_SIZE) as u32 + 1;
            assert_eq!(digest.chunks, expected_chunks, "n={n}");
            let back = decrypt(&dek, &h, &file).unwrap_or_else(|e| panic!("n={n}: {e}"));
            assert_eq!(back, data, "n={n}");
        }
    }

    #[test]
    fn ciphertext_differs_between_identical_puts_and_hides_plaintext() {
        let dek = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        let h = handle();
        let data = b"SENTINEL-the quick brown fox jumps over the lazy dog-SENTINEL".repeat(100);
        let (a, _) = encrypt(&dek, &h, &data);
        let (b, _) = encrypt(&dek, &h, &data);
        assert_ne!(a, b);
        let needle = b"quick brown fox";
        assert!(!a.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn truncation_is_detected() {
        let dek = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        let h = handle();
        let data = pattern(2 * CHUNK_SIZE + 10);
        let (file, _) = encrypt(&dek, &h, &data);
        // drop the final (third) chunk entirely: the reader must not return
        // the first two chunks as a complete object
        let second_chunk_len = u32::from_be_bytes(
            file[PREFIX_LEN + 4 + CHUNK_SIZE + TAG_LEN..][..4]
                .try_into()
                .unwrap_or_else(|_| panic!("slice")),
        ) as usize;
        let cut = PREFIX_LEN + (4 + CHUNK_SIZE + TAG_LEN) + (4 + second_chunk_len);
        assert!(matches!(
            decrypt(&dek, &h, &file[..cut]),
            Err(CryptoError::Truncated)
        ));
        // cut mid-chunk
        assert!(matches!(
            decrypt(&dek, &h, &file[..file.len() - 5]),
            Err(CryptoError::Truncated)
        ));
        // cut inside the prefix
        assert!(matches!(
            decrypt(&dek, &h, &file[..3]),
            Err(CryptoError::Truncated)
        ));
        // empty file
        assert!(matches!(
            decrypt(&dek, &h, &[]),
            Err(CryptoError::Truncated)
        ));
    }

    #[test]
    fn reorder_and_bitflip_and_trailing_are_detected() {
        let dek = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        let h = handle();
        let data = pattern(2 * CHUNK_SIZE);
        let (file, digest) = encrypt(&dek, &h, &data);
        assert_eq!(digest.chunks, 3);
        let c1 = PREFIX_LEN;
        let clen = 4 + CHUNK_SIZE + TAG_LEN;
        // swap chunks 0 and 1 (same length)
        let mut swapped = file.clone();
        swapped[c1..c1 + clen].copy_from_slice(&file[c1 + clen..c1 + 2 * clen]);
        swapped[c1 + clen..c1 + 2 * clen].copy_from_slice(&file[c1..c1 + clen]);
        assert!(matches!(
            decrypt(&dek, &h, &swapped),
            Err(CryptoError::Authentication)
        ));
        // flip one bit in the second chunk
        let mut flipped = file.clone();
        flipped[c1 + clen + 100] ^= 0x01;
        assert!(matches!(
            decrypt(&dek, &h, &flipped),
            Err(CryptoError::Authentication)
        ));
        // trailing garbage after the final chunk
        let mut trailing = file.clone();
        trailing.push(0);
        assert!(matches!(
            decrypt(&dek, &h, &trailing),
            Err(CryptoError::Trailing)
        ));
        // duplicate the final chunk: second copy has wrong index -> auth fails
        let final_start = c1 + 2 * clen;
        let mut dup = file.clone();
        dup.extend_from_slice(&file[final_start..]);
        assert!(matches!(
            decrypt(&dek, &h, &dup),
            Err(CryptoError::Trailing | CryptoError::Authentication)
        ));
    }

    #[test]
    fn wrong_key_or_handle_fails() {
        let dek = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        let other = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        let h = handle();
        let h2 = Handle::parse("v_ba9876543210").unwrap_or_else(|e| panic!("{e}"));
        let (file, _) = encrypt(&dek, &h, b"hello");
        assert!(matches!(
            decrypt(&other, &h, &file),
            Err(CryptoError::Authentication)
        ));
        assert!(matches!(
            decrypt(&dek, &h2, &file),
            Err(CryptoError::Authentication)
        ));
    }

    #[test]
    fn dek_wrap_round_trip_and_binding() {
        let kek = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        let dek = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        let h = handle();
        let wrapped = wrap_dek(&kek, &h, &dek).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(wrapped.len(), NONCE_LEN + KEY_LEN + TAG_LEN);
        let back = unwrap_dek(&kek, &h, &wrapped).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back.as_bytes(), dek.as_bytes());
        let h2 = Handle::parse("v_ba9876543210").unwrap_or_else(|e| panic!("{e}"));
        assert!(unwrap_dek(&kek, &h2, &wrapped).is_err());
        let other = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        assert!(unwrap_dek(&other, &h, &wrapped).is_err());
        let mut tampered = wrapped.clone();
        tampered[NONCE_LEN + 3] ^= 0xff;
        assert!(unwrap_dek(&kek, &h, &tampered).is_err());
        assert!(unwrap_dek(&kek, &h, &wrapped[..10]).is_err());
    }

    #[test]
    fn meta_seal_round_trip() {
        let dek = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        let h = handle();
        let sealed = seal_meta(&dek, &h, b"{\"name\":\"x\"}").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            open_meta(&dek, &h, &sealed).unwrap_or_else(|e| panic!("{e}")),
            b"{\"name\":\"x\"}"
        );
        // a wrapped DEK blob is not accepted as a meta blob (different AAD suffix)
        let wrapped = wrap_dek(&dek, &h, &dek).unwrap_or_else(|e| panic!("{e}"));
        assert!(open_meta(&dek, &h, &wrapped).is_err());
    }

    #[test]
    fn key_debug_is_redacted() {
        let k = Key::generate().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(format!("{k:?}"), "Key([redacted])");
    }

    #[test]
    fn sha256_hex_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
