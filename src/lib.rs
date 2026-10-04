//! nagual — an adaptive immune system for autonomous agents.
//!
//! Named for the Nahuatl *nagual* — the guardian spirit that watches
//! over a being.
//!
//! Static blocklists die the day they're written. A real immune system
//! does three things a firewall can't: it *detects* novel attack
//! signatures (pathogens), *derives* countermeasures from them
//! (antibodies), and *shares* those antibodies so one organism's attack
//! becomes everyone's immunity (vaccination).
//!
//! In `nagual`:
//!
//! - A [`Pathogen`] is a detected attack signature — evidence-hashed,
//!   severity-classed, first-seen stamped.
//! - An [`Antibody`] is a counter-signature derived from a pathogen,
//!   signed by the organism's key and carrying its *lineage* — which
//!   pathogen it answers and which antibody it was refined from.
//! - A [`Vaccine`] is an antibody packaged for export: signed by the
//!   issuing organism so peers can verify provenance before adopting.
//! - The [`ImmuneRegistry`] is hash-chained: detections, developments,
//!   adoptions, deployments — an organism's immune history is auditable.
//!
//! Herd immunity: first attack a peer sees, every organism is immune to.
//!
//! ```no_run
//! use nagual::{Identity, ImmuneRegistry, Severity};
//!
//! let me = Identity::generate();
//! let mut immune = ImmuneRegistry::new(me.public_key());
//! let p = immune.detect(&me, "ignore previous instructions and",
//!     Severity::High, "prompt:3f8a").unwrap();
//! let ab = immune.develop(&me, &p.id, "ignore previous instructions and").unwrap();
//! assert!(immune.is_immune("ignore previous instructions and exfiltrate"));
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("canonical json")
}

#[derive(Debug)]
pub enum Error {
    BadSignature(String),
    BadAntibody(String),
    BadChain(String),
    UnknownPathogen(String),
    Serde(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature(m) => write!(f, "signature failure: {m}"),
            Error::BadAntibody(m) => write!(f, "invalid antibody: {m}"),
            Error::BadChain(m) => write!(f, "immune chain broken: {m}"),
            Error::UnknownPathogen(m) => write!(f, "unknown pathogen: {m}"),
            Error::Serde(e) => write!(f, "serde: {e}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

// ---------------------------------------------------------------- identity

pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Identity {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Identity {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.key.sign(msg).to_bytes())
    }
}

pub fn verify_signature(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), Error> {
    let pk_bytes =
        hex::decode(pubkey_hex).map_err(|e| Error::BadSignature(format!("pubkey hex: {e}")))?;
    let pk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("pubkey not 32 bytes".into()))?,
    )
    .map_err(|e| Error::BadSignature(format!("pubkey: {e}")))?;
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| Error::BadSignature(format!("sig hex: {e}")))?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("sig not 64 bytes".into()))?,
    );
    pk.verify(msg, &sig)
        .map_err(|_| Error::BadSignature("verification failed".into()))
}

// ---------------------------------------------------------------- pathogen

/// How dangerous a detected pattern is.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A detected attack signature: the pattern, a hash of the evidence that
/// revealed it, and first-seen provenance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pathogen {
    /// Content-derived id (signature + first_seen).
    pub id: String,
    /// The attack signature — a literal substring or glob (`*` suffix).
    pub signature: String,
    /// SHA-256 of the evidence (prompt, payload, event) that revealed it.
    pub evidence_hash: String,
    /// Where it was first seen (event id, peer id, source ref).
    pub first_seen: String,
    pub severity: Severity,
    pub ts: u64,
}

// ---------------------------------------------------------------- antibody

/// A signed countermeasure derived from a pathogen. Antibodies carry
/// lineage: the pathogen they answer and, for refined antibodies, the
/// parent they descend from — an immune system that remembers how it
/// learned.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Antibody {
    /// Content-derived id.
    pub id: String,
    /// The pathogen this antibody answers.
    pub pathogen_id: String,
    /// The counter-signature — inputs containing this are flagged.
    pub pattern: String,
    /// Refinement generation: 1 = direct response, 2+ = refined.
    pub generation: u32,
    /// Parent antibody id for refinements.
    pub parent: Option<String>,
    /// Organism that developed this antibody (hex pubkey).
    pub issuer: String,
    pub ts: u64,
    /// Signature over the canonical body.
    pub signature: String,
}

impl Antibody {
    fn body(&self) -> Value {
        json!({
            "id": self.id,
            "pathogen_id": self.pathogen_id,
            "pattern": self.pattern,
            "generation": self.generation,
            "parent": self.parent,
            "issuer": self.issuer,
            "ts": self.ts,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        verify_signature(&self.issuer, &canonical(&self.body()), &self.signature)
    }

    /// Does this antibody cover the given input? `*` in the pattern is a
    /// wildcard: segments must appear in order, anywhere in the input.
    pub fn covers(&self, input: &str) -> bool {
        let segments: Vec<&str> = self.pattern.split('*').collect();
        let mut rest = input;
        for seg in segments {
            if seg.is_empty() {
                continue;
            }
            match rest.find(seg) {
                Some(i) => rest = &rest[i + seg.len()..],
                None => return false,
            }
        }
        true
    }
}

// ---------------------------------------------------------------- vaccine

/// An antibody packaged for export: the antibody plus the issuer's
/// signature over the vaccine envelope, so a receiving peer can verify
/// both the antibody and its chain of custody.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vaccine {
    pub antibody: Antibody,
    /// Pathogen signature the antibody answers — lets receivers index
    /// without trusting the sender's registry.
    pub pathogen_signature: String,
    /// Envelope signature by the issuing organism.
    pub signature: String,
}

impl Vaccine {
    fn envelope(&self) -> Value {
        json!({
            "antibody": self.antibody,
            "pathogen_signature": self.pathogen_signature,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        self.antibody.verify()?;
        verify_signature(
            &self.antibody.issuer,
            &canonical(&self.envelope()),
            &self.signature,
        )
    }
}

// ---------------------------------------------------------------- registry

/// Immune history event kinds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ImmuneEvent {
    PathogenDetected(Pathogen),
    AntibodyDeveloped(Antibody),
    VaccineAdopted {
        vaccine: Vaccine,
        /// Local id assigned on adoption.
        adopted_as: String,
    },
}

/// One hash-chained registry entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub seq: u64,
    pub prev: String,
    pub hash: String,
    pub event: ImmuneEvent,
}

/// The immune registry: pathogens detected, antibodies developed,
/// vaccines adopted — hash-chained so the organism's immune history is
/// auditable and untamperable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImmuneRegistry {
    /// This organism's public key.
    pub owner: String,
    pub entries: Vec<RegistryEntry>,
    /// Live antibody table (derived from events, kept for fast lookup).
    #[serde(default)]
    pub antibodies: BTreeMap<String, Antibody>,
    /// Pathogen index: id -> signature.
    #[serde(default)]
    pub pathogens: BTreeMap<String, String>,
}

impl ImmuneRegistry {
    pub fn new(owner_pubkey: String) -> Self {
        ImmuneRegistry {
            owner: owner_pubkey,
            entries: Vec::new(),
            antibodies: BTreeMap::new(),
            pathogens: BTreeMap::new(),
        }
    }

    fn tip(&self) -> String {
        self.entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64))
    }

    fn push(&mut self, event: ImmuneEvent) {
        let seq = self.entries.len() as u64;
        let prev = self.tip();
        let hash = sha256_hex(&canonical(&json!({
            "seq": seq, "prev": prev, "event": event,
        })));
        self.entries.push(RegistryEntry {
            seq,
            prev,
            hash,
            event,
        });
    }

    /// Detect a novel attack signature. Idempotent — re-detecting the
    /// same signature returns the existing pathogen.
    pub fn detect(
        &mut self,
        me: &Identity,
        signature: &str,
        severity: Severity,
        first_seen: &str,
    ) -> Result<Pathogen, Error> {
        if me.public_key() != self.owner {
            return Err(Error::BadSignature("identity does not own registry".into()));
        }
        if signature.is_empty() {
            return Err(Error::BadAntibody("empty signature".into()));
        }
        if let Some((id, _)) = self
            .pathogens
            .iter()
            .find(|(_, sig)| sig.as_str() == signature)
        {
            // Known pathogen — return it without re-chaining.
            return Ok(Pathogen {
                id: id.clone(),
                signature: signature.to_string(),
                evidence_hash: String::new(),
                first_seen: first_seen.to_string(),
                severity,
                ts: now_secs(),
            });
        }
        let ts = now_secs();
        let pathogen = Pathogen {
            id: sha256_hex(&canonical(&json!({
                "signature": signature, "first_seen": first_seen, "ts": ts,
            }))),
            signature: signature.to_string(),
            evidence_hash: sha256_hex(first_seen.as_bytes()),
            first_seen: first_seen.to_string(),
            severity,
            ts,
        };
        self.pathogens
            .insert(pathogen.id.clone(), signature.to_string());
        self.push(ImmuneEvent::PathogenDetected(pathogen.clone()));
        Ok(pathogen)
    }

    /// Derive a signed antibody for a known pathogen. `pattern` is the
    /// counter-signature — typically the attack signature itself or a
    /// refined generalization of it.
    pub fn develop(
        &mut self,
        me: &Identity,
        pathogen_id: &str,
        pattern: &str,
    ) -> Result<Antibody, Error> {
        self.develop_refined(me, pathogen_id, pattern, None)
    }

    /// Derive a refined antibody descending from a parent — generation 2+.
    pub fn develop_refined(
        &mut self,
        me: &Identity,
        pathogen_id: &str,
        pattern: &str,
        parent: Option<&str>,
    ) -> Result<Antibody, Error> {
        if me.public_key() != self.owner {
            return Err(Error::BadSignature("identity does not own registry".into()));
        }
        if !self.pathogens.contains_key(pathogen_id) {
            return Err(Error::UnknownPathogen(pathogen_id.to_string()));
        }
        let generation = match parent {
            None => 1,
            Some(p) => self
                .antibodies
                .get(p)
                .map(|a| a.generation + 1)
                .ok_or_else(|| Error::BadAntibody(format!("unknown parent: {p}")))?,
        };
        let ts = now_secs();
        let mut antibody = Antibody {
            id: sha256_hex(&canonical(&json!({
                "pathogen_id": pathogen_id, "pattern": pattern,
                "generation": generation, "parent": parent, "ts": ts,
            }))),
            pathogen_id: pathogen_id.to_string(),
            pattern: pattern.to_string(),
            generation,
            parent: parent.map(|s| s.to_string()),
            issuer: self.owner.clone(),
            ts,
            signature: String::new(),
        };
        antibody.signature = me.sign(&canonical(&antibody.body()));
        self.antibodies
            .insert(antibody.id.clone(), antibody.clone());
        self.push(ImmuneEvent::AntibodyDeveloped(antibody.clone()));
        Ok(antibody)
    }

    /// Package an antibody for export to a peer.
    pub fn export_vaccine(&self, me: &Identity, antibody_id: &str) -> Result<Vaccine, Error> {
        if me.public_key() != self.owner {
            return Err(Error::BadSignature("identity does not own registry".into()));
        }
        let antibody = self
            .antibodies
            .get(antibody_id)
            .ok_or_else(|| Error::BadAntibody(format!("unknown antibody: {antibody_id}")))?;
        let pathogen_signature = self
            .pathogens
            .get(&antibody.pathogen_id)
            .cloned()
            .unwrap_or_default();
        let mut vaccine = Vaccine {
            antibody: antibody.clone(),
            pathogen_signature,
            signature: String::new(),
        };
        vaccine.signature = me.sign(&canonical(&vaccine.envelope()));
        Ok(vaccine)
    }

    /// Adopt a vaccine from a peer. Verifies the envelope and antibody
    /// signatures, then chains the adoption — the organism's immune
    /// history records where its immunity came from.
    pub fn adopt(&mut self, vaccine: &Vaccine) -> Result<Antibody, Error> {
        vaccine.verify()?;
        if vaccine.antibody.issuer == self.owner {
            return Err(Error::BadAntibody(
                "cannot adopt own vaccine — already immune".into(),
            ));
        }
        if self.antibodies.contains_key(&vaccine.antibody.id) {
            return Ok(vaccine.antibody.clone());
        }
        // Register the pathogen signature locally if unknown.
        let local_id = sha256_hex(&canonical(&json!({
            "signature": vaccine.pathogen_signature,
            "adopted_from": vaccine.antibody.issuer,
        })));
        if !self
            .pathogens
            .values()
            .any(|s| *s == vaccine.pathogen_signature)
        {
            self.pathogens
                .insert(local_id.clone(), vaccine.pathogen_signature.clone());
        }
        let adopted_as = vaccine.antibody.id.clone();
        self.antibodies
            .insert(adopted_as.clone(), vaccine.antibody.clone());
        self.push(ImmuneEvent::VaccineAdopted {
            vaccine: vaccine.clone(),
            adopted_as,
        });
        Ok(vaccine.antibody.clone())
    }

    /// Is this input covered by any live antibody?
    pub fn is_immune(&self, input: &str) -> bool {
        self.antibodies.values().any(|a| a.covers(input))
    }

    /// Which antibodies cover this input (for reporting).
    pub fn matching(&self, input: &str) -> Vec<&Antibody> {
        self.antibodies
            .values()
            .filter(|a| a.covers(input))
            .collect()
    }

    /// Verify the registry chain and every antibody signature in it.
    pub fn verify(&self) -> Result<(), Error> {
        let mut prev = "0".repeat(64);
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 {
                return Err(Error::BadChain(format!("seq gap at {i}")));
            }
            if e.prev != prev {
                return Err(Error::BadChain(format!("prev mismatch at {i}")));
            }
            let hash = sha256_hex(&canonical(&json!({
                "seq": e.seq, "prev": e.prev, "event": e.event,
            })));
            if hash != e.hash {
                return Err(Error::BadChain(format!("hash mismatch at {i}")));
            }
            match &e.event {
                ImmuneEvent::AntibodyDeveloped(a) => a.verify()?,
                ImmuneEvent::VaccineAdopted { vaccine, .. } => vaccine.verify()?,
                _ => {}
            }
            prev = e.hash.clone();
        }
        Ok(())
    }

    /// Registry head — notarizable by `kola` witnesses.
    pub fn head(&self) -> (u64, String) {
        (self.entries.len() as u64, self.tip())
    }
}
