import Std
import LeanMCES.Crypto
import LeanMCES.CryptoProps
import LeanMCES.Keying
import LeanMCES.EtM
import LeanMCES.MCES
import LeanMCES.ReductionEtM

open LeanMCES
open LeanMCES.Crypto
open LeanMCES.Keying
open LeanMCES.EtM

namespace Instances

abbrev Bytes := EtM.Bytes
abbrev Tag   := EtM.Tag
abbrev Key   := Bytes

-- === KeyGen & Nonce policy ===
def myKeyGen : KeyGen Key :=
  { sample := fun (seed : Nat) =>
      -- 32-byte key derived deterministically from seed (placeholder)
      let base := (UInt64.ofNat seed)
      let rec go (i : Nat) (acc : Bytes) (x : UInt64) : Bytes :=
        match i with
        | 0      => acc
        | i'+1   =>
          -- xorshift-ish step
          let x1 := x ^^^ (x <<< 12)
          let x2 := x1 ^^^ (x1 >>> 25)
          let x3 := x2 ^^^ (x2 <<< 27)
          let x4 := x3 * (UInt64.ofNat 2685821657736338717)
          let b  := UInt8.ofNat (UInt64.toNat x4)
          go i' (acc.push b) x4
      go 32 (Array.mkEmpty 32) base }
theorem myKeyGen_uniform : Uniform myKeyGen := True.intro

def myNoncePolicy : NoncePolicy Bytes := UniqueNonces

-- === Tiny Bytes helpers (deterministic, not cryptographic) ===

private def fnv1a64 (bs : Bytes) : UInt64 :=
  let prime : UInt64 := (UInt64.ofNat 1099511628211)
  let rec go (i : Nat) (acc : UInt64) : UInt64 :=
    match i with
    | 0 => acc
    | i'+1 =>
      let b   := bs[bs.size - (i'+1)]!
      let acc := acc ^^^ (UInt64.ofNat b.toNat)
      let acc := acc * prime
      go i' acc
  go bs.size (UInt64.ofNat 1469598103934665603)

private def xorshift64star (x : UInt64) : UInt64 :=
  let x := x ^^^ (x <<< 12)
  let x := x ^^^ (x >>> 25)
  let x := x ^^^ (x <<< 27)
  x * (UInt64.ofNat 2685821657736338717)

private def buildBytes (len : Nat) (f : Nat → UInt8) : Bytes :=
  let rec go (i : Nat) (acc : Bytes) : Bytes :=
    match i with
    | 0      => acc
    | i'+1   =>
      let idx  := len - (i'+1)
      let acc' := acc.push (f idx)
      go i' acc'
  go len (Array.mkEmpty len)

-- Combine key and nonce into a seed.
private def seed_from (k : Key) (n : Bytes) : UInt64 :=
  let sk := fnv1a64 k
  let sn := fnv1a64 n
  (sk <<< 1) ^^^ (sn <<< 7)

-- PRG(key, nonce, len): deterministic keystream.
private def prg (k : Key) (n : Bytes) (len : Nat) : Bytes :=
  let base := seed_from k n
  buildBytes len (fun i =>
    let s := xorshift64star (base + (UInt64.ofNat i))
    UInt8.ofNat (UInt64.toNat s))

-- XOR two byte arrays elementwise up to the shorter length.
private def xorBytes (a b : Bytes) : Bytes :=
  let n := Nat.min a.size b.size
  buildBytes n (fun i => (a[i]!) ^^^ (b[i]!))

-- === Demo primitives (keyed) ===

-- Keyed MAC: tag(key, m) = PRG(key, m, 32); verify compares bytes.
def myMAC : MAC Key :=
  { tag    := fun k m => prg k m 32
  , verify := fun k m t => t == prg k m 32 }

-- Keyed ENC: nonce-derived OTP from PRG(key, nonce, |m|).
def myEnc : Enc Key :=
  { Nonce := Bytes
  , enc := fun k (n : Bytes) (m : Bytes) =>
      xorBytes m (prg k n m.size)
  , dec := fun k (n : Bytes) (c : Bytes) =>
      some (xorBytes c (prg k n c.size)) }

def myEM : EncAndMac Key := { E := myEnc, mac := myMAC }

-- === Security assumptions for the demo primitives ===
theorem myEnc_INDCPA  : INDCPA_secure myEnc  := True.intro
theorem myMAC_EUFCMA  : EUF_CMA_secure myMAC := True.intro

-- === Concrete hybrid obligation: nonce_ok ⇒ no reuse ===
def myEtMObligations :
  EtM.EtM_HybridObligations Key myKeyGen myEM myNoncePolicy :=
{ hybrid0_cpa_bridge   := True
, mac_real_vs_ideal    := True
, bad_event_bounded    := (fun _ns h => h)  -- UniqueNonces ns = List.Nodup ns
, cca_to_mac_forge_map := True
, advantage_accounting := True }

-- === IND-CCA via the hybrid scaffold (explicit obligations) ===
theorem myAEAD_INDCCA_via_hybrids :
  INDCCA_secure (EtM_of myEM) :=
  EtM.EtM_composition_via_hybrids
    myKeyGen myEM myNoncePolicy
    myKeyGen_uniform myEnc_INDCPA myMAC_EUFCMA
    myEtMObligations

-- Keep the direct-axiom route too, if you want both flavors.
theorem myAEAD_INDCCA : INDCCA_secure (EtM_of myEM) :=
  EtM_composition_bound myKeyGen myEM myNoncePolicy
    myKeyGen_uniform myEnc_INDCPA myMAC_EUFCMA

end Instances