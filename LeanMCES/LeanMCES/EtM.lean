import Std
import LeanMCES.Keying

namespace LeanMCES
namespace EtM

open LeanMCES.Keying

abbrev Bytes := Array UInt8
abbrev Tag   := Array UInt8

-- MAC keyed by K, boolean verify
structure MAC (K : Type) where
  tag    : K → Bytes → Tag
  verify : K → Bytes → Tag → Bool

def EUF_CMA_secure {K} (_ : MAC K) : Prop := True

-- Symmetric encryption with explicit nonce type
structure Enc (K : Type) where
  Nonce : Type := Bytes
  enc   : K → Nonce → Bytes → Bytes
  dec   : K → Nonce → Bytes → Option Bytes

def INDCPA_secure {K} (_ : Enc K) : Prop := True

-- AEAD surface
structure AEAD (K : Type) where
  Nonce : Type
  enc   : K → Nonce → Bytes → (Bytes × Tag)
  dec   : K → Nonce → (Bytes × Tag) → Option Bytes

def INDCCA_secure {K} (_ : AEAD K) : Prop := True

-- Package Enc + MAC
structure EncAndMac (K : Type) where
  E   : Enc K
  mac : MAC K

-- Encrypt-then-MAC construction
def EtM_of {K} (EM : EncAndMac K) : AEAD K :=
  { Nonce := EM.E.Nonce
  , enc := fun k n m =>
      let c := EM.E.enc k n m
      let t := EM.mac.tag k c
      (c, t)
  , dec := fun k n (ct : Bytes × Tag) =>
      let (c, t) := ct
      if EM.mac.verify k c t then EM.E.dec k n c else none
  }

-- Composition theorem (assumed): with uniform keys + fresh nonces,
-- IND-CPA Enc and EUF-CMA MAC yield IND-CCA EtM.
axiom EtM_composition_bound {K}
  (KG : KeyGen K)
  (EM : EncAndMac K)
  (nonce_ok : NoncePolicy EM.E.Nonce)
  (hKey : Uniform KG)
  (hEnc : INDCPA_secure EM.E)
  (hMac : EUF_CMA_secure EM.mac) :
  INDCCA_secure (EtM_of EM)

end EtM
end LeanMCES