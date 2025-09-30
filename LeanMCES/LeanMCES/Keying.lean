import Std

namespace LeanMCES
namespace Keying

-- Abstract key generator: given any seed (Nat), produce a key.
structure KeyGen (K : Type) where
  sample : Nat → K

-- "Uniform" is an assumption about the distribution of KeyGen.
-- We keep it abstract as a Prop so you can cite a real RNG/PRF later.
def Uniform {K : Type} (_ : KeyGen K) : Prop := True

-- A nonce policy is just a predicate over sequences of nonces.
def NoncePolicy (N : Type) := List N → Prop

-- The standard "freshness" policy: all nonces are pairwise distinct.
def UniqueNonces {N : Type} : NoncePolicy N := fun ns => List.Nodup ns

end Keying
end LeanMCES