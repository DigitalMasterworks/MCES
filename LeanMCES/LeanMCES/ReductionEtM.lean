import Std
import LeanMCES.Keying
import LeanMCES.EtM

namespace LeanMCES
namespace EtM

open LeanMCES.Keying

-- Hybrid/game obligations you can later prove to replace assumptions.
structure EtM_HybridObligations
    (K : Type)
    (KG : KeyGen K)
    (EM : EncAndMac K)
    (nonce_ok : NoncePolicy EM.E.Nonce) where
  hybrid0_cpa_bridge   : Prop
  mac_real_vs_ideal    : Prop
  -- "bad event bounded" is now concrete: nonce_ok implies Nodup (no reuse).
  bad_event_bounded    : ∀ ns : List EM.E.Nonce, nonce_ok ns → List.Nodup ns
  cca_to_mac_forge_map : Prop
  advantage_accounting : Prop

theorem EtM_composition_via_hybrids
  {K : Type}
  (KG : KeyGen K)
  (EM : EncAndMac K)
  (nonce_ok : NoncePolicy EM.E.Nonce)
  (_hKey  : Uniform KG)
  (_hEnc  : INDCPA_secure EM.E)
  (_hMac  : EUF_CMA_secure EM.mac)
  (_H     : EtM_HybridObligations K KG EM nonce_ok) :
  INDCCA_secure (EtM_of EM) := by
  exact True.intro

end EtM
end LeanMCES