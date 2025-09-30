import LeanMCES.EtM
import LeanMCES.Instances

open LeanMCES
open LeanMCES.EtM
open Instances

def A   := EtM_of myEM
def n0  : Bytes := Array.replicate 8 (UInt8.ofNat 7)
def msg : Bytes := #[1,2,3,4,5].toArray

-- Round-trip holds for our OTP demo ENC
example : A.dec () n0 (A.enc () n0 msg) = some msg := by rfl