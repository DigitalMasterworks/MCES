import Std
import LeanMCES.Crypto

namespace LeanMCES
namespace Crypto

theorem xor_involutive (a b : Bool) : xor a (xor a b) = b := by
  cases a <;> cases b <;> decide

theorem xor_cancel (a b : Bool) : xor (xor a b) a = b := by
  cases a <;> cases b <;> decide

theorem xorZip_cancel_left :
  ∀ (ks xs : Msg), xs.length = ks.length → xorZip ks (xorZip ks xs) = xs
  | [], [], _ => rfl
  | [], _::_, h => by cases h
  | _::_, [], h => by cases h.symm
  | k::ks, x::xs, h => by
      have h' : xs.length = ks.length := by
        have : Nat.succ xs.length = Nat.succ ks.length := by simpa using h
        exact Nat.succ.inj this
      have ih := xorZip_cancel_left ks xs h'
      simp [xorZip, xor_involutive, ih]

theorem xorZip_cancel_right :
  ∀ (ks xs : Msg), ks.length = xs.length → xorZip (xorZip ks xs) ks = xs
  | [], [], _ => rfl
  | [], _::_, h => by cases h
  | _::_, [], h => by cases h.symm
  | k::ks, x::xs, h => by
      have h' : ks.length = xs.length := by
        have : Nat.succ ks.length = Nat.succ xs.length := by simpa using h
        exact Nat.succ.inj this
      have ih := xorZip_cancel_right ks xs h'
      simp [xorZip, xor_cancel, ih]

theorem enc_dec_inverse (ke : KeyEnc) (m : Msg) (hlen : m.length = ke.bits.length) :
  dec ke (enc ke m) = m := by
  have h := xorZip_cancel_left ke.bits m hlen
  simpa [enc, dec] using h

theorem dec_enc_inverse (ke : KeyEnc) (c : Msg) (hlen : c.length = ke.bits.length) :
  enc ke (dec ke c) = c := by
  have h := xorZip_cancel_left ke.bits c hlen
  simpa [enc, dec] using h

theorem enc_realizes (m c : Msg) (hlen : m.length = c.length) :
  ∃ k : KeyEnc, enc k m = c := by
  refine ⟨{ bits := xorZip m c }, ?_⟩
  have h := xorZip_cancel_right m c hlen
  simpa [enc] using h

theorem decrypt_correct
  (ke : KeyEnc) (km : KeyMac) (pt : Msg)
  (Hlen1 : ke.bits.length = pt.length)
  (_Hlen2 : ke.bits.length = km.bits.length) :
  decrypt ke km (enc ke pt) (mac km (enc ke pt)) = some pt := by
  unfold decrypt
  have h : dec ke (enc ke pt) = pt := by
    simpa [enc, dec] using xorZip_cancel_left ke.bits pt Hlen1.symm
  simp [mac, h]

theorem decrypt_authentic
  (ke : KeyEnc) (km : KeyMac) (c t pt : Msg)
  (_Hlen1 : ke.bits.length = pt.length)
  (_Hlen2 : ke.bits.length = km.bits.length)
  (Hlen3 : ke.bits.length = c.length)
  (Hdec : decrypt ke km c t = some pt) :
  c = enc ke pt ∧ t = mac km c := by
  unfold decrypt at Hdec
  by_cases htag : t = mac km c
  · have hpt : dec ke c = pt := by simpa [htag] using Hdec
    have henc : enc ke pt = c := by
      have : enc ke (dec ke c) = c := dec_enc_inverse ke c Hlen3.symm
      simpa [hpt] using this
    exact ⟨henc.symm, htag⟩
  · simp [htag] at Hdec

end Crypto
end LeanMCES