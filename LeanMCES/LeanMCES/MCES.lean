-- LeanMCES/MCES.lean
import Std
import LeanMCES.Crypto
import LeanMCES.CryptoProps
import LeanMCES.EtM

open LeanMCES.Crypto

-- Decrypting an encryption (with matching tag) yields the original plaintext.
theorem MCES_correct
  (ke : KeyEnc) (km : KeyMac) (pt : List Bool)
  (Hlen1 : ke.bits.length = pt.length)
  (Hlen2 : ke.bits.length = km.bits.length) :
  decrypt ke km (enc ke pt) (mac km (enc ke pt)) = some pt :=
decrypt_correct ke km pt Hlen1 Hlen2

-- If decryption returns a plaintext, the pair (c,t) is the real one.
theorem MCES_authentic
  (ke : KeyEnc) (km : KeyMac)
  (c t pt : List Bool)
  (Hlen1 : ke.bits.length = pt.length)
  (Hlen2 : ke.bits.length = km.bits.length)
  (Hlen3 : ke.bits.length = c.length)
  (Hdec : decrypt ke km c t = some pt) :
  c = enc ke pt ∧ t = mac km c :=
decrypt_authentic ke km c t pt Hlen1 Hlen2 Hlen3 Hdec

-- Each ciphertext of length n can be produced by some encryption key for a given plaintext.
theorem unique_key_for_cipher
  (pt : List Bool) (c : List Bool) (Hlen : pt.length = c.length) :
  ∃ (ke : KeyEnc), enc ke pt = c :=
enc_realizes pt c Hlen

-- Shannon-style secrecy in counting form (bijection-based)
theorem MCES_shannon_secrecy
  (pt1 pt2 : List Bool) (n : Nat)
  (Hlen1 : pt1.length = n) (Hlen2 : pt2.length = n)
  (c : List Bool) (HlenC : c.length = n) :
  (∃ ke1 : KeyEnc, enc ke1 pt1 = c) ↔
  (∃ ke2 : KeyEnc, enc ke2 pt2 = c) := by
  constructor
  · intro _H
    have hlen : pt2.length = c.length := by simpa [Hlen2] using HlenC.symm
    obtain ⟨ke, h⟩ := enc_realizes pt2 c hlen
    exact ⟨ke, h⟩
  · intro _H
    have hlen : pt1.length = c.length := by simpa [Hlen1] using HlenC.symm
    obtain ⟨ke, h⟩ := enc_realizes pt1 c hlen
    exact ⟨ke, h⟩