import Std

namespace LeanMCES
namespace Crypto

abbrev Msg := List Bool

structure KeyEnc where
  bits : Msg
deriving Repr, DecidableEq

structure KeyMac where
  bits : Msg
deriving Repr, DecidableEq

def xor (b1 b2 : Bool) : Bool :=
  match b1, b2 with
  | true,  true  => false
  | false, false => false
  | _,     _     => true

def xorZip (ks xs : Msg) : Msg :=
  match ks, xs with
  | k :: ks', x :: xs' => xor k x :: xorZip ks' xs'
  | _, _               => []

def enc (ke : KeyEnc) (m : Msg) : Msg := xorZip ke.bits m
def dec (ke : KeyEnc) (c : Msg) : Msg := xorZip ke.bits c
def mac (km : KeyMac) (c : Msg) : Msg := km.bits ++ c

def decrypt (ke : KeyEnc) (km : KeyMac) (c : Msg) (t : Msg) : Option Msg :=
  if t = mac km c then some (dec ke c) else none

end Crypto
end LeanMCES