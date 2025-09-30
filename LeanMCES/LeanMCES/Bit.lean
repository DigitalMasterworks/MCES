import Std

namespace LeanMCES.Bit
abbrev Msg := List Bool
structure KeyEnc where bits : Msg deriving Repr, DecidableEq
structure KeyMac where bits : Msg deriving Repr, DecidableEq
end LeanMCES.Bit