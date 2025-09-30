/-
  LeanMCES.lean — project entrypoint
-/
import LeanMCES.Crypto
import LeanMCES.CryptoProps
import LeanMCES.EtM
import LeanMCES.MCES
import LeanMCES.Instances

def main : IO Unit := do
  IO.println "LeanMCES build succeeded."