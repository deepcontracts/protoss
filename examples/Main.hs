module Main where

import Foreign.C.String
import Foreign.Ptr
import Data.Word

foreign import ccall protoss_cosmos_send_phrase :: CString -> Word64 -> CString -> CString -> CString -> CString -> Word64 -> IO CString

main = do
  phrase <- newCString "power forum anger wash problem innocent rifle emerge culture offer among palace essay maid junior spin wife meat six gasp two rough boat marble"
  addr_prefix <- newCString "cosmos"
  to_address <- newCString "cosmos..."
  amount <- newCString "100000"
  denom <- newCString "atom"
  let
    nonce = fromIntegral 1
    chain_id = fromIntegral 1
  
  protoss_cosmos_send_phrase phrase nonce addr_prefix to_address amount denom chain_id >>= peekCString >>= return
