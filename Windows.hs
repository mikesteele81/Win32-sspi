{-# LANGUAGE OverloadedStrings #-}

module Windows where

import Data.Char
import Foreign
import Foreign.C

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Foreign as T

-- missing from Win32 package
type ULONG = CULong

-- | useAsPtr returns a length and byte buffer, but all the win32 functions
-- rely on null termination.
useAsPtr0 :: Text -> (Ptr CWchar -> IO a) -> IO a
useAsPtr0 t f = T.useAsPtr (T.snoc t (chr 0x0)) $ \ str _ -> f  (castPtr str)

-- This traverses the string twice. Is there a faster way?
fromPtr0 :: Ptr CWchar -> IO Text
fromPtr0 ptr = do
    -- length in 16-bit words.
    len <- lengthArray0 0x0000 ptr'
    -- no loss of precision here. I16 is a newtype wrapper around Int.
    T.fromPtr ptr' $ fromIntegral len
  where
    ptr' :: Ptr Word16
    ptr' = castPtr ptr
