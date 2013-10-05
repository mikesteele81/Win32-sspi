module System.Win32.SSPI.LUID
  ( LUID ()
  ) where

import Control.Applicative
import Foreign.Safe

import System.Win32.Types

-- typedef struct _LUID {
--   DWORD LowPart;
--   LONG  HighPart;
-- } LUID, *PLUID;
data LUID = LUID !DWORD !LONG

instance Storable LUID where
  sizeOf _ = 4 + sizeOf (undefined :: LONG)
  -- long is at least as large as DWORD
  alignment _ = alignment (undefined :: LONG)
  peek ptr = LUID
    <$> peek (castPtr ptr)
    <*> peek (castPtr ptr `plusPtr` 4)
  poke ptr (LUID lowPart highPart) = do
    poke (castPtr ptr) lowPart
    poke (castPtr ptr `plusPtr` 4) highPart
