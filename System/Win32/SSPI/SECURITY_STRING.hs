module System.Win32.SSPI.SECURITY_STRING where

import Control.Applicative
import Foreign.C
import Foreign.Safe

import Data.Text (Text)
import qualified Data.Text as T
import System.Win32.Types

import Windows

-- | A few functions use this structure instead of simple null-terminated
--   strings
--   Microsoft's documentation is inconsistent, and I think the main MSDN
--   documentation page contains errors. It claims that buffer is of type
--   USHORT, but headers indicate it is an unsigned short *. 
data SECURITY_STRING = SECURITY_STRING
    { -- | Specifies the length, in bytes, of the string pointed to by the
      --   Buffer member, not including the terminating NULL character, if any.
      --   
      --   Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003,
      --   and Windows XP:  When the Length structure member is zero and the
      --   MaximumLength structure member is 1, the Buffer structure member
      --   can be an empty string or contain solely a null character. This
      --   behavior changed beginning with Windows Server 2008 R2 and Windows
      --   7 with SP1.
      ssLength :: !USHORT
      -- | Specifies the total size, in bytes, of memory allocated for
      -- Buffer. Up to MaximumLength bytes may be written into the buffer
      -- without trampling memory.
    , ssMaximumLength :: !USHORT
      -- | Pointer to a wide-character string. Note that the strings returned
      -- by the various LSA functions might not be null-terminated.
    , ssBuffer :: !(Ptr CWchar)
    }

instance Storable SECURITY_STRING where
  sizeOf _ = 2 * sizeOf (undefined :: USHORT) + sizeOf nullPtr
  alignment _ = alignment nullPtr
  peek ptr = SECURITY_STRING
      <$> peekElemOff (castPtr ptr) 0
      <*> peekElemOff (castPtr ptr) 1
      <*> peek (plusPtr (castPtr ptr) (2 * sizeOf (undefined :: USHORT)))
  poke ptr ss = do
      pokeElemOff (castPtr ptr) 0 $ ssLength ss
      pokeElemOff (castPtr ptr) 1 $ ssMaximumLength ss
      poke (plusPtr (castPtr ptr) (2 * sizeOf (undefined :: USHORT))) $ ssBuffer ss

withSECURITY_STRING :: Text -> (Ptr SECURITY_STRING -> IO r) -> IO r
withSECURITY_STRING txt act =
    useAsPtr0 txt $ \ ptxt ->
    with (SECURITY_STRING bytes (bytes + 2) ptxt) $ \ pSs ->
    act pSs
  where
    -- bytes not including a null character.
    bytes = fromIntegral . (* 2) . T.length $ txt

