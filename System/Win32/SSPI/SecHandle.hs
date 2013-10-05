module System.Win32.SSPI.SecHandle
  ( SecHandle ()
  ) where

import Control.Applicative
import Foreign.Safe

import Windows

-- typedef struct _SecHandle
-- {
--     ULONG_PTR dwLower ;
--     ULONG_PTR dwUpper ;
-- } SecHandle, * PSecHandle ;
data SecHandle = SecHandle
    { dwLower :: Ptr ULONG
    , dwUpper :: Ptr ULONG
    }

instance Storable SecHandle where
  sizeOf _ = 2 * sizeOf nullPtr
  alignment _ = alignment nullPtr
  peek ptr = SecHandle
    <$> peekElemOff (castPtr ptr) 0
    <*> peekElemOff (castPtr ptr) 1
  poke ptr cred = do
    pokeElemOff (castPtr ptr) 0 $ dwLower cred
    pokeElemOff (castPtr ptr) 1 $ dwUpper cred
