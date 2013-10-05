{-# LANGUAGE OverloadedStrings #-}

module System.Win32.SSPI.ContextHandle
  ( ContextHandle ()
  , asSecHandle
  , newContextHandle
  ) where

import Foreign.Safe hiding (addForeignPtrFinalizer)
import Foreign.Concurrent

import System.Win32.SSPI.SecHandle
import System.Win32.SSPI.SSPI

newtype ContextHandle = ContextHandle (ForeignPtr SecHandle)

-- | The Win32 AcceptSecurityContext procedure will allocate resources for a
-- new context that must be freed with DeleteSecurityContext. This allocation
-- will not occur if AcceptSecurityContext triggers an error condition while
-- executing. Memory for the original pointer to the handle must eventually
-- freed in any case.
--
-- newContextHandle creates a new foreign pointer holding a dynamically
-- allocated pointer. The supplied action is performed, and if no exceptions
-- are raised a second finalizer (in addition to the one for freeing the
-- pointer) will be registered.
newContextHandle :: SSPI -> (Ptr SecHandle -> IO b) -> IO (ContextHandle, b)
newContextHandle sspi act = do
    fpsecbuffer <- mallocForeignPtr
    ret <- withForeignPtr fpsecbuffer act
    addForeignPtrFinalizer fpsecbuffer $ do
        _ <- withForeignPtr fpsecbuffer $ c_DeleteSecurityContext sspi . castPtr
        return ()
    return (ContextHandle fpsecbuffer, ret)

-- |Access a `ContextHandle`'s underlying SecHandle. The pointer is only
-- guaranteed to be valid when used within the closure.
asSecHandle :: ContextHandle -> (Ptr SecHandle -> IO b) -> IO b
asSecHandle (ContextHandle fp) = withForeignPtr fp
