{-# LANGUAGE OverloadedStrings #-}

module System.Win32.SSPI.ContextExport
  ( ContextExport ()
  , importSecurityContext
  , exportSecurityContext
  , withContextExport
  ) where

import Foreign.Safe

import Control.Applicative
import Data.ByteString as SB
import Data.ByteString.Unsafe as SB
import Data.Text

import System.Win32.Error as E
import System.Win32.SSPI.ContextHandle
import System.Win32.SSPI.SecBuffer
import System.Win32.SSPI.SECURITY_STRING
import System.Win32.SSPI.SSPI
import Windows

-- | Microsoft does not document what the BufferType field will be set
--   to, so we store it along with the bytes.
data ContextExport = ContextExport !ULONG !SB.ByteString

importSecurityContext :: SSPI -> Text -> ContextExport
    -> IO ContextHandle
importSecurityContext sspi package packagedContext =
    withSECURITY_STRING package $ \ppackage ->
    withContextExport packagedContext $ \ ppackedContext -> do
        (context, _) <- newContextHandle sspi $ \pcontextHandle -> do
            E.failUnlessSuccess "importSecurityContext"
                $ c_ImportSecurityContext sspi ppackage ppackedContext
                    nullPtr pcontextHandle
        return context

exportSecurityContext :: SSPI -> ContextHandle -> IO ContextExport
exportSecurityContext sspi context =
    asSecHandle context $ \ptr_context ->
    alloca $ \ psec_buffer -> do
    E.failUnlessSuccess "exportSecurityContext"
        $ c_ExportSecurityContext sspi ptr_context 0 psec_buffer nullPtr
    ret <- peek psec_buffer >>= fromSecBuffer
    freeContextBuffer sspi $ castPtr psec_buffer
    return ret

fromSecBuffer :: SecBuffer -> IO ContextExport
fromSecBuffer (SecBuffer num ty buf) =
    ContextExport ty . SB.pack <$> peekArray (fromIntegral num) (castPtr buf)

withContextExport :: ContextExport -> (Ptr SecBuffer -> IO a) -> IO a
withContextExport (ContextExport ty bytes) act =
    SB.unsafeUseAsCStringLen bytes $ \ (pBytes, len) ->
    with (SecBuffer (fromIntegral len) ty (castPtr pBytes)) act
