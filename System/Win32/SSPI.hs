{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module System.Win32.SSPI
  ( ContextExport ()
  , ContextHandle ()
  , CredHandle
  , LUID ()
  , SecPkgInfo ()
  , SSPI (..)
  , Token ()
  , acceptSecurityContext
  , acceptNewSecurityContext
  , acquireCredentialsHandle
  , enumerateSecurityPackages
  , exportSecurityContext
  , importSecurityContext
  , initSecurityInterface
  , queryCredentialsName
  ) where

import Control.Applicative
import Foreign hiding (addForeignPtrFinalizer)
import Foreign.C
import Foreign.Concurrent

import qualified Data.ByteString as SB
import qualified Data.ByteString.Internal as SBI
import Data.Text (Text)
import System.Win32.Time

import qualified System.Win32.Error as E
import System.Win32.SSPI.ContextExport
import System.Win32.SSPI.ContextHandle
import System.Win32.SSPI.LUID
import System.Win32.SSPI.SecBuffer
import System.Win32.SSPI.SecPkgInfo
import System.Win32.SSPI.SSPI
import Windows

-- sEC_E_OK                  = 0x00000000
-- sEC_E_INSUFFICIENT_MEMORY = 0x80090300
-- sEC_E_INTERNAL_ERROR      = 0x80090304
-- sEC_E_INVALID_HANDLE      = 0x80090301
-- sEC_E_NO_CREDENTIALS      = 0x8009030E
-- sEC_E_NOT_OWNER           = 0x80090306
-- sEC_E_SECPKG_NOT_FOUND    = 0x80090305
-- sEC_E_UNKNOWN_CREDENTIALS = 0x8009030D

-- flag values for ExportSecurityContext
sECPKG_CONTEXT_EXPORT_RESET_NEW  = 0x1
sECPKG_CONTEXT_EXPORT_DELETE_OLD = 0x2
sECPKG_CONTEXT_EXPORT_TO_KERNEL  = 0x4

-- attributes to query with QueryCredentialsAttributes
sECPKG_CRED_ATTR_NAMES = 1

sECPKG_ID_NONE = 0XFFFF

sECURITY_NETWORK_DREP :: ULONG
sECURITY_NETWORK_DREP = 0x00000000

newtype CredHandle = CredHandle (ForeignPtr C_CredHandle)

newtype Token = Token SB.ByteString

-- The underlying function takes an array of tagged buffers, but
-- for negotiate authentication there is only one type of buffer ever
-- needed.
withToken :: Token -> (Ptr SecBufferDesc -> IO b) -> IO b
withToken (Token token) act =
    withForeignPtr fptoken $ \ptokenBase -> do
        let ptoken = castPtr ptokenBase `plusPtr` off
        with (SecBuffer (fromIntegral len) sECBUFFER_TOKEN ptoken) $ \ pSecBuffer ->
            with (SecBufferDesc sECBUFFER_VERSION 1 pSecBuffer) $ \ pSecBufferDesc ->
            act pSecBufferDesc
  where
    (fptoken, off, len) = SBI.toForeignPtr token

newToken :: (Ptr SecBufferDesc -> IO b) -> IO (Token, b)
newToken act =
    with (SecBuffer 0 sECBUFFER_TOKEN nullPtr) $ \pbuffer ->
    with (SecBufferDesc sECBUFFER_VERSION 1 pbuffer) $ \pdesc -> do
    ret <- act pdesc
    SecBuffer count _ pbytes <- peek pbuffer
    bytes <- peekArray (fromIntegral count) $ castPtr pbytes
    return (Token $ SB.pack bytes, ret)

acceptSecurityContext :: SSPI -> CredHandle -> ContextHandle -> Token
    -> ULONG -> IO (ULONG, Token)
acceptSecurityContext sspi cred context input contextReq = do
    (contextAttr, _, output) <- acceptSecurityContext' sspi cred
        (Just context) input contextReq
    return (contextAttr, output)

acceptNewSecurityContext :: SSPI -> CredHandle -> Token -> ULONG
    -> IO (ULONG, ContextHandle, Token)
acceptNewSecurityContext sspi cred input contextReq =
    acceptSecurityContext' sspi cred Nothing input contextReq

acceptSecurityContext' :: SSPI -> CredHandle -> Maybe ContextHandle
    -> Token -> ULONG -> IO (ULONG, ContextHandle, Token)
acceptSecurityContext' sspi (CredHandle fpc_cred) mcontext input contextReq =
    withToken input $ \pInput ->
    withForeignPtr fpc_cred $ \pc_cred ->
    alloca $ \pcontextAttr -> do
    (output, (context, contextAttr)) <- newToken $ \poutput -> do
        -- On the first call (mcontext is Nothing) newContext will receive
        -- a context from the OS. On subsequent calls (mcontext is not
        -- Nothing) newContext should be identical to context
        context' <- case mcontext of
          Nothing -> do
            (context, _) <- newContextHandle sspi $ \pcontext -> do
                E.failUnlessSuccess "acceptNewSecurityContext"
                    $ c_AcceptSecurityContext sspi pc_cred nullPtr pInput
                        contextReq sECURITY_NETWORK_DREP pcontext poutput
                        pcontextAttr nullPtr
            return context
          Just context -> do
            asSecHandle context $ \pcontext -> do
                E.failUnlessSuccess "acceptNewSecurityContext"
                    $ c_AcceptSecurityContext sspi pc_cred pcontext pInput
                        contextReq sECURITY_NETWORK_DREP pcontext poutput
                        pcontextAttr nullPtr
            return context
        contextAttr <- peek pcontextAttr
        return (context', contextAttr)
    return (contextAttr, context, output)

acquireCredentialsHandle :: SSPI -> Text -> Text -> ULONG
    -> IO (CredHandle, FILETIME)
acquireCredentialsHandle sspi principal package credentialUse =
    useAsPtr0 principal $ \ pprincipal ->
    useAsPtr0 package $ \ ppackage ->
    alloca $ \ pfiletime -> do
    fpc_credHandle <- mallocForeignPtr
    withForeignPtr fpc_credHandle $ \ pc_credHandle -> do
        E.failUnlessSuccess "acquireCredentialsHandle"
            $ c_AcquireCredentialsHandle sspi pprincipal ppackage
                credentialUse nullPtr nullPtr nullPtr nullPtr pc_credHandle
                pfiletime
        -- Wait to add a finalizer until we know pc_credHandle has been
        -- acquired.
        addForeignPtrFinalizer fpc_credHandle
            $ finalizer pc_credHandle
    filetime <- peek pfiletime
    return (CredHandle fpc_credHandle, filetime)
  where
    finalizer ptr = do
        _ <- c_FreeCredentialsHandle sspi ptr
        return ()

enumerateSecurityPackages :: SSPI -> IO [SecPkgInfo]
enumerateSecurityPackages sspi =
    alloca $ \ pcPackages ->
    alloca $ \ ppPackageInfo -> do
    E.failUnlessSuccess "enumerateSecurityPackages"
        $ c_EnumerateSecurityPackages sspi pcPackages ppPackageInfo
    cPackages <- fromIntegral <$> peek pcPackages
    pPackageInfo <- peek ppPackageInfo
    packageInfos <- peekSecPkgInfoArray cPackages pPackageInfo
    -- If c_EnumerateSecurityPackages throws an error this buffer will not
    -- have been allocated.
    freeContextBuffer sspi $ castPtr pPackageInfo
    return packageInfos    

queryCredentialsName :: SSPI -> CredHandle -> IO Text
queryCredentialsName sspi (CredHandle fpcred) =
    withForeignPtr fpcred $ \ pcred ->
    alloca $ \ppText -> do
    let test = ppText :: Ptr (Ptr CWchar)
    E.failUnlessSuccess "queryCredentialsName"
        $ c_QueryCredentialsAttributes sspi pcred sECPKG_CRED_ATTR_NAMES
            (castPtr ppText :: Ptr ())
    pText <- peek ppText
    fromPtr0 pText
