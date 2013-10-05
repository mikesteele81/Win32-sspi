{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module System.Win32.SSPI.SSPI
  ( C_CredHandle
  , SECURITY_FUNCTION_TABLE
  , SSPI (..)
  , freeContextBuffer
  , initSecurityInterface
  ) where

import Control.Applicative
import Foreign.Safe
import Foreign.C

import System.Win32.SSPI.SecHandle
import System.Win32.SSPI.LUID
import System.Win32.SSPI.SecBuffer
import System.Win32.SSPI.SecPkgInfo
import System.Win32.SSPI.SECURITY_STRING
import System.Win32.Time
import System.Win32.Types
import qualified System.Win32.Error as E
import Windows

-- defined in ntdef.h
type SECURITY_STATUS = CULong

-- typedef struct _SecHandle {
--   ULONG_PTR       dwLower;
--   ULONG_PTR       dwUpper;
-- } SecHandle, * PSecHandle;
data C_CredHandle = C_CredHandle
    { dwLower :: Ptr ULONG
    , dwUpper :: Ptr ULONG
    }

instance Storable C_CredHandle where
  sizeOf _ = 2 * sizeOf nullPtr
  alignment _ = alignment nullPtr
  peek ptr = C_CredHandle
    <$> peekElemOff (castPtr ptr) 0
    <*> peekElemOff (castPtr ptr) 1
  poke ptr cred = do
    pokeElemOff (castPtr ptr) 0 $ dwLower cred
    pokeElemOff (castPtr ptr) 1 $ dwUpper cred

data SECURITY_FUNCTION_TABLE

type ACCEPT_SECURITY_CONTEXT = Ptr C_CredHandle
    -> Ptr SecHandle -> Ptr SecBufferDesc -> ULONG -> ULONG
    -> Ptr SecHandle -> Ptr SecBufferDesc -> Ptr ULONG
    -> Ptr FILETIME -> IO SECURITY_STATUS

type ACQUIRE_CREDENTIALS_HANDLE = LPTSTR -> LPTSTR -> ULONG -> Ptr LUID
    -> Ptr () -> Ptr () -> Ptr () -> Ptr C_CredHandle -> Ptr FILETIME
    -> IO SECURITY_STATUS

type DELETE_SECURITY_CONTEXT = Ptr SecHandle
    -> IO SECURITY_STATUS

type ENUMERATE_SECURITY_PACKAGES = Ptr ULONG -> Ptr (Ptr SecPkgInfo)
    -> IO SECURITY_STATUS

-- SECURITY_STATUS SEC_Entry ExportSecurityContext(
--   _In_       PCtxtHandle phContext,
--   _In_       Ulong fFlags,
--   _Out_      PSecBuffer pPackedContext,
--   _Out_opt_  HANDLE *pToken
-- );
type EXPORT_SECURITY_CONTEXT = Ptr SecHandle -> ULONG
    -> Ptr SecBuffer -> Ptr HANDLE -> IO SECURITY_STATUS

type FREE_CONTEXT_BUFFER = Ptr () -> IO SECURITY_STATUS

type FREE_CREDENTIALS_HANDLE = Ptr C_CredHandle -> IO SECURITY_STATUS

type QUERY_CONTEXT_ATTRIBUTES = Ptr SecHandle -> ULONG
    -> Ptr () -> IO SECURITY_STATUS

type QUERY_CREDENTIALS_ATTRIBUTES = Ptr C_CredHandle -> ULONG -> Ptr ()
    -> IO SECURITY_STATUS

-- SECURITY_STATUS SEC_Entry ImportSecurityContext(
--   _In_      PSECURITY_STRING *pszPackage,
--   _In_      PSecBuffer pPackedContext,
--   _In_opt_  HANDLE pToken,
--   _Out_     PCtxtHandle phContext
-- );
type IMPORT_SECURITY_CONTEXT = Ptr SECURITY_STRING -> Ptr SecBuffer
    -> HANDLE -> Ptr SecHandle -> IO SECURITY_STATUS

data SSPI = SSPI
    { c_AcceptSecurityContext :: ACCEPT_SECURITY_CONTEXT
    , c_AcquireCredentialsHandle :: ACQUIRE_CREDENTIALS_HANDLE
    , c_DeleteSecurityContext :: DELETE_SECURITY_CONTEXT
    , c_EnumerateSecurityPackages :: ENUMERATE_SECURITY_PACKAGES
    , c_ExportSecurityContext :: EXPORT_SECURITY_CONTEXT
    , c_FreeContextBuffer :: FREE_CONTEXT_BUFFER
    , c_FreeCredentialsHandle :: FREE_CREDENTIALS_HANDLE
    , c_ImportSecurityContext :: IMPORT_SECURITY_CONTEXT
    , c_QueryContextAttributes :: QUERY_CONTEXT_ATTRIBUTES
    , c_QueryCredentialsAttributes :: QUERY_CREDENTIALS_ATTRIBUTES
    }

-- |blah
-- TechNet Errata:
-- The documentation claims that there is a "Reserved1" member
-- between EnumerateSecurityPackages and QueryCredentialsAttributes.
-- This is incorrect. All offsets after EnumerateSecurityPackages are
-- reduced by one as a result.
initSecurityInterface :: IO SSPI
initSecurityInterface = do
    psfp <- E.failIfNull "initSecurityInterface" c_InitSecurityInterface
    version <- peek (castPtr psfp :: Ptr ULONG)
    print version
    -- `psfp` is a structure containing mostly function pointers. The
    -- `fpOffset` function takes an offset from the first `USHORT` member
    -- in units of pointers.
    let fpOffset :: Int -> IO (FunPtr a)
        fpOffset off = castPtrToFunPtr <$> peek pptr
          where pptr = castPtr . plusPtr psfp
                       $ sizeOf (undefined :: ULONG) + off * sizeOf nullPtr
    SSPI
      <$> (mkAcceptSecurityContext <$> fpOffset 6)
      <*> (mkAcquireCredentialsHandle <$> fpOffset 2)
      <*> (mkDeleteSecurityContext <$> fpOffset 8)
      <*> (mkEnumerateSecurityPackages <$> fpOffset 0)
      <*> (mkExportSecurityContext <$> fpOffset 19)
      <*> (mkFreeContextBuffer <$> fpOffset 15)
      <*> (mkFreeCredentialsHandle <$> fpOffset 4)
      <*> (mkImportSecurityContext <$> fpOffset 20)
      <*> (mkQueryContextAttributes <$> fpOffset 10)
      <*> (mkQueryCredentialsAttributes <$> fpOffset 1)

-- restrict to only exporting the context to a buffer
freeContextBuffer :: SSPI -> Ptr () -> IO ()
freeContextBuffer sspi ptr = E.failUnlessSuccess "freeContextBuffer"
    $ c_FreeContextBuffer sspi ptr

foreign import WINDOWS_CCONV "dynamic"
    mkAcceptSecurityContext :: FunPtr ACCEPT_SECURITY_CONTEXT
        -> ACCEPT_SECURITY_CONTEXT

foreign import WINDOWS_CCONV "dynamic"
    mkAcquireCredentialsHandle :: FunPtr ACQUIRE_CREDENTIALS_HANDLE
        -> ACQUIRE_CREDENTIALS_HANDLE

foreign import WINDOWS_CCONV "dynamic"
    mkDeleteSecurityContext :: FunPtr DELETE_SECURITY_CONTEXT
        -> DELETE_SECURITY_CONTEXT

foreign import WINDOWS_CCONV "dynamic"
    mkEnumerateSecurityPackages :: FunPtr ENUMERATE_SECURITY_PACKAGES
        -> ENUMERATE_SECURITY_PACKAGES

foreign import WINDOWS_CCONV "dynamic"
    mkExportSecurityContext :: FunPtr EXPORT_SECURITY_CONTEXT
        -> EXPORT_SECURITY_CONTEXT

-- | Used to free ContextBuffer and SecPkgInfo arrays.
foreign import WINDOWS_CCONV "dynamic"
    mkFreeContextBuffer :: FunPtr FREE_CONTEXT_BUFFER -> FREE_CONTEXT_BUFFER

foreign import WINDOWS_CCONV "dynamic"
    mkFreeCredentialsHandle :: FunPtr FREE_CREDENTIALS_HANDLE
        -> FREE_CREDENTIALS_HANDLE

foreign import WINDOWS_CCONV "dynamic"
    mkImportSecurityContext :: FunPtr IMPORT_SECURITY_CONTEXT
        -> IMPORT_SECURITY_CONTEXT

foreign import WINDOWS_CCONV "Security.h InitSecurityInterfaceW"
    c_InitSecurityInterface :: IO (Ptr SECURITY_FUNCTION_TABLE)

foreign import WINDOWS_CCONV "dynamic"
    mkQueryContextAttributes :: FunPtr QUERY_CONTEXT_ATTRIBUTES
        -> QUERY_CONTEXT_ATTRIBUTES

foreign import WINDOWS_CCONV "dynamic"
    mkQueryCredentialsAttributes :: FunPtr QUERY_CREDENTIALS_ATTRIBUTES
        -> QUERY_CREDENTIALS_ATTRIBUTES
