{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}

module System.Win32.Error
  ( ErrCode (..)
  , Win32Exception (..)
  , ToErrCode (..)
  , errorWin
  , failIf
  , failIf_
  , failIfNull
  , failIfFalse_
  , failUnlessSuccess
  , failWith
  ) where

import Control.Applicative
import Control.Exception
import Control.Monad
import Data.Char
import Data.Typeable
import Data.Word
import Foreign.C.Types
import Foreign.Safe
import Numeric

import Data.Text (Text)
import qualified Data.Text as T
import System.Win32.Types (DWORD)
import qualified System.Win32 as Win32

data ErrCode
    = ErrorSuccess
    | InsufficientMemory
    | InvalidHandle
    | InternalError
    | NoCredentials
    | NotOwner
    | SecPkgNotFound
    | UnknownCredentials
    | ErrorOther !DWORD
    deriving Show

-- Some MSDN functions return a DWORD to be used as an error code while others
-- return a ULONG. In both cases the error code will fit into 32-bits.
class ToErrCode a where
  toErrCode :: a -> ErrCode

instance ToErrCode Word32 where
  toErrCode 0x00000000 = ErrorSuccess
  toErrCode 0x80090300 = InsufficientMemory
  toErrCode 0x80090301 = InvalidHandle
  toErrCode 0x80090304 = InternalError
  toErrCode 0x8009030E = NoCredentials
  toErrCode 0x80090306 = NotOwner
  toErrCode 0x80090305 = SecPkgNotFound
  toErrCode 0x8009030D = UnknownCredentials
  toErrCode d = ErrorOther d

instance ToErrCode CULong where
  toErrCode = (toErrCode :: Word32 -> ErrCode) . fromIntegral

data Win32Exception = Win32Exception
    { function :: !Text
    , errCode :: !ErrCode
    , systemMessage :: !Text
    } deriving (Typeable, Show)

instance Exception Win32Exception

failIfFalse_ :: Text -> IO Bool -> IO ()
failIfFalse_ = failIf_ not

failIf :: (a -> Bool) -> Text -> IO a -> IO a
failIf p wh act = do
    v <- act
    when (p v) $ errorWin wh
    return v

failIf_ :: (a -> Bool) -> Text -> IO a -> IO ()
failIf_ p wh act = failIf p wh act >> return ()

failIfNull :: Text -> IO (Ptr a) -> IO (Ptr a)
failIfNull = failIf (== nullPtr)

errorWin :: Text -> IO a
errorWin fn_name = do
    err_code <- Win32.getLastError
    failWith fn_name err_code

failWith :: Text -> DWORD -> IO a
failWith fn_name err_code = do
    c_msg <- Win32.getErrorMessage err_code
    msg <- if c_msg == Win32.nullPtr
           then return $ "Error 0x" `T.append` T.pack (Numeric.showHex err_code "")
           else do
               msg <- T.pack <$> Win32.peekTString c_msg
               -- We ignore failure of freeing c_msg, given we're already failing
               _ <- Win32.localFree c_msg
               return msg
    -- drop trailing \n
    let msg' = T.reverse . T.dropWhile isSpace . T.reverse $ msg
    throw $ Win32Exception fn_name (toErrCode err_code) msg'

failUnlessSuccess :: (ToErrCode e) => Text -> IO e -> IO ()
failUnlessSuccess fn_name act = do
    failIf_ (predicate . toErrCode) fn_name act
  where
    predicate ErrorSuccess = False
    predicate _ = True
