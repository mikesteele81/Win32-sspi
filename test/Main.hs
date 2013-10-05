{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Text as T
import System.Win32.SSPI

-- put your qualified name here. It should be of the form
-- <computer>\<user>
credname :: T.Text
credname = undefined

main :: IO ()
main = do
    sspi <- initSecurityInterface
    packages <- enumerateSecurityPackages sspi
    mapM_ print packages
    (handle, _) <- acquireCredentialsHandle sspi credname "Negotiate" 0x00000002
    name <- queryCredentialsName sspi handle
    print $ "account name: " ++ show name
    print "hello"
