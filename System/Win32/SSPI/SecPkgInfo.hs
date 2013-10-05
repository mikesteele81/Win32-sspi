module System.Win32.SSPI.SecPkgInfo
  ( SecPkgInfo ()
  , peekSecPkgInfo
  , peekSecPkgInfoArray
  , withSecPkgInfo
  ) where

import Control.Applicative
import Foreign.Safe

import Data.Text (Text)
import System.Win32.Types

import Windows

-- typedef struct _SecPkgInfo {
--   ULONG    fCapabilities;
--   USHORT   wVersion;
--   USHORT   wRPCID;
--   ULONG    cbMaxToken;
--   SEC_CHAR *Name;
--   SEC_CHAR *Comment;
-- } SecPkgInfo, *PSecPkgInfo;
data SecPkgInfo = SecPkgInfo
    { spiCapabilities :: !ULONG
    , spiVersion :: !USHORT
    , spiRPCID :: !USHORT
    , spiMaxToken :: !ULONG
    , spiName :: !Text
    , spiComment :: !Text
    } deriving (Show)

peekSecPkgInfo :: Ptr SecPkgInfo -> IO SecPkgInfo
peekSecPkgInfo ptr =
    SecPkgInfo <$> peek pcap <*> peek pversion <*> peek prpcid <*> peek pmax
               <*> (fromPtr0 =<< peek pname) <*> (fromPtr0 =<< peek pcomment)
 where
   pcap     = castPtr ptr
   pversion = castPtr . plusPtr ptr $ sulong
   prpcid   = castPtr . plusPtr ptr $ sulong + sushort
   pmax     = castPtr . plusPtr ptr $ sulong + 2 * sushort
   pname    = castPtr . plusPtr ptr $ 2 * (sulong + sushort)
   pcomment = castPtr . plusPtr ptr $ sptr + 2 * (sulong + sushort)

withSecPkgInfo :: SecPkgInfo -> (Ptr SecPkgInfo -> IO b) -> IO b
withSecPkgInfo spi act =
    useAsPtr0 (spiName spi) $ \pname ->
    useAsPtr0 (spiComment spi) $ \pcomment ->
    allocaBytesAligned size align $ \ptr -> do
    poke (castPtr ptr) $ spiCapabilities spi
    poke (castPtr ptr `plusPtr` sulong) $ spiVersion spi
    poke (castPtr ptr `plusPtr` (sulong + sushort)) $ spiRPCID spi
    poke (castPtr ptr `plusPtr` (sulong + 2 * sushort)) $ spiMaxToken spi
    poke (castPtr ptr `plusPtr` (2 * (sulong + sushort))) $ pname
    poke (castPtr ptr `plusPtr` (2 * (sulong + sushort) + sptr)) $ pcomment
    act ptr
  where
    align = alignment nullPtr

peekSecPkgInfoArray :: Int -> Ptr SecPkgInfo -> IO [SecPkgInfo]
peekSecPkgInfoArray count ptr
    | count < 0 = return []
    | otherwise = f (count - 1) []
  where
    f 0 acc = do
        e <- peekSecPkgInfo ptr
        return (e:acc)
    f n acc = do
        e <- peekSecPkgInfo (ptr `plusPtr` (n * size))
        f (n - 1) (e:acc)

size :: Int
size = 2 * (sulong + sushort + sptr)

-- convenience to support both 32-bit and 64-bit builds
sushort, sulong, sptr :: Int
sushort = sizeOf (undefined :: USHORT)
{-# INLINE sushort #-}
sulong = sizeOf (undefined :: ULONG)
{-# INLINE sulong #-}
sptr = sizeOf nullPtr
{-# INLINE sptr #-}
