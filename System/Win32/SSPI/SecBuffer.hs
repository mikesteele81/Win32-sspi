module System.Win32.SSPI.SecBuffer
  ( SecBuffer (..)
  , SecBufferDesc (..)
  , sECBUFFER_TOKEN
  , sECBUFFER_VERSION
  , withEmptySecBuffer
  ) where

import Control.Applicative
import Foreign.Safe

import Windows

-- types
sECBUFFER_TOKEN :: ULONG
sECBUFFER_TOKEN = 0x00000002

sECBUFFER_VERSION :: ULONG
sECBUFFER_VERSION = 0 -- TODO: verify this

-- typedef struct _SecBufferDesc {
--   ULONG      ulVersion;
--   ULONG      cBuffers;
--   PSecBuffer pBuffers;
-- } SecBufferDesc, *PSecBufferDesc;

data SecBufferDesc = SecBufferDesc
    { ulVersion :: ULONG
    , cBuffers :: ULONG
    , pBuffers :: Ptr SecBuffer
    }

instance Storable SecBufferDesc where
  sizeOf _ = 2 * sizeOf (undefined :: ULONG) + sizeOf nullPtr
  alignment _ = alignment nullPtr
  peek ptr = SecBufferDesc
      <$> peek (castPtr ptr)
      <*> peekElemOff (castPtr ptr) 1
      <*> peek (plusPtr (castPtr ptr) (2 * sizeOf (0 :: ULONG)))
  poke ptr sb = do
      pokeElemOff (castPtr ptr) 0 $ ulVersion sb
      pokeElemOff (castPtr ptr) 1 $ cBuffers sb
      poke ppvBuffer $ pBuffers sb
    where
      ppvBuffer = castPtr ptr `plusPtr` (2 * sizeOf (0 :: ULONG))

-- | Direct marshalling of the C type.
-- typedef struct _SecBuffer {
--   ULONG cbBuffer;
--   ULONG BufferType;
--   PVOID pvBuffer;
-- } SecBuffer, *PSecBuffer;
data SecBuffer = SecBuffer
    { sbCount :: ULONG
    , sbType :: ULONG
    , sbBuffer :: Ptr ()
    } 

instance Storable SecBuffer where
  sizeOf _ = 2 * sizeOf (undefined :: ULONG) + sizeOf nullPtr
  alignment _ = alignment nullPtr
  peek ptr = SecBuffer
      <$> peek (castPtr ptr)
      <*> peekElemOff (castPtr ptr) 1
      <*> peek (plusPtr (castPtr ptr) (2 * sizeOf (0 :: ULONG)))
  poke ptr sb = do
      pokeElemOff (castPtr ptr) 0 $ sbCount sb
      pokeElemOff (castPtr ptr) 1 $ sbType sb
      poke ppvBuffer $ sbBuffer sb
    where
      ppvBuffer = castPtr ptr `plusPtr` (2 * sizeOf (0 :: ULONG))

sECBUFFER_EMPTY = 0x0

withEmptySecBuffer :: (Ptr SecBuffer -> IO a) -> IO a
withEmptySecBuffer act =
    with (SecBuffer 0 sECBUFFER_EMPTY nullPtr) act
