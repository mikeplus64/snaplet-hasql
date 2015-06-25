{-# LANGUAGE ExplicitNamespaces     #-}
{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE OverloadedStrings      #-}
module Snap.Snaplet.Hasql
  ( HasPool(..)
  , initHasql
  , initHasql'
  , session
  , session'
  , module H
  ) where
import           Control.Lens
import           Control.Monad.Reader
import qualified Data.Configurator    as C
import           Hasql                as H hiding (session)
import qualified Hasql
import           Hasql.Backend        hiding (Tx)
import           Paths_snaplet_hasql
import           Snap

class (Show (CxError db), Show (TxError db), CxTx db, Cx db) =>
      HasPool s db | s -> db where
  poolLens :: Lens' s (Pool db)

instance (Cx db, CxTx db, Show (CxError db), Show (TxError db)) =>
         HasPool (Pool db) db where
  poolLens = id

initHasql
  :: HasPool c db
  => CxSettings db
  -> SnapletInit c (Pool db)
initHasql cx =
  makeSnaplet "hasql" "" (Just getDataDir) $ do
    poolSettings <- getPoolSettings =<< getSnapletUserConfig
    pool         <- liftIO (acquirePool cx poolSettings)
    onUnload (releasePool pool)
    return pool

getPoolSettings cfg = (\(Just a) -> a) <$> liftIO (poolSettings
  <$> C.require cfg "max-connections"
  <*> C.require cfg "connection-timeout")

initHasql'
  :: HasPool c db
  => CxSettings db
  -> Maybe PoolSettings
  -> SnapletInit c (Pool db)
initHasql' cx Nothing  = error "initHasql: Incorrect poolSettings parameters."
initHasql' cx (Just p) =
  makeSnaplet "hasql" "" (Just getDataDir) $ do
    pool <- liftIO (acquirePool cx p)
    onUnload (releasePool pool)
    return pool

{-# INLINE session #-}
-- | Wrapper around 'session' that calls 'fail' on failure.
session :: HasPool v db => Session db IO r -> Handler b v r
session f = do
  db <- view poolLens
  r  <- liftIO (Hasql.session db f)
  case r of
    Right a -> return a
    Left er -> fail (show er)

{-# INLINE session' #-}
-- | Wrapper around 'session'.
session' :: HasPool v db
         => Session db IO r
         -> Handler b v (Either (SessionError db) r)
session' f = do
  db <- view poolLens
  liftIO (Hasql.session db f)

