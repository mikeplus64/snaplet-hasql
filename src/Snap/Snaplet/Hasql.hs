{-# LANGUAGE ExplicitNamespaces     #-}
{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE OverloadedStrings      #-}
module Snap.Snaplet.Hasql
  ( HasPool(..)
  , hasqlInit
  , session
  , session'
  , module H
  ) where
import           Control.Lens
import           Control.Monad.Reader
import           Hasql                as H hiding (session)
import qualified Hasql
import           Hasql.Backend        hiding (Tx)
import           Snap

class (Show (CxError db), Show (TxError db), CxTx db, Cx db) =>
      HasPool s db | s -> db where
  poolLens :: Lens' s (Pool db)

instance (Cx db, CxTx db, Show (CxError db), Show (TxError db)) =>
         HasPool (Pool db) db where
  poolLens = id

hasqlInit
  :: HasPool c db
  => CxSettings db
  -> PoolSettings
  -> SnapletInit c (Pool db)
hasqlInit cx p =
  makeSnaplet "hasql" "" Nothing $ do
    pool <- liftIO (acquirePool cx p)
    onUnload (releasePool pool)
    return pool

{-# INLINE session #-}
-- | Wrapper around 'session' that just calls 'fail' on failure, and
-- uses the available 'poolLens'. Most useful inside 'Handler`s.
session :: (HasPool v db, MonadReader v m, MonadIO m)
        => Session db IO r -> m r
session f = do
  db <- view poolLens
  r  <- liftIO (Hasql.session db f)
  case r of
    Right a -> return a
    Left er -> fail (show er)

{-# INLINE session' #-}
-- | Wrapper around 'session'.
session' :: (HasPool v db, MonadReader v m, MonadIO m)
         => Session db IO r
         -> m (Either (SessionError db) r)
session' f = do
  db <- view poolLens
  liftIO (Hasql.session db f)

