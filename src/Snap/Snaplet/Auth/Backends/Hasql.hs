{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE DeriveGeneric        #-}
{-# LANGUAGE GADTs                #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE QuasiQuotes          #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TemplateHaskell      #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns         #-}
{-|

This module allows you to use the auth snaplet with your user database stored
in a PostgreSQL database.  When you run your application with this snaplet, a
config file will be copied into the the @snaplets/hasql-auth@ directory.
This file contains all of the configurable options for the snaplet and allows
you to change them without recompiling your application.

To use this snaplet in your application enable the session, postgres, and auth
snaplets as follows:

> data App = App
>     { ... -- your own application state here
>     , _sess :: Snaplet SessionManager
>     , _db   :: Snaplet (Pool s)
>     , _auth :: Snaplet (AuthManager App)
>     }

Then in your initializer you'll have something like this:

> d <- nestSnaplet "db" db pgsInit
> a <- nestSnaplet "auth" auth $ initHasqlAuth sess d

If you have not already created the database table for users, it will
automatically be created for you the first time you run your application.

Adapted from snaplet-postgresql-simple.

-}
module Snap.Snaplet.Auth.Backends.Hasql where
------------------------------------------------------------------------------
import           Control.Applicative
import           Control.Lens
import           Control.Monad
import           Control.Monad.Trans
import           Data.Aeson
import           Data.ByteString      (ByteString)
import qualified Data.ByteString      as B
import qualified Data.Configurator    as C
import           Data.Foldable        (fold)
import qualified Data.HashMap.Lazy    as HM
import           Data.Text            (Text)
import qualified Data.Text            as T
import qualified Data.Text.Encoding   as T
import qualified Data.Text.Read       as T
import           Data.Time
import           GHC.Generics
import           Hasql
import           Hasql.Backend        (CxTx, CxValue)
import           Paths_snaplet_hasql
import           Prelude
import           Snap
import           Snap.Snaplet.Auth
import           Snap.Snaplet.Session
import           Web.ClientSession
------------------------------------------------------------------------------

newtype HasqlAuthManager s = HasqlAuthManager { pool :: Pool s }

------------------------------------------------------------------------------
-- | Initializer for the postgres backend to the auth snaplet.
--
initHasqlAuth
  :: (CxTx s, CxAuthUser s)
  => SnapletLens b SessionManager -- ^ Lens to the session snaplet
  -> Snaplet (Pool s)             -- ^ The hasql snaplet
  -> SnapletInit b (AuthManager b)
initHasqlAuth sess db = makeSnaplet "hasql-auth" desc datadir $ do
  config       <- getSnapletUserConfig
  authSettings <- authSettingsFromConfig
  liftIO (do
    key <- getKey (asSiteKey authSettings)
    let pool    = db^#snapletValue
        manager = HasqlAuthManager pool
    Hasql.session pool (tx txMode (unitEx defAuthTable))
    rng <- mkRNG
    return AuthManager
      { backend               = manager
      , session               = sess
      , activeUser            = Nothing
      , minPasswdLen          = asMinPasswdLen authSettings
      , rememberCookieName    = asRememberCookieName authSettings
      , rememberPeriod        = asRememberPeriod authSettings
      , siteKey               = key
      , lockout               = asLockout authSettings
      , randomNumberGenerator = rng
      })
 where
  desc    = "A Hasql backend for user authentication"
  datadir = Just (fmap (++"/resources/auth") getDataDir)

-- | Default authentication table layout
defAuthTable :: Stmt c
defAuthTable =
  [stmt|CREATE TABLE IF NOT EXISTS snap_auth_user
    ( uid                 SERIAL      PRIMARY KEY
    , login               text        UNIQUE NOT NULL
    , email               text        NOT NULL
    , password            text        NOT NULL
    , activated_at        timestamptz NOT NULL
    , suspended_at        timestamptz NOT NULL
    , remember_token      text        NOT NULL
    , login_count         integer     NOT NULL
    , failed_login_count  integer     NOT NULL
    , locked_out_until    timestamptz NOT NULL
    , current_login_at    timestamptz NOT NULL
    , last_login_at       timestamptz NOT NULL
    , current_login_ip    text        NOT NULL
    , last_login_ip       text        NOT NULL
    , created_at          timestamptz NOT NULL
    , updated_at          timestamptz NOT NULL
    , reset_token         text        NOT NULL
    , reset_requested_at  timestamptz NOT NULL
    , user_meta           json        NOT NULL
    )
  |]

type CxAuthUser c = ( CxValue c Text
                    , CxValue c (Maybe Text)
                    , CxValue c (Maybe UTCTime)
                    , CxValue c Int
                    , CxValue c Integer
                    , CxValue c ByteString
                    , CxValue c (Maybe ByteString)
                    , CxValue c Value)

userFromTuple
  ( Just . UserId -> userId, userLogin, userEmail
  , Just . Encrypted -> userPassword, userActivatedAt, userSuspendedAt
  , userRememberToken, userLoginCount, userFailedLoginCount
  , userLockedOutUntil, userCurrentLoginAt, userLastLoginAt
  , userCurrentLoginIp, userLastLoginIp, userCreatedAt, userUpdatedAt
  , userResetToken, userResetRequestedAt, Object userMeta) =
  AuthUser{userRoles = [], ..}

saveQuery :: CxAuthUser c => AuthUser -> Tx c s AuthUser
saveQuery u@AuthUser{..} =
  userFromTuple <$> singleEx (maybe insertQuery updateQuery userId)
 where
  -- YIKES
  passwordToBS (Encrypted bs) = bs
  passwordToBS (ClearText bs) = error "Cannot save a ClearText password!"

  fromPassword = case userPassword of
    Just (Encrypted _) -> Encrypted
    Just (ClearText _) -> ClearText
    Nothing            -> Encrypted

  -- no userRoles - should there be?

  insertQuery =
    [stmt|INSERT INTO snap_auth_user
          VALUES(default,?,?,?,?, ?,?,?,?, ?,?,?, ?,?,?,?, ?,?,?)
          RETURNING snap_auth_user.* |]

    userLogin userEmail (fmap passwordToBS userPassword)
    userActivatedAt userSuspendedAt userRememberToken userLoginCount
    userFailedLoginCount userLockedOutUntil userCurrentLoginAt
    userLastLoginAt userCurrentLoginIp userLastLoginIp userCreatedAt
    userUpdatedAt userResetToken userResetRequestedAt (Object userMeta)

  updateQuery uid =
    [stmt|UPDATE snap_auth_user
          SET login               = ?
            , email               = ?
            , password            = ?
            , activated_at        = ?
            , suspended_at        = ?
            , remember_token      = ?
            , login_count         = ?
            , failed_login_count  = ?
            , locked_out_until    = ?
            , current_login_at    = ?
            , last_login_at       = ?
            , current_login_ip    = ?
            , last_login_ip       = ?
            , created_at          = ?
            , updated_at          = ?
            , reset_token         = ?
            , reset_requested_at  = ?
            , user_meta           = ?
          WHERE uid = ?
          RETURNING snap_auth_user.* |]
     userLogin userEmail (fmap passwordToBS userPassword)
     userActivatedAt userSuspendedAt userRememberToken userLoginCount
     userFailedLoginCount userLockedOutUntil userCurrentLoginAt
     userLastLoginAt userCurrentLoginIp userLastLoginIp userCreatedAt
     userUpdatedAt userResetToken userResetRequestedAt (Object userMeta)
     (text2int (unUid uid))

instance (CxTx s, CxAuthUser s) => IAuthBackend (HasqlAuthManager s) where
  save HasqlAuthManager{..} u@AuthUser{..} =
    either (\_ -> Left BackendError) Right <$>
    Hasql.session pool (tx readMode (saveQuery u))

  lookupByUserId HasqlAuthManager{..} (UserId uid) =
    either (const Nothing) (fmap userFromTuple) <$>
    Hasql.session pool (tx readMode (maybeEx query))
   where
    query = [stmt|SELECT * FROM snap_auth_user WHERE snap_auth_user.uid = ?|]
            (text2int uid)

  lookupByLogin HasqlAuthManager{..} login =
    either (const Nothing) (fmap userFromTuple) <$>
    Hasql.session pool (tx readMode (maybeEx query))
   where
    query = [stmt|SELECT * FROM snap_auth_user WHERE snap_auth_user.login = ?|]
            login

  lookupByRememberToken HasqlAuthManager{..} rt =
    either (const Nothing) (fmap userFromTuple) <$>
    Hasql.session pool (tx readMode (maybeEx query))
   where
    query = [stmt|SELECT * FROM snap_auth_user
                  WHERE snap_auth_user.remember_token = ?|] rt

  destroy HasqlAuthManager{..}
          AuthUser{userId = Just (UserId (text2int -> uid))} =
    void $
      Hasql.session pool (tx (Just (ReadUncommitted, Just True))
                             (unitEx $ [stmt|DELETE FROM snap_auth_user
                                             WHERE uid = ?|] uid))

readMode :: TxMode
readMode = Just (RepeatableReads, Nothing)

text2int :: Text -> Integer
text2int = either (error "text2int: Can't parse") fst . T.decimal

txMode :: TxMode
txMode = Just (RepeatableReads, Just True)
