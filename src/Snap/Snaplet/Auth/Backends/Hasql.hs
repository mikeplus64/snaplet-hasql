{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE DeriveGeneric        #-}
{-# LANGUAGE FlexibleContexts     #-}
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
Adapted from "snaplet-postgresql-simple"\'s auth module.

This module allows you to use the auth snaplet with your user database stored
in a Hasql database.  When you run your application with this snaplet, a
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

> d <- nestSnaplet "db" db $ hasqlInit
> a <- nestSnaplet "auth" auth $ initHasqlAuth sess d

A database table @snap_auth_users@ for users is created on initialisation.

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
import           Data.Text            (Text)
import qualified Data.Text            as T
import qualified Data.Text.Encoding   as T
import qualified Data.Text.Read       as T
import           Data.Time
import           GHC.Generics
import           Hasql
import           Hasql.Backend        (CxError, CxTx, CxValue, TxError)
import           Paths_snaplet_hasql
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
  :: (CxTx s, Show (CxError s), Show (TxError s), CxAuthUser s)
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
    Hasql.session pool (tx writeMode (unitEx defAuthTable))
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
  desc = "A Hasql backend for user authentication"
  datadir = Just (fmap (++"/resources/auth") getDataDir)

-- | Default authentication table layout
defAuthTable :: Stmt c
defAuthTable =
  [stmt|CREATE TABLE IF NOT EXISTS snap_auth_user
    ( uid                 SERIAL      PRIMARY KEY
    , login               text        UNIQUE NOT NULL
    , email               text
    , password            text
    , activated_at        timestamptz
    , suspended_at        timestamptz
    , remember_token      text
    , login_count         integer     NOT NULL
    , failed_login_count  integer     NOT NULL
    , locked_out_until    timestamptz
    , current_login_at    timestamptz
    , last_login_at       timestamptz
    , current_login_ip    text
    , last_login_ip       text
    , created_at          timestamptz
    , updated_at          timestamptz
    , reset_token         text
    , reset_requested_at  timestamptz
    , user_meta           json        NOT NULL
    )
  |]

type CxAuthUser c = ( CxValue c Text
                    , CxValue c (Maybe Text)
                    , CxValue c (Maybe UTCTime)
                    , CxValue c Int
                    , CxValue c ByteString
                    , CxValue c (Maybe ByteString)
                    , CxValue c Value)

userFromTuple
  ( Just . UserId . T.pack . (show :: Int -> String) -> userId, userLogin
  , userEmail, Just . Encrypted -> userPassword, userActivatedAt
  , userSuspendedAt, userRememberToken, userLoginCount, userFailedLoginCount
  , userLockedOutUntil, userCurrentLoginAt, userLastLoginAt
  , userCurrentLoginIp, userLastLoginIp, userCreatedAt, userUpdatedAt
  , userResetToken, userResetRequestedAt, Object userMeta) =
  AuthUser{userRoles = [], ..}

saveQuery :: CxAuthUser c => AuthUser -> Tx c s AuthUser
saveQuery u@AuthUser{..} =
  userFromTuple <$> singleEx (maybe insertQuery updateQuery userId)
 where
  -- YIKES
  passwordToText :: Password -> Text
  passwordToText (Encrypted bs) = T.decodeUtf8 bs
  passwordToText (ClearText bs) = error "Cannot save a ClearText password!"

  fromPassword :: ByteString -> Password
  fromPassword = Encrypted

  -- no userRoles - should there be?

  insertQuery =
    [stmt|INSERT INTO snap_auth_user
          VALUES(default,?,?,?,?, ?,?,?,?, ?,?,?, ?,?,?,?, ?,?,?)
          RETURNING snap_auth_user.* |]

    userLogin userEmail (fmap passwordToText userPassword)
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
     userLogin userEmail (fmap passwordToText userPassword)
     userActivatedAt userSuspendedAt userRememberToken userLoginCount
     userFailedLoginCount userLockedOutUntil userCurrentLoginAt
     userLastLoginAt userCurrentLoginIp userLastLoginIp userCreatedAt
     userUpdatedAt userResetToken userResetRequestedAt (Object userMeta)
     (text2int (unUid uid))

-- there ought to be a way to not have to "hide" the error like this... or at
-- least a way to log an error from here
hideError :: (Show (TxError c), Show (CxError c))
          => Either (SessionError c) a -> IO (Either AuthFailure a)
hideError = either
  (\e -> print e >> pure (Left BackendError))
  (pure . Right)

instance (CxTx s, Show (CxError s), Show (TxError s), CxAuthUser s) =>
         IAuthBackend (HasqlAuthManager s) where
  save HasqlAuthManager{..} u =
    hideError =<< Hasql.session pool (tx writeMode (saveQuery u))

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
    void (Hasql.session pool
          (tx writeMode
           (unitEx ([stmt|DELETE FROM snap_auth_user WHERE uid = ?|] uid))))

readMode :: TxMode
readMode = Just (Serializable, Nothing)

writeMode :: TxMode
writeMode = Just (Serializable, Just True)

text2int :: Text -> Int
text2int t =
  either (\a -> error ("text2int: Can't parse " ++ show t)) fst
         (T.decimal t)

