{-# LANGUAGE CPP                   #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE OverloadedLists       #-}

module AuthAPI (
  ExampleAPI
, Account(..)
, app
, authSettings
, LoginForm(..)
, homePage
, loginPage
) where

import Prelude ()
import Prelude.Compat
import Control.Monad.Catch (catch)
import Control.Monad
import Data.ByteString.Lazy (fromStrict)
import Data.Default (def)
import Data.List (find)
import Data.Serialize (Serialize)
import GHC.Generics
import Network.Wai (Application, Request)
import Servant (Handler, ReqBody, FormUrlEncoded)
import Servant ((:<|>)(..), (:>), errBody, throwError, err403, toQueryParam)
import Servant (Post, Headers, Header, AuthProtect, Get, Server, Proxy)
import Servant (addHeader, serveWithContext, Proxy(..), Context(..))
import Servant.HTML.Blaze
import Servant.Server.Experimental.Auth (AuthHandler, mkAuthHandler)
import Servant.Server.Experimental.Auth.Cookie
import Text.Blaze.Html5 ((!), Markup)
import qualified Data.Text as T
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import qualified Data.ByteString.Char8 as BSC8

#if MIN_VERSION_servant (0,9,0)
import Web.FormUrlEncoded (FromForm(..), ToForm(..), lookupUnique)
#else
import Servant (FromFormUrlEncoded(..), ToFormUrlEncoded(..))
#endif

----------------------------------------------------------------------------
-- Accounts

-- | A structure that will be stored in the cookies to identify the user.
data Account = Account
  { accUid       :: Int
  , _accUsername :: String
  , _accPassword :: String
  } deriving (Show, Eq, Generic)

instance Serialize Account

type instance AuthCookieData = Account

-- | In-memory database of "registered" users.
usersDB :: [Account]
usersDB =
  [ Account 101 "mr_foo" "password1"
  , Account 102 "mr_bar" "letmein"
  , Account 103 "mr_baz" "baseball" ]

-- | Function to retrieve users from db.
userLookup :: String -> String -> [Account] -> Maybe Int
userLookup username password db = accUid <$> find f db
  where f (Account _ u p) = u == username && p == password


----------------------------------------------------------------------------
-- Login form

-- | Helper structure to get data from html-form.
data LoginForm = LoginForm
  { lfUsername :: String
  , lfPassword :: String
  } deriving (Eq, Show)


#if MIN_VERSION_servant (0,9,0)
instance FromForm LoginForm where
  fromForm f = do
    username <- fmap T.unpack $ lookupUnique "username" f
    password <- fmap T.unpack $ lookupUnique "password" f
    return LoginForm
      { lfUsername = username
      , lfPassword = password }

instance ToForm LoginForm where
  toForm LoginForm {..} =
    [ ("username", toQueryParam lfUsername)
    , ("password", toQueryParam lfPassword) ]
#else
instance FromFormUrlEncoded LoginForm where
  fromFormUrlEncoded d = do
    username <- case lookup "username" d of
      Nothing -> Left "username field is missing"
      Just  x -> return (T.unpack x)
    password <- case lookup "password" d of
      Nothing -> Left "password field is missing"
      Just  x -> return (T.unpack x)
    return LoginForm
      { lfUsername = username
      , lfPassword = password }

instance ToFormUrlEncoded LoginForm where
  toFormUrlEncoded LoginForm {..} =
    [ ("username", toQueryParam lfUsername)
    , ("password", toQueryParam lfPassword) ]
#endif

----------------------------------------------------------------------------
-- API of the example

-- | Interface
type ExampleAPI =
       Get '[HTML] Markup
  :<|> "login" :> Get '[HTML] Markup
  :<|> "login" :> ReqBody '[FormUrlEncoded] LoginForm
       :> Post '[HTML] (Headers '[Header "set-cookie" EncryptedSession] Markup)
  :<|> "logout" :> Get '[HTML] (Headers '[Header "set-cookie" EncryptedSession] Markup)
  :<|> "private" :> AuthProtect "cookie-auth" :> Get '[HTML] Markup

-- | Implementation
server :: (ServerKeySet s)
  => AuthCookieSettings
  -> RandomSource
  -> s
  -> Server ExampleAPI
server settings rs sks = serveHome
    :<|> serveLogin
    :<|> serveLoginPost
    :<|> serveLogout
    :<|> servePrivate where

  serveHome = return homePage
  serveLogin = return (loginPage True)

  serveLoginPost LoginForm {..} =
    case userLookup lfUsername lfPassword usersDB of
      Nothing   -> return $ addHeader emptyEncryptedSession (loginPage False)
      Just uid -> addSession
        settings -- the settings
        rs       -- random source
        sks      -- server key set
        (Account uid lfUsername lfPassword)
        (redirectPage "/private")

  serveLogout = removeSession settings (redirectPage "/")

  servePrivate (Account uid u p) = return (privatePage uid u p)

-- | Custom handler that bluntly reports any occurred errors.
authHandler :: (ServerKeySet s) => AuthCookieSettings -> s -> AuthHandler Request Account
authHandler acs sks = mkAuthHandler $ \request ->
  (getSession acs sks request) `catch` handleEx >>= maybe
    (throwError err403 {errBody = "No cookies"})
    (return)
  where
    handleEx :: AuthCookieException -> Handler (Maybe Account)
    handleEx ex = throwError err403 {errBody = fromStrict . BSC8.pack $ show ex}

-- | Authentication settings.
-- Note that we do not use "Secure" flag here. Cookies with this flag will be
-- accepted only if they were transfered over https. This is a must for
-- production server, but is an obstacle if you want to check it without
-- setting up TLS.
authSettings :: AuthCookieSettings
authSettings = def {acsCookieFlags = ["HttpOnly"]}

-- | Application
app :: (ServerKeySet s) => AuthCookieSettings -> RandomSource -> s -> Application
app settings rs sks = serveWithContext
  (Proxy :: Proxy ExampleAPI)
  ((authHandler settings sks) :. EmptyContext)
  (server settings rs sks)


----------------------------------------------------------------------------
-- Markup

pageMenu :: Markup
pageMenu = do
  H.a ! A.href "/"        $ "home"
  void " "
  H.a ! A.href "/login"   $ "login"
  void " "
  H.a ! A.href "/private" $ "private"
  H.hr

homePage :: Markup
homePage = H.docTypeHtml $ do
  H.head (H.title "home")
  H.body $ do
    pageMenu
    H.p "This is an example of using servant-auth-cookie library."
    H.p "Use login page to get access to the private page."

loginPage :: Bool -> Markup
loginPage firstTime = H.docTypeHtml $ do
  H.head (H.title "login")
  H.body $ do
    pageMenu
    H.form ! A.method "post" ! A.action "/login" $ do
      H.table $ do
        H.tr $ do
         H.td "username:"
         H.td (H.input ! A.type_ "text" ! A.name "username")
        H.tr $ do
         H.td "password:"
         H.td (H.input ! A.type_ "password" ! A.name "password")
      H.input ! A.type_ "submit"
    unless firstTime $
      H.p "Incorrect username/password"

privatePage :: Int -> String -> String -> Markup
privatePage uid username' password' = H.docTypeHtml $ do
  H.head (H.title "private")
  H.body $ do
    pageMenu
    H.p $ H.b "ID: "       >> H.toHtml (show uid)
    H.p $ H.b "username: " >> H.toHtml username'
    H.p $ H.b "password: " >> H.toHtml password'
    H.hr
    H.a ! A.href "/logout"  $ "logout"

redirectPage :: String -> Markup
redirectPage uri = H.docTypeHtml $ do
  H.head $ do
    H.title "redirecting..."
    H.meta ! A.httpEquiv "refresh" ! A.content (H.toValue $ "1; url=" ++ uri)
  H.body $ do
    H.p "You are being redirected."
    H.p $ do
      void "If your browser does not refresh the page click "
      H.a ! A.href (H.toValue uri) $ "here"

