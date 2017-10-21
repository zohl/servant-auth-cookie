{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE FlexibleContexts #-}

module AuthAPI (
  ExampleAPI
, Account (..)
, app
, authSettings
, LoginForm (..)
, homePage
, loginPage
) where

import Prelude ()
import Prelude.Compat
import Control.Monad.Catch (catch)
import Control.Monad (void, unless, when)
import Data.ByteString.Lazy (fromStrict)
import Data.Default (def)
import Data.List (find)
import Data.Maybe (catMaybes)
import Data.Serialize (Serialize)
import GHC.Exts (fromList)
import GHC.Generics
import Network.HTTP.Types (urlEncode)
import Network.Wai (Application)
import Servant (ReqBody, FormUrlEncoded, Header)
import Servant ((:<|>)(..), (:>), errBody, err403, toQueryParam)
import Servant (Post, AuthProtect, Get, Server, Proxy)
import Servant (addHeader, serveWithContext, Proxy(..), Context(..))
import Servant.HTML.Blaze
import Servant.Server.Experimental.Auth (mkAuthHandler)
import Servant.Server.Experimental.Auth.Cookie
import Text.Blaze.Html5 ((!), Markup)
import qualified Data.Text as T
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8 as BSC8

#if MIN_VERSION_servant (0,9,1)
import Control.Monad.IO.Class (liftIO)
import Servant (Capture)
#else
import Servant (Headers)
#endif

#if MIN_VERSION_servant (0,9,0)
import Web.FormUrlEncoded (FromForm(..), ToForm(..), lookupUnique, lookupMaybe)
#else
import Servant (FromFormUrlEncoded(..), ToFormUrlEncoded(..))
#endif

#if MIN_VERSION_servant (0,7,0)
import Servant (Handler, throwError)
#else
import Control.Monad.Except (ExceptT, throwError)
import Servant (ServantErr)
#endif

#if !MIN_VERSION_servant (0,7,0)
type Handler a = ExceptT ServantErr IO a
#endif

----------------------------------------------------------------------------
-- Accounts

-- | A structure that will be stored in the cookies to identify the user.
data Account = Account
  { accUid       :: Int
  , accUsername :: String
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
  , lfRemember :: Bool
  } deriving (Eq, Show)


#if MIN_VERSION_servant (0,9,0)
instance FromForm LoginForm where
  fromForm f = do
    lfUsername <- fmap T.unpack $ lookupUnique "username" f
    lfPassword <- fmap T.unpack $ lookupUnique "password" f
    lfRemember <- fmap (maybe False (const True)) $ lookupMaybe "remember" f
    return LoginForm {..}

instance ToForm LoginForm where
  toForm LoginForm {..} = fromList $
      ("username", toQueryParam lfUsername)
    : ("password", toQueryParam lfPassword)
    : (catMaybes $ [
        if lfRemember then Just ("remember", toQueryParam ()) else Nothing
      ])
#else
instance FromFormUrlEncoded LoginForm where
  fromFormUrlEncoded d = do
    lfUsername <- case lookup "username" d of
      Nothing -> Left "username field is missing"
      Just  x -> return (T.unpack x)
    lfPassword <- case lookup "password" d of
      Nothing -> Left "password field is missing"
      Just  x -> return (T.unpack x)
    lfRemember <- case lookup "remember" d of
      Nothing -> return False
      Just  _ -> return True
    return LoginForm {..}

instance ToFormUrlEncoded LoginForm where
  toFormUrlEncoded LoginForm {..} = fromList $
      ("username", toQueryParam lfUsername)
    : ("password", toQueryParam lfPassword)
    : (catMaybes $ [
        if lfRemember then Just ("remember", toQueryParam ()) else Nothing
      ])
#endif

----------------------------------------------------------------------------
-- API of the example

-- | Interface
#if MIN_VERSION_servant(0,9,1)
type ExampleAPI =
       Get '[HTML] Markup
  :<|> "login" :> Get '[HTML] Markup
  :<|> "login" :> ReqBody '[FormUrlEncoded] LoginForm :> Post '[HTML] (Cookied Markup)
  :<|> "logout" :> Get '[HTML] (Cookied Markup)
  :<|> "private" :> AuthProtect "cookie-auth" :> Get '[HTML] (Cookied Markup)
  :<|> "whoami" :> Header "cookie" T.Text :> Get '[HTML] Markup
  :<|> "keys" :> (
         Get '[HTML] Markup
    :<|> "add" :> Get '[HTML] Markup
    :<|> "rem" :> Capture "key" String :> Get '[HTML] Markup)
#else
type ExampleAPI =
       Get '[HTML] Markup
  :<|> "login" :> Get '[HTML] Markup
  :<|> "login"
       :> ReqBody '[FormUrlEncoded] LoginForm
       :> Post '[HTML] (Headers '[Header "Set-Cookie" EncryptedSession] Markup)
  :<|> "logout"
       :> Get '[HTML] (Headers '[Header "Set-Cookie" EncryptedSession] Markup)
  :<|> "private" :> AuthProtect "cookie-auth" :> Get '[HTML] Markup
  :<|> "keys" :> Get '[HTML] Markup
#endif

-- | Implementation
server :: (ServerKeySet s)
  => AuthCookieSettings
  -> (IO ())
  -> RandomSource
  -> s
  -> Server ExampleAPI
#if MIN_VERSION_servant(0,9,1)
server settings generateKey rs sks =
#else
server settings _generateKey rs sks =
#endif
       serveHome
  :<|> serveLogin
  :<|> serveLoginPost
  :<|> serveLogout
  :<|> servePrivate
#if MIN_VERSION_servant(0,9,1)
  :<|> serveWhoami
#endif
  :<|> serveKeys where

  addSession' = addSession
    settings -- the settings
    rs       -- random source
    sks      -- server key set

  serveHome = return homePage
  serveLogin = return (loginPage True)

  serveLoginPost LoginForm {..} =
    case userLookup lfUsername lfPassword usersDB of
      Nothing   -> return $ addHeader emptyEncryptedSession (loginPage False)
      Just uid  -> addSession'
        (def { ssExpirationType = if lfRemember then MaxAge else Session })
        (Account uid lfUsername lfPassword)
        (redirectPage "/private" "Session has been started")

  serveLogout = removeSession settings (redirectPage "/" "Session has been terminated")

#if MIN_VERSION_servant(0,9,1)
  servePrivate = cookied settings rs sks (Proxy :: Proxy Account) servePrivate'

  serveWhoami Nothing = return $ whoamiPage Nothing
  serveWhoami (Just h) = do
    mwm <- getHeaderSession settings sks h `catch` handleEx
    return $ whoamiPage $ epwSession <$> mwm
    where
      handleEx :: AuthCookieExceptionHandler
      handleEx _ex = return Nothing
#else
  servePrivate = servePrivate' . epwSession
#endif

  servePrivate' :: Account -> Handler Markup
  servePrivate' (Account uid u p) = return $ privatePage uid u p

#if MIN_VERSION_servant(0,9,1)
  serveKeys = (keysPage True <$> getKeys sks) :<|> serveAddKey :<|> serveRemKey

  serveAddKey = do
    liftIO $ generateKey
    return $ redirectPage "/keys" "New key was added"

  serveRemKey b64key = either
    (\err -> throwError err403 { errBody = fromStrict . BSC8.pack $ err })
    (\key -> do
      removeKey sks key
      return $ redirectPage "/keys" "The key was removed")
    (Base64.decode . BSC8.pack $ b64key)
#else
  serveKeys = keysPage False <$> getKeys sks
#endif

-- | Custom handler that bluntly reports any occurred errors.
authHandler :: AuthCookieHandler Account
authHandler acs sks = mkAuthHandler $ \request ->
  (getSession acs sks request) `catch` handleEx >>= maybe
    (throwError err403 {errBody = "No cookies"})
    (return)
  where
    handleEx :: AuthCookieExceptionHandler
    handleEx ex = throwError err403 {errBody = fromStrict . BSC8.pack $ show ex}

-- | Authentication settings.
-- Note that we do not use "Secure" flag here. Cookies with this flag will be
-- accepted only if they were transfered over https. This is a must for
-- production server, but is an obstacle if you want to check it without
-- setting up TLS.
authSettings :: AuthCookieSettings
authSettings = def {acsCookieFlags = ["HttpOnly"]}

-- | Application
app :: (ServerKeySet s)
  => AuthCookieSettings
  -> IO () -- ^ An action to create a new key
  -> RandomSource
  -> s
  -> Application
app settings generateKey rs sks = serveWithContext
  (Proxy :: Proxy ExampleAPI)
  ((authHandler settings sks) :. EmptyContext)
  (server settings generateKey rs sks)


----------------------------------------------------------------------------
-- Markup

pageMenu :: Markup
pageMenu = do
  H.a ! A.href "/"        $ "home"
  void " "
  H.a ! A.href "/login"   $ "login"
  void " "
  H.a ! A.href "/private" $ "private"
  void " "
#if MIN_VERSION_servant(0,9,1)
  H.a ! A.href "/whoami"  $ "whoami"
  void " "
#endif
  H.a ! A.href "/keys"    $ "keys"
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
        H.tr $ do
         H.td ! A.colspan "2" $ H.label $ do
           H.input ! A.type_ "checkbox" ! A.name "remember" ! A.checked ""
           "Remember me"
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
    H.a ! A.href "/logout" $ "logout"

#if MIN_VERSION_servant(0,9,1)
whoamiPage :: Maybe Account -> Markup
whoamiPage macc = H.docTypeHtml $ do
  H.head (H.title "whoami")
  H.body $ do
    pageMenu
    case macc of
      Nothing  -> H.p $ H.b "Not authenticated"
      Just acc -> H.p $ H.b "username: " >> H.toHtml (accUsername acc)
#endif

keysPage :: Bool -> (BSC8.ByteString, [BSC8.ByteString]) -> Markup
keysPage showControls (k, ks) = H.docTypeHtml $ do
  H.head (H.title "keys")
  H.body $ do
    pageMenu
    when showControls $
      H.a ! A.href "/keys/add" $ "add new key"
    H.p $ H.b $ keyElement False k
    mapM_ H.p $ map (keyElement showControls) ks

keyElement :: Bool -> BSC8.ByteString -> Markup
keyElement removable key = let
  b64key =  Base64.encode $ key
  url = "/keys/rem/" ++ (BSC8.unpack . urlEncode True $ b64key)
  in do
     H.span ! A.class_ "key" $ H.toHtml (BSC8.unpack b64key)
     when (removable) $ do
       void " "
       H.a ! A.href (H.stringValue url) $ "(remove)"

redirectPage :: String -> String -> Markup
redirectPage uri message = H.docTypeHtml $ do
  H.head $ do
    H.title "redirecting..."
    H.meta ! A.httpEquiv "refresh" ! A.content (H.toValue $ "1; url=" ++ uri)
  H.body $ do
    H.p $ H.toHtml message
    H.p "You are being redirected."
    H.p $ do
      void "If your browser does not refresh the page click "
      H.a ! A.href (H.toValue uri) $ "here"

