{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE TypeOperators              #-}
{-# LANGUAGE RecordWildCards            #-}

import Control.Monad (when)

import Data.Maybe (fromJust, isNothing)
import Data.Serialize (Serialize)
import qualified Data.Text as T (unpack)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (toStrict, fromStrict)

import Servant (
    Proxy(..), Server, (:>), (:<|>)(..)
  , Header, Headers, addHeader
  , Get, Post, ReqBody, FormUrlEncoded, FromFormUrlEncoded(..))

import Servant.Server (
    Context ((:.), EmptyContext)
  , serveWithContext)

import Servant.API.Experimental.Auth    (AuthProtect)
import Servant.API.ContentTypes         (Accept(..), MimeRender(..))
import Servant.Server.Experimental.Auth (AuthHandler)
import Servant.Server.Experimental.Auth.Cookie

import Network.Wai              (Application, Request)
import Network.Wai.Handler.Warp (run)

import GHC.Generics

import Network.HTTP.Media ((//), (/:))

import Text.Blaze.Html5 ((!))
import Text.Blaze.Html.Renderer.Utf8 (renderHtml)
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A

import Crypto.Random (DRG, drgNew)
import Crypto.Hash (HashAlgorithm)
import Crypto.Cipher.Types (BlockCipher)


data HTML

instance Accept HTML where
   contentType _ = "text" // "html" /: ("charset", "utf-8")

instance MimeRender HTML ByteString where
   mimeRender _ x = fromStrict $ x


data Account = Account Int String String
  deriving (Show, Eq, Generic)

instance Serialize Account

type instance AuthCookieData = Account


data LoginForm = LoginForm {
  username :: String
, password :: String
} deriving (Eq, Show)

instance FromFormUrlEncoded LoginForm where
  fromFormUrlEncoded d = do
    let username' = lookup "username" d
    when (isNothing username') $ Left "username field is missing"

    let password' = lookup "password" d
    when (isNothing username') $ Left "password field is missing"

    Right $ LoginForm {
        username = T.unpack . fromJust $ username'
      , password = T.unpack . fromJust $ password'
      }


usersDB :: [Account]
usersDB = [
    Account 101 "mr_foo" "password1"
  , Account 102 "mr_bar" "letmein"
  , Account 103 "mr_baz" "baseball"
  ]

userLookup :: String -> String -> [Account] -> Maybe Int
userLookup _ _ [] = Nothing
userLookup username' password' ((Account uid username'' password''):as) =
  case (username', password') == (username'', password'') of
    True  -> Just uid
    False -> userLookup username' password' as


type ExampleAPI =
       Get '[HTML] ByteString
  :<|> "login" :> Get '[HTML] ByteString
  :<|> "login" :> ReqBody '[FormUrlEncoded] LoginForm
       :> Post '[HTML] (Headers '[Header "set-cookie" ByteString] ByteString)
  :<|> "private" :> AuthProtect "cookie-auth" :> Get '[HTML] ByteString


server :: Settings -> Server ExampleAPI
server settings = serveHome
    :<|> serveLogin
    :<|> serveLoginPost
    :<|> servePrivate where

  serveHome = return $ render homePage
  serveLogin = return $ render $ loginPage True

  serveLoginPost form = case userLookup (username form) (password form) usersDB of
    Nothing   -> return $ addHeader "" (render $ loginPage False)
    Just uid' -> addSession
                   settings
                   (Account uid' (username form) (password form))
                   (render $ redirectPage "/private")

  servePrivate (Account uid u p) = return $ render (privatePage uid u p)

  render = toStrict . renderHtml


app :: Settings -> Application
app settings = serveWithContext
  (Proxy :: Proxy ExampleAPI)
  ((defaultAuthHandler settings :: AuthHandler Request Account) :. EmptyContext)
  (server settings)


main :: IO ()
main = do

  randomSource' <- mkRandomSource drgNew 1000
  serverKey' <- mkServerKey 16 Nothing

  let authSettings = ($ defaultSettings) $ \(Settings {..}) -> Settings {
    cookieFlags = []
  , hideReason = False
  , randomSource = randomSource'
  , serverKey = serverKey'
  , ..
  }

  run 8080 (app authSettings)


pageMenu :: H.Html
pageMenu = do
  H.a ! A.href "/"        $ "home"
  _ <- " "
  H.a ! A.href "/login"   $ "login"
  _ <- " "
  H.a ! A.href "/private" $ "private"
  H.hr


homePage :: H.Html
homePage = H.docTypeHtml $ do
  H.head $ do
    H.title "home"
  H.body $ do
    pageMenu
    H.p "This is an example of using servant-auth-cookie library."
    H.p "Use login page to get access to the private page."


loginPage :: Bool -> H.Html
loginPage firstTime = H.docTypeHtml $ do
  H.head $ do
    H.title "login"
  H.body $ do
    pageMenu
    H.form ! A.method "post" ! A.action "/login" $ do
      H.table $ do
        H.tr $ do
         H.td $ "username:"
         H.td $ H.input ! A.type_ "text" ! A.name "username"
        H.tr $ do
         H.td $ "password:"
         H.td $ H.input ! A.type_ "password" ! A.name "password"
      H.input ! A.type_ "submit"
    when (not firstTime) $ H.p "Incorrect username/password"


privatePage :: Int -> String -> String -> H.Html
privatePage uid username' password' = H.docTypeHtml $ do
  H.head $ do
    H.title "private"
  H.body $ do
    pageMenu
    H.p $ H.b "ID: "       >> H.toHtml (show uid)
    H.p $ H.b "username: " >> H.toHtml username'
    H.p $ H.b "password: " >> H.toHtml password'


redirectPage :: String -> H.Html
redirectPage uri = H.docTypeHtml $ do
  H.head $ do
    H.title "redirecting..."
    H.meta ! A.httpEquiv "refresh" ! A.content (H.toValue $ "1; url=" ++ uri)
  H.body $ do
    H.p "You are being redirected."
    H.p $ do
      "If your browser does not refresh the page click "
      H.a ! A.href (H.toValue uri) $ "here"


