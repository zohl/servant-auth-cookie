{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE TypeOperators              #-}

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
  :<|> ReqBody '[FormUrlEncoded] LoginForm
       :> Post '[HTML] (Headers '[Header "set-cookie" ByteString] ByteString)
  :<|> "private" :> AuthProtect "cookie-auth" :> Get '[HTML] ByteString


server :: Server ExampleAPI
server = servePublicPage :<|> serveLogin :<|> servePrivatePage where

  servePrivatePage (Account uid u p) = return $ render (privatePage uid u p)

  servePublicPage = return $ render (publicPage "")

  serveLogin form = case userLookup (username form) (password form) usersDB of
    Nothing   -> return $ addHeader "" (render $ publicPage "Incorrect username/password")
    Just uid' -> addSession 
                   authSettings
                   (Account uid' (username form) (password form))
                   (render $ publicPage "You are logged in")

  render = toStrict . renderHtml


authSettings :: Settings
authSettings = defaultSettings {
    cookieFlags = []
  , hideReason = False
  }

app :: Application
app = serveWithContext
  (Proxy :: Proxy ExampleAPI)
  ((defaultAuthHandler authSettings :: AuthHandler Request Account) :. EmptyContext)
  server

main :: IO ()
main = run 8080 app 
    

pageMenu :: H.Html
pageMenu = do
  H.a ! A.href "/"        $ "public"
  _ <- " "
  H.a ! A.href "/private" $ "private"
  H.hr

publicPage :: String -> H.Html
publicPage message = H.docTypeHtml $ do
  H.head $ do
    H.title "public page"
  H.body $ do
    pageMenu
    H.form ! A.method "post" ! A.action "/" $ do
      H.input ! A.type_ "text"     ! A.name "username" >> H.br
      H.input ! A.type_ "password" ! A.name "password" >> H.br
      H.input ! A.type_ "submit"
    when (length message > 0) $ H.p (H.toHtml message)

privatePage :: Int -> String -> String -> H.Html
privatePage uid username' password' = H.docTypeHtml $ do
  H.head $ do
    H.title "private page"
  H.body $ do
    pageMenu
    H.p $ H.b "ID: "       >> H.toHtml (show uid)
    H.p $ H.b "username: " >> H.toHtml username'
    H.p $ H.b "password: " >> H.toHtml password'
