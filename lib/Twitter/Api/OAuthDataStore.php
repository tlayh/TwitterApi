<?php

namespace Twitter\Api;

class OAuthDataStore {
  function lookupConsumer($consumerKey) {
    // implement me
  }

  function lookupToken($consumer, $tokenType, $token) {
    // implement me
  }

  function lookupNonce($consumer, $token, $nonce, $timestamp) {
    // implement me
  }

  function newRequestToken($consumer, $callback = null) {
    // return a new token attached to this consumer
  }

  function newAccessToken($token, $consumer, $verifier = null) {
    // return a new access token attached to this consumer
    // for the user associated with this token if the request token
    // is authorized
    // should also invalidate the request token
  }

}