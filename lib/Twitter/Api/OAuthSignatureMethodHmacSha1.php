<?php

namespace Twitter\Api;

/**
 * The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104] 
 * where the Signature Base String is the text and the key is the concatenated values (each first 
 * encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&' 
 * character (ASCII code 38) even if empty.
 *   - Chapter 9.2 ("HMAC-SHA1")
 */
class OAuthSignatureMethodHmacSha1 extends OAuthSignatureMethod 
{
  function getName() 
  {
    return "HMAC-SHA1";
  }

  public function buildSignature($request, $consumer, $token) 
  {
    $baseString = $request->getSignatureBaseString();
    $request->baseString = $baseString;

    $keyParts = array(
      $consumer->secret,
      ($token) ? $token->secret : ""
    );

    $keyParts = OAuthUtil::urlencodeRfc3986($keyParts);
    $key = implode('&', $keyParts);

    return base64_encode(hash_hmac('sha1', $baseString, $key, true));
  }
}