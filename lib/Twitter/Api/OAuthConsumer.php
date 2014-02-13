<?php

namespace Twitter\Api;

class OAuthConsumer 
{
    public $key;
    public $secret;

    function __construct($key, $secret, $callbackUrl=NULL) 
    {
        $this->key         = $key;
        $this->secret      = $secret;
        $this->callbackUrl = $callbackUrl;
    }

    function __toString() 
    {
        return "OAuthConsumer[key=$this->key,secret=$this->secret]";
    }
}