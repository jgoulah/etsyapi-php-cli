<?php
require 'oauth.inc.php';

$v2_path  = 'v2';
if ($argc > 1) {
    if ($argv[1] == 'sandbox') {
        print "using sandbox\n";
        $v2_path  = 'v2/sandbox';
    }
}

if (!strlen(OAUTH_CONSUMER_KEY) || !strlen(OAUTH_CONSUMER_SECRET)) {
    print "please set OAUTH_CONSUMER_KEY and OAUTH_CONSUMER_SECRET environment variables\n";
    exit;
}

if (OAUTH_DEBUG) {
    print 'key: '. OAUTH_CONSUMER_KEY ."\n";
    print 'secret: '. OAUTH_CONSUMER_SECRET ."\n";
}

// step 1

$oauth = new OAuth(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET);
$req_token = $oauth->getRequestToken("http://openapi.etsy.com/$v2_path/oauth/request_token", 'oob');

if (OAUTH_DEBUG) {
    print "request token info\n";
    print_r($req_token);
}

$login_url = sprintf(
    "%s?oauth_consumer_key=%s&oauth_token=%s",
    $req_token['login_url'],
    $req_token['oauth_consumer_key'],
    $req_token['oauth_token']
);


/// read user input for verifier
print "please sign in to this url and paste the verifier below: $login_url \n";
print '$ ';
$verifier = trim(fgets(STDIN));

// step 2

$request_token = $req_token['oauth_token'];
$request_token_secret = $req_token['oauth_token_secret'];

$oauth->setToken($request_token, $request_token_secret);

try {
    $acc_token = $oauth->getAccessToken("http://openapi.etsy.com/$v2_path/oauth/access_token", null, $verifier);
} catch (OAuthException $e) {
    error_log($e->getMessage());
    error_log(print_r($oauth->getLastResponse(), true));
    error_log(print_r($oauth->getLastResponseInfo(), true));
    exit;
}

if (OAUTH_DEBUG) {
    print "access token info\n";
    print_r($acc_token);
}


// step 3

$access_token = $acc_token['oauth_token'];
$access_token_secret = $acc_token['oauth_token_secret'];

$oauth = new OAuth(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET,
                   OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_URI);
$oauth->setToken($access_token, $access_token_secret);

try {
    $data = $oauth->fetch("http://openapi.etsy.com/$v2_path/private/users/__SELF__");
    $json = $oauth->getLastResponse();
    
    print "results for logged in user info\n";
    print_r(json_decode($json, true));
    
} catch (OAuthException $e) {
    error_log($e->getMessage());
    error_log(print_r($oauth->getLastResponse(), true));
    error_log(print_r($oauth->getLastResponseInfo(), true));
    exit;
}
