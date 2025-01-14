<?php
openlog("okta", LOG_PID | LOG_PERROR, LOG_LOCAL0);

session_start();

$client_id = 'YOUR_CLIENT_ID';
$client_secret = 'YOUR_CLIENT_SECRET';
$redirect_uri = 'REDIRECT_URL_OF_YOUR_PHP_APPLICATION';
//$metadata_url = 'https://hornblower.okta.com/.well-known/oauth-authorization-server';
$metadata_url = 'https://COMPANY.okta.com/.well-known/openid-configuration';

if(isset($_GET['logout'])) {
  unset($_SESSION['username']);
  unset($_SESSION['sub']);
  header('Location: /');
  die();
}

if(isset($_SESSION['sub'])) {
  echo '<p>Logged in as</p>';
  echo '<p>' . $_SESSION['username'] . '</p>';
  echo '<p><a href="/?logout">Log Out</a></p>';
  echo '<pre>';
print_r($_SESSION);
  echo '</pre>';
  die();
}


$metadata = http($metadata_url);

if(!isset($_GET['code'])) {
  syslog(LOG_INFO, "No code from _GET");
  $_SESSION['state'] = bin2hex(random_bytes(5));
  $_SESSION['code_verifier'] = bin2hex(random_bytes(50));
  $code_challenge = base64_urlencode(hash('sha256', $_SESSION['code_verifier'], true));
  syslog(LOG_INFO, "state: ".$_SESSION['state']);
  syslog(LOG_INFO, "code_verifier: ".$_SESSION['code_verifier']);
  syslog(LOG_INFO, "code_challenge: ".$code_challenge);
  
  $authorize_url = $metadata->authorization_endpoint.'?'.http_build_query([
    'response_type' => 'code',
    'client_id' => $client_id,
    'redirect_uri' => $redirect_uri,
    'state' => $_SESSION['state'],
    'scope' => 'openid profile email',
    'code_challenge' => $code_challenge,
    'code_challenge_method' => 'S256',
  ]);
  syslog(LOG_INFO, "authorize_url: ".$authorize_url);

  echo '<p>Not logged in 2</p>';
  echo '<p><a href="'.$authorize_url.'">Log In</a></p>';
} else {
  syslog(LOG_INFO, "state: ".$_SESSION['state'].' vs '.$_GET['state']);

  if($_SESSION['state'] != $_GET['state']) {
   syslog(LOG_INFO, "Authorization server returned an invalid state parameter");
    die('Authorization server returned an invalid state parameter');
  }

  if(isset($_GET['error'])) {
    syslog(LOG_INFO, 'Authorization server returned an error: '.htmlspecialchars($_GET['error']));
    die('Authorization server returned an error: '.htmlspecialchars($_GET['error']));
  }

  $response = http($metadata->token_endpoint, [
    'grant_type' => 'authorization_code',
    'code' => $_GET['code'],
    'redirect_uri' => $redirect_uri,
    'client_id' => $client_id,
    'client_secret' => $client_secret,
    'code_verifier' => $_SESSION['code_verifier'],
  ]);

  $access_token = $response->access_token;
  syslog(LOG_INFO, "access_token: ".$access_token);
  
  if(!isset($response->access_token)) {
    syslog(LOG_INFO, 'Error fetching access token');
    die('Error fetching access token');
  }

  $userinfo_endpoint = $metadata->userinfo_endpoint;
  syslog(LOG_INFO, "userinfo_endpoint: ".$userinfo_endpoint);
  
  $userinfo = http($userinfo_endpoint, [
    'access_token' => $access_token,
  ]);

  if($userinfo->sub) {
    $_SESSION['sub'] = $userinfo->sub;
    $_SESSION['username'] = $userinfo->preferred_username;
    $_SESSION['profile'] = $userinfo;
    syslog(LOG_INFO, "sub: ".$_SESSION['sub']);
    syslog(LOG_INFO, "username: ".$_SESSION['username']);
    syslog(LOG_INFO, "profile: ".var_export($_SESSION['profile'], true));
    header('Location: /');
    die();
  }

}



// Base64-urlencoding is a simple variation on base64-encoding
// Instead of +/ we use -_, and the trailing = are removed.
function base64_urlencode($string) {
  return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
}


function http($url, $params=false) {
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  syslog(LOG_INFO, "url: ".$url);

  if($params !== false){
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    syslog(LOG_INFO, "params: ".http_build_query($params));
  }
  $answer = json_decode(curl_exec($ch));
  syslog(LOG_INFO, "answer: ".var_export($answer, true));
  return $answer;
}

