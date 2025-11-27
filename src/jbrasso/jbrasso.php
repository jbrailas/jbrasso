<?php
/**
 * @package     jbraSso.Plugins
 * @author      Giannis Brailas <jbrailas@rns-systems.eu>
 * @version		1.6
 * @copyright   Copyright (C) 2025 Giannis Brailas. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */
 
// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die();

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Authentication\AuthenticationResponse;
use Joomla\CMS\Event\User\AuthenticationEvent;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\User\User;
use Joomla\Event\SubscriberInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\Input\Input;
use Joomla\CMS\Router\Route;
use Joomla\Http\HttpFactory;
use Joomla\CMS\User\UserHelper;
use Joomla\Utilities\ArrayHelper;

/**
 * A oauth v2.0 user adapter authentication plugin.
 *
 * @package     jbraSso.Plugins
 * @subpackage  Authentication
 * @since       1.0
 */
class PlgSystemJbraSso extends CMSPlugin
{
	private $authUrl;
    private $tokenUrl;
    private $apiUrl;
    private $clientId;
    private $app_name;
    private $app_scope;
    private $clientSecret;
	private $logout_url;
	private $acceptable_domains;
	private $frontend_sso;
	private $admin_sso;
	private $create_user;
    private $debug;
	private $redirectUri;

    public function __construct(&$subject, $config)
    {
        parent::__construct($subject, $config);

        // Load plugin parameters
        $this->authUrl = $this->params->get('auth_url', '');
        $this->tokenUrl = $this->params->get('token_url', '');
        $this->apiUrl = $this->params->get('api_url', '');
        $this->clientId = $this->params->get('client_id', '');
		$this->app_name = $this->params->get('app_name', '');
		$this->app_scope = $this->params->get('app_scope', 'openid');
        $this->clientSecret = $this->params->get('client_secret', '');
		$this->logout_url = $this->params->get('logout_url', 'https://login.microsoftonline.com/common/oauth2/v2.0/logout');
		$this->acceptable_domains = $this->params->get('acceptable_domains', '');
		$this->frontend_sso = $this->params->get('frontend_sso', false);
		$this->admin_sso = $this->params->get('admin_sso', false);
		$this->create_user = $this->params->get('create_user', false);
		$this->debug = $this->params->get('debug', false);
        
		if (Factory::getApplication()->isClient('administrator')) {
			// Redirect URI for the administrator context
			$this->redirectUri = Uri::root() . 'administrator/index.php?plugin=jbrasso&app_name=' . $this->app_name . '&task=oauthcallback';
		} else {
			// Redirect URI for the site context
			$this->redirectUri = Uri::root() . 'index.php?plugin=jbrasso&app_name=' . $this->app_name . '&task=oauthcallback';
		}
    }

    public function onAfterRoute()
    {
		// Check if the request is for your plugin
		$app = Factory::getApplication();
		$clientKey = $app->isClient('administrator') ? 'admin' : 'site';
		$input = $app->input;
		$plugin = $input->getCmd('plugin');
		$app_name = $input->getCmd('app_name');
		$task = $input->getCmd('task');
		
        // Only trigger on public pages and if the user is not logged in
        $user = Factory::getUser();
        if (!$user->guest) {
			//if the user has selected to logout
			if ($plugin === 'jbrasso' && $task === 'logout') {
				if ($this->debug) error_log('Logout requested.');
				$this->logout();
			}
            return;
        }
	
		if ($plugin === 'jbrasso' && $app_name === 'azure' && $task === 'oauthcallback') {
			$this->handleOAuthCallback();
			return;
		}
		
		// Store current URL here
		//if ($app->isClient('site') || ($app->isClient('administrator') && $this->admin_sso )) {
		
		// Save current URL to return to after login
		$uri = Uri::getInstance();
		$currentUrl = base64_encode($uri->toString());
		$app->setUserState("oauth2.returnUrl", $currentUrl);
		
		//}
		
		if ($plugin === 'jbrasso' && $app_name === 'azure' && $task === 'start') {

			// Start the login flow manually
			$this->redirectForAuthorization(Factory::getSession()->get("oauth2.state.$clientKey"));
			return;
		}
		
		// Check for a remember me cookie
		$rememberMeCookieName = 'joomla_remember_me_' . UserHelper::getShortHashedUserAgent();
		//$cookieValue = $input->cookie->get($rememberMeCookieName, null, 'raw');
		$cookieValue = isset($_COOKIE[$rememberMeCookieName]) ? $_COOKIE[$rememberMeCookieName] : null;

		if ($this->debug) error_log('jbrasso: cookieValue of remember_me is: ' . $cookieValue);

		// initialise the login authentication process if a cookie is present
		if ($cookieValue && $app->isClient('site') && $this->frontend_sso) {

			if ($this->debug) error_log('jbrasso: cookieValue of remember_me is found.');
			
			$decodedValue = base64_decode($cookieValue, true);
			if ($this->debug) error_log('jbrasso: decodedValue is: ' . $decodedValue);
        	
			if ($decodedValue && strpos($decodedValue, ':') !== false) {

				// Parse the cookie value
				list($series, $token) = explode(':', $decodedValue, 2);

				// Fetch the stored token from the database
				$result = $this->validateRememberMeToken($series, $token);
				
				if ($this->debug)
					error_log('jbrasso: validateRememberMeToken result is: ' . print_r($result,true));

				if ($result && isset($result->user_id)) {
					
					$user = Factory::getUser($result->user_id);
					//ενημέρωση του χρήστη
					$user = $this->updateUser($user, null);
					$this->autoLoginUser($user);

					if ($this->debug) error_log('jbrasso: User Login ' . $result->user_id . ' succeeded using remember_me cookie.');
					return;
					
				} else {
					// Invalid cookie, clear it
					$input->cookie->set($rememberMeCookieName, '', time() - 3600, '/');
					if ($this->debug) error_log('jbrasso: Invalid remember_me cookie.');
				}
			}
			$input->cookie->set($rememberMeCookieName, '', time() - 3600, '/');
		}
		
       
		//in frontend always and in backend only if the checkbox admin_sso is clicked
		if ( ($app->isClient('site') && $this->frontend_sso) || ($app->isClient('administrator') && $this->admin_sso )) {
			
			// Check if we have valid tokens
			$tokens = $this->loadTokens();
			if ($tokens) {
				if ($this->isAccessTokenValid($tokens)) {

					// Access token is valid; proceed with user login
					$this->processUserSession($tokens);
					return;
				}

				// Access token expired; attempt to refresh
				if (!empty($tokens['refresh_token'])) {
					$this->handleTokenRefresh($tokens['refresh_token']);
					return;
				}
			}
			
			 // else: No valid tokens; Redirect to the OAuth 2.0 authorization server
			// Redirect to OAuth2 provider
			$this->redirectForAuthorization(Factory::getSession()->get("oauth2.state.$clientKey"));
		}
    }
	
	private function isAccessTokenValid($tokens)
	{
		if (empty($tokens['access_token']) || empty($tokens['expires_in']) || empty($tokens['created_at'])) {
			// Token data is incomplete
			if ($this->debug) error_log('jbrasso: Token data is incomplete.');
			return false;
		}

		// Ensure 'created_at' and 'expires_in' are integers
		$updatedAt = strtotime($tokens['created_at']);
		$expiresIn = (int) $tokens['expires_in'];

		if ($this->debug) {
			error_log('jbrasso: Token details - Created at: ' . $tokens['created_at']);
			error_log('jbrasso: Token details - Expires in: ' . $expiresIn);
		}

		// Validate 'created_at' and 'expires_in'
		if ($updatedAt <= 0 || $expiresIn <= 0) {
			if ($this->debug) {
				error_log('jbrasso: Invalid token timestamps: created_at=' . $updatedAt . ', expires_in=' . $expiresIn);
			}
			return false;
		}

		// Calculate expiration time
		$currentTime = time(); // Current time in seconds
		$expirationTime = $updatedAt + $expiresIn; // When the token expires

		// Add a buffer to handle small clock differences
		$bufferTime = 60 * 5; // 5-minute buffer
		if ($currentTime >= $expirationTime - $bufferTime) {
			// Token has expired
			if ($this->debug) {
				error_log('jbrasso: Access token has expired or is about to expire.');
				error_log('jbrasso: Current time: ' . $currentTime . ', Expiration time: ' . $expirationTime);
			}
			return false;
		}

		// Token is still valid
		if ($this->debug) error_log('jbrasso: Access token is valid.');
		return true;
	}

	/**
	 * Validate the Remember Me token.
	 *
	 * @param string $series The series value from the cookie.
	 * @param string $token The token value from the cookie.
	 * @return object|null Returns the user object if the token is valid, or null if invalid.
	 */
	private function validateRememberMeToken($series, $token)
	{
		if ($this->debug) error_log('jbrasso: validateRememberMeToken function initialized.');

		// Get the database object
		$db = Factory::getDbo();

		// Build the query to fetch the user details associated with the token
		$query = $db->getQuery(true)
			->select($db->quoteName(['user_id', 'token']))
			->from($db->quoteName('#__user_keys'))
			->where($db->quoteName('series') . ' = ' . $db->quote($series))
			->where($db->quoteName('time') . ' >= ' . $db->quote(time() - 30 * 86400)); // Token validity: 30 days

		// Execute the query
		$db->setQuery($query);

		try {
			$result = $db->loadObject();

			if ($result) {
				// Use password_verify to check if the plaintext token matches the hashed token in DB
				if (password_verify($token, $result->token)) {
					return $result;  // Valid token
				}
			}
		} catch (Exception $e) {
			if ($this->debug) error_log('Error validating Remember Me token: ' . $e->getMessage());
		}

		return null; // Token is invalid or expired
	}
	
	private function handleTokenRefresh($refreshToken)
	{
		$newTokens = $this->refreshAccessToken($refreshToken);

		if ($newTokens) {
			
			// proceed with user info processing, saving tokens and login
			$this->processUserSession($newTokens);
			
		} else {
			if ($this->debug) error_log('Failed to refresh tokens.');
			$this->redirectWithError('Failed to refresh access token. Please log in again.');
		}
	}
	
	private function processUserSession($tokens)
	{
		$app = Factory::getApplication();
		$clientKey = $app->isClient('administrator') ? 'admin' : 'site';
		$user = $this->processUserInfo($tokens);

		if (!empty($user->id)) {
			$this->saveTokens($user->id, $tokens);
			$this->autoLoginUser($user);
			Factory::getSession()->set("oauth2.retry.$clientKey", false);
		} else {
			if ($this->debug) error_log('Failed to retrieve user info for valid tokens.');
			//$this->redirectWithError('Failed to retrieve user info for valid tokens. Please log in again.');
			$app->enqueueMessage('Failed to retrieve user info for valid tokens.', 'error');
		}
	}

    private function handleOAuthCallback()
    {
		$app = Factory::getApplication();
		$clientKey = $app->isClient('administrator') ? 'admin' : 'site';
		$session = Factory::getSession();
        $input = $app->input;
        $authCode = $input->getString('code');
        $state = $input->getString('state');
		$storedState = $session->get("oauth2.state.$clientKey"); //New 29-7-2025
		$retryFlag = $session->get("oauth2.retry.$clientKey", false); //New 29-7-2025
		
		if ($this->debug) {
			error_log('--- jbrasso: handleOAuthCallback START ---');
			error_log('Request URI: ' . (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'N/A'));
			error_log('Redirect URI expected by plugin: ' . $this->redirectUri);
			error_log('PHP session_name: ' . session_name());
			error_log('PHP session_id: ' . session_id());
			error_log('$_COOKIE keys: ' . implode(', ', array_keys($_COOKIE)));
			error_log('Raw $_COOKIE: ' . print_r($_COOKIE, true));
			error_log('Incoming state param: ' . (isset($_GET['state']) ? $_GET['state'] : 'NULL'));
			error_log('Session stored (oauth2.state.' . $clientKey . '): ' . $session->get("oauth2.state.$clientKey"));
			error_log('Session retry flag (oauth2.retry.' . $clientKey . '): ' . var_export($session->get("oauth2.retry.$clientKey", false), true));
			error_log('SESSION array: ' . print_r($_SESSION, true));
			error_log('--- jbrasso: handleOAuthCallback DEBUG END ---');
		}
		
		if ((empty($state) || empty($storedState) || $state !== $storedState)) {

			if ($this->debug) {
				error_log("Invalid state. Got: $state, Expected: $storedState");
			}
			
			if (!$retryFlag) {

				$session->set("oauth2.retry.$clientKey", true);

				// Only retry with NON-EMPTY existing state
				if (!empty($storedState)) {
					$this->redirectForAuthorization($storedState);
				} else {
					// No stored state = start clean
					$this->redirectForAuthorization();
				}

				return;
			}

			// If already retried once, stop and show error
			$app->enqueueMessage('Invalid state parameter.', 'error');
			return;
		}
		
		// authorization code provided
		if ($authCode) {

			// Fetch access token using the authorization code
			$tokenData = $this->fetchAccessToken($authCode);
			
			//if no tokenData found
			if (!$tokenData) {
				
				if ($this->debug) error_log('No tokenData found!');
				
				$useState = $state ?: $storedState;
				
				// Redirect to authorization endpoint for a new code
				$authUrl = $this->authUrl . '?' . http_build_query([
					'response_type' => 'code',
					'client_id' => $this->clientId,
					'redirect_uri' => $this->redirectUri,
					'state' => $useState,
					'scope' => $this->app_scope,
				]);
				
				$app->redirect($authUrl);
			} 
			else {

				if ($this->debug)  error_log('tokenData found');
				
				// proceed with user info processing, saving tokens and login
				$this->processUserSession($tokenData);
				
			}
		
		} else {
			// No authorization code provided, check for an existing token
			$tokens = $this->loadTokens();
			
			if ($tokens) {
				if (!$this->isAccessTokenValid($tokens)) {
					
					if ($this->debug) Factory::getApplication()->enqueueMessage('access token is not valid.', 'error');
					
					// Access token expired, try refreshing it
					$newTokens = $this->refreshAccessToken($tokens['refresh_token']);

					if ($newTokens) {
						// proceed with user info processing, saving tokens and login
						$this->processUserSession($newTokens);

					} else {
						// Failed to refresh tokens, require re-authorization
						$app->enqueueMessage('Failed to refresh access token. Please log in again.', 'error');
						
						$useState = $state ?: $storedState;
						
						$authUrl = $this->authUrl . '?' . http_build_query([
							'response_type' => 'code',
							'client_id' => $this->clientId,
							'redirect_uri' => $this->redirectUri,
							'state' => $useState,
							'scope' => $this->app_scope,
						]);
						
						$app->redirect($authUrl);
					}
				} else {
					// Access token is valid
					// proceed with user info processing, saving tokens and login
					$this->processUserSession($tokens);
					
				}	
			} else {
				if ($this->debug) error_log('No access token found');
				// No token available, require authorization
				$app->enqueueMessage('No access token found. Please log in.', 'error');
				
				$useState = $state ?: $storedState;
				
				$authUrl = $this->authUrl . '?' . http_build_query([
					'response_type' => 'code',
					'client_id' => $this->clientId,
					'redirect_uri' => $this->redirectUri,
					'state' => $useState,
					'scope' => $this->app_scope,
				]);
				$app->redirect($authUrl);
			}
		}
    }
	
	private function processUserInfo($tokenData)
	{
		if ($this->debug) error_log('processUserInfo executed');

		$accessToken = $tokenData['access_token'];
		
		try {

			// Make a request to the OAuth provider to get user information
			$ch = curl_init($this->apiUrl);
			curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
			curl_setopt( $ch, CURLOPT_ENCODING, "" );
			curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
			curl_setopt( $ch, CURLOPT_AUTOREFERER, true );
			curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
			curl_setopt( $ch, CURLOPT_MAXREDIRS, 10 );
			curl_setopt( $ch, CURLOPT_POST, false);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array(
				'Authorization: Bearer '.$accessToken,
				'User-Agent:web'
				));		
			$content = curl_exec($ch);
			
			//Factory::getApplication()->enqueueMessage('Authorization header: ' . print_r($headers, true), 'message');
			//Factory::getApplication()->enqueueMessage('Formatted headers: ' . implode(', ', $headers), 'message');
					
			 // Check if the response has the status code property
			//if (!isset($response->code) || $response->code != 200) {
			if(curl_error($ch)){
				Factory::getApplication()->enqueueMessage('Failed to retrieve user information. HTTP Code: ' . curl_error($ch), 'error');
				//Factory::getApplication()->enqueueMessage('Failed to retrieve user information. HTTP Code: ' . (isset($response->code) ? $response->code : 'N/A'), 'error');
				//Factory::getApplication()->enqueueMessage('Response body: ' . print_r($response->body, true), 'error');
				return false;
			}
			
			//Factory::getApplication()->enqueueMessage('Response body: ' . print_r($content, true), 'error');

			//$userInfo = json_decode($response->body, true);
			$userInfo = json_decode($content, true);
			
			//Factory::getApplication()->enqueueMessage('Response body: ' . print_r($userInfo, true), 'error');

			if (empty($userInfo)) {
				Factory::getApplication()->enqueueMessage('Invalid user information received.', 'error');
				return false;
			}
			elseif (isset($userInfo['error_description'])) {
                Factory::getApplication()->enqueueMessage($userInfo['error_description'], 'error');
                return false;
            }
			elseif (isset($userInfo['error'])) {
                Factory::getApplication()->enqueueMessage($userInfo['error'], 'error');
                return false;
            }

			//find the user
			//$user = $this->getUserByEmail($userInfo['mail']);
			$user = $this->getUserAndCheck($userInfo);
			
			// Process the user information (e.g., create or update user)
			if (empty($user)) {
				// User does not exist; create a new user
				$user = $this->createUser($userInfo);
			} else {
				// User exists; update user information if necessary
				$user = $this->updateUser($user, $userInfo);
				
			}

			if (!empty($user)) {
				return $user;
			}
			else {
				Factory::getApplication()->enqueueMessage('user data is empty.');
				return false;
			}
			
		} catch (Exception $e) {
            Factory::getApplication()->enqueueMessage($e->getMessage(), 'error');
            return false;
        }
	}
	
	
	private function updateUser($user, $userInfo) {
		if ($this->debug) error_log('updateUser executed\n');
		
		//if the user object has an id
		if (!empty($user->id)) {
			
			//find if the Azure Entra user is disabled.
			$block = 0;
			if (!empty($userInfo['accountEnabled'])) {
				if ($userInfo['accountEnabled'] != 1) 
					$block = 1;
			}
			
			//update users table
			$usr = new stdClass();
			$usr->id = $user->id;
			if (!empty($userInfo['surname']) && !empty($userInfo['givenName']))
				$usr->name = $userInfo['surname'] . " " . $userInfo['givenName'];
			$usr->block = $block;
			$usr->lastvisitDate = date("Y-m-d H:i:s");
			
			Factory::getDbo()->updateObject('#__users', $usr, "id");
			
			//get ip address and pc name
			$input = new Input($_SERVER);
			//$remoteUser = $input->get('REMOTE_USER', null, 'USERNAME'); //only with kerberos shmanic sso/ldap
			$ipaddress = $input->get('REMOTE_ADDR', null, 'REMOTE_ADDR');
			$pc_name = gethostbyaddr($ipaddress);
			unset($input);
			
			//get id from ppcr_user_info table
			$db = Factory::getDbo();
			$query = $db->getQuery(true);
			$query	->select("id")
					->from('#__ppcr_user_info')
					->where('userid = ' . (int) $user->id);
			$db->setQuery($query);		
			$user_info_id = $db->loadResult();
				
			if (!empty($user_info_id)) {
				
				//update ppcr_user_info table
				$usr_info = new stdClass();
				$usr_info->id = $user_info_id;
				if (!empty($userInfo['surname']) && !empty($userInfo['givenName']))
					$usr_info->name = $userInfo['surname'] . " " . $userInfo['givenName'];
				$usr_info->disabled = $block;
				if (!empty($userInfo['displayName']))
					$usr_info->en_name = $userInfo['displayName'];
				if (!empty($userInfo['mobilePhone']))
					$usr_info->mobile = $userInfo['mobilePhone'];
				if (!empty($userInfo['businessPhones'][0]))
					$usr_info->tel1 = $userInfo['businessPhones'][0];
				if (!empty($userInfo['mail'])) {
					
					if (str_contains($userInfo['mail'], 'ppcr.gr')) {
						$usr_info->email1 = $userInfo['mail'];
						$usr_info->email1_license = 1;
					}
					else {
						$usr_info->email2 = $userInfo['mail'];
						$usr_info->email2_license = 1;
					}
				}
				
				//save ip address and pc name
				if (isset($ipaddress)) {   //if there is an ip address
					//and if the ip address is local and if the lastvisitDate is older than 1 day
					//if (str_contains($ipaddress, '10.10.10.') && (strtotime($user->lastvisitDate) < strtotime('-1 day')) ) { 
					if (str_contains($ipaddress, '10.10.10.')) {
						$usr_info->ipaddress = $ipaddress;
						$usr_info->lastlogin = date("Y-m-d H:i:s");
						$usr_info->pcname = $pc_name;
					}
				}
			
				Factory::getDbo()->updateObject('#__ppcr_user_info', $usr_info, "id");	
			}
		}
		return $user;
	}
	
	private function createUser($userInfo) {
		if ($this->debug) error_log('createUser executed\n');
		
		if (!$this->create_user) {
			if ($this->debug) error_log('createUser option is unchecked!\n');
			Factory::getApplication()->enqueueMessage('The option to create new user account is disabled. If you want access inform the IT.', 'error');
			return;
		}
		
		$db = Factory::getDbo();
		
        if (!empty($userInfo) && (str_ends_with($userInfo['mail'], '@ppcr.gr') || str_ends_with($userInfo['mail'], '@ppcgroup.com'))) {
            // If user doesn't exist, create a new Joomla user
            $user = new User();
            $user->email = $userInfo['mail'];
            $user->name = $userInfo['surname'] . " " . $userInfo['givenName'];
            $user->username = $userInfo['userPrincipalName'];
			$user->lastvisitDate = date("Y-m-d H:i:s");
			$user->groups = [2]; //default group is registered
            //$user->password_clear = UserHelper::genRandomPassword(12); // NO!

            if (!$user->save()) {
                Factory::getApplication()->enqueueMessage('Failed to create user account.', 'error');
                return;
            }
			
			//write english name of the user
			if ($userInfo['displayName'])
				$en_name = $userInfo['displayName'];
			else
				$en_name = $user->name;
			
			// Escape the name to prevent SQL injection
			$escaped_en_name = $db->quote($en_name);
			
			//then insert the user at __ppcr_user_info
			
			$query = $db->getQuery(true);
			
			//if the email belongs to ppcr domain then insert it to column username
			if (str_ends_with($user->email, '@ppcr.gr')) {
				$query
					->insert($db->quoteName('#__ppcr_user_info'))
					->columns($db->quoteName(['userid', 'email1', 'email1_license', 'name', 'en_name', 'disabled']))
					->values(implode(',', [
						(int) $user->id,
						$db->quote($user->email),
						1,
						$db->quote($user->name),
						$escaped_en_name,
						(int) $user->block
					]));
			} // if the email DOES NOT belong to ppcr domain then insert it to email2
			else {
				//$query = 'INSERT INTO ' . $db->quoteName('#__ppcr_user_info') . 
				//	' (userid, email2, email2_license, name, en_name, disabled) select id, email, 1, name, ' . $escaped_en_name . ', block from ' . 
				//	$db->quoteName('#__users') . 
				//	' where id not in (select userid from ' . $db->quoteName('#__ppcr_user_info')  . ')';	
				$query
					->insert($db->quoteName('#__ppcr_user_info'))
					->columns($db->quoteName(['userid', 'email2', 'email2_license', 'name', 'en_name', 'disabled']))
					->values(implode(',', [
						(int) $user->id,
						$db->quote($user->email),
						1,
						$db->quote($user->name),
						$escaped_en_name,
						(int) $user->block
					]));
			}
			
			try {
				$db->setQuery($query);
				$db->execute();
			}
			catch (Exception $e) {
				//Factory::getApplication()->enqueueMessage($e->getMessage(), 'error');
				error_log($e->getMessage());
				//$errors .= " (1) \n";
			}
        }
		else {
               Factory::getApplication()->enqueueMessage('userInfo not found.', 'error');
               return;
            }
		
		return $user;
	}

    private function autoLoginUser($user)
    {
		if ($this->debug) error_log('autoLoginUser executed\n');
        $app = Factory::getApplication();
		$clientKey = $app->isClient('administrator') ? 'admin' : 'site'; //New 29-7-2025

		if ($user instanceof User) {
			// Ensure the user object is properly loaded
			$user->set('guest', 0);
			$user->set('aid', 1); // Access level, adjust as needed
			
			// Assign the user's ACL groups
			$user->set('groups', $user->getAuthorisedGroups());

			// Ensure required fields exist
			if (!$user->get('language')) {
				$user->set('language', $app->getLanguage()->getTag());
			}

			if (!$user->get('timezone')) {
				$user->set('timezone', $app->get('offset')); // Joomla default timezone
			}
			
			$app->loadIdentity($user);
			
			// Store the user in the session
			$session = Factory::getSession();
			$session->set('user', $user);
			$app->set('user', $user);

			// Prepare the login response
			$options = [];
			$response = [
				'username' => $user->username,
				'fullname' => $user->name,
				'email'    => $user->email,
				'language' => $user->language,
				'status'   => 'success',
				'user'     => $user,
				'action'   => 'login',
			];

			// Trigger the onUserLogin event
			$results = $app->triggerEvent('onUserAfterLogin', [$response, $options]);

			// Check if login event plugins processed the request
			if (in_array(false, ArrayHelper::toInteger($results), true)) {
				if ($this->debug) error_log("Failed to trigger login event");
				$app->enqueueMessage('Failed to trigger login event.', 'error');
				return false;
			} else {
				
				// After successful login
				$returnUrl = $app->getUserState("oauth2.returnUrl");
				$app->setUserState("oauth2.returnUrl", null); // Clear returnUrl
				$app->setUserState("oauth2.retry.$clientKey", null); // Clear retry
				$app->setUserState("oauth2.state.$clientKey", null); // Clear state
				
				// Determine the redirection URL based on context
				if ($app->isClient('administrator')) {
					
					if ($returnUrl) {
						$decodedUrl = base64_decode($returnUrl);
						$app->redirect($decodedUrl);
					} else {
						// Redirect to the admin dashboard
						$adminUrl = Uri::root() . 'administrator/index.php';
						$app->redirect(Route::_($adminUrl));
					}
				} else {
					
					//after successful login set the remember me cookie manually
					// Generate the series and token
					$db = Factory::getDbo();
					$series = UserHelper::genRandomPassword(20);
					$token = UserHelper::genRandomPassword(20);
					$hashedToken = UserHelper::hashPassword($token);
					$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

					// Check if an entry already exists for this user
					$query = $db->getQuery(true);
					$query->select('id') // Only need the ID
							->from($db->quoteName('#__user_keys'))
							->where($db->quoteName('user_id') . ' = ' . $db->quote($user->id));
					$db->setQuery($query);
					$existingEntry = $db->loadResult();

					if ($existingEntry) {
						// Delete the existing entry
						$deleteQuery = $db->getQuery(true);
						$deleteQuery->delete($db->quoteName('#__user_keys'))
									->where($db->quoteName('user_id') . ' = ' . $db->quote($user->id));
						$db->setQuery($deleteQuery);
						$db->execute();
						if ($this->debug) error_log('jbrasso: Existing remember me token deleted for user ' . $user->id);
					}

					// Insert into the database
					$query = $db->getQuery(true)
						->insert($db->quoteName('#__user_keys'))
						->columns($db->quoteName(['user_id', 'series', 'token', 'time', 'uastring']))
						->values(implode(',', [
							(int) $user->id,
							$db->quote($series),
							$db->quote($hashedToken),
							$db->quote(time()),
							$db->quote($userAgent)
						]));
					$db->setQuery($query);
					$db->execute();

					// Set the cookie
					$rememberMeCookieName = 'joomla_remember_me_' . UserHelper::getShortHashedUserAgent();
					$cookieValue = base64_encode($series . ':' . $token);
					$cookieExpiry = time() + 30 * 86400;
					$cookiePath = '/';
					
					// Use setcookie() directly
					setcookie(
						$rememberMeCookieName,
						$cookieValue,
						[
							'expires' => $cookieExpiry,
							'path' => $cookiePath,
							'secure' => true, // Essential if using HTTPS
							'httponly' => true, // Recommended for security
							'samesite' => 'Lax', // Or 'Strict' if needed
						]
					);
					//old way: doesn't set secure and httponly
					//$app->input->cookie->set($rememberMeCookieName, $cookieValue, time() + 30 * 86400, '/');

					if ($this->debug) error_log('jbrasso: Login succeeded and remember_me cookie has been set.');
					
					if ($returnUrl) {
						$decodedUrl = base64_decode($returnUrl);
						$app->redirect($decodedUrl);
					} else {
						// Redirect to the main site homepage
						$siteUrl = Uri::base();
						$app->redirect(Route::_($siteUrl));
					}
				}
				
				return $user;
			}
			
		} else {
			// Handle error: User object is invalid
			error_log("Failed to auto-login user: Invalid user object");
			Factory::getApplication()->enqueueMessage('Failed to auto-login user: Invalid user object.', 'error');
			return false;
		}
    }


	private function getUserAndCheck($userInfo)
	{
		if ($this->debug) error_log('getUserAndCheck executed\n');
		
		if (!$this->acceptable_domains) 
			return null;
		
		$email = $userInfo['mail'];
		$employeeId = $userInfo['employeeId'];
		
		// Split the domain list string into an array of domains
		$acceptable_domains = explode(',', $this->acceptable_domains);
		
		// Trim whitespace from each domain
		$acceptable_domains = array_map('trim', $acceptable_domains);
		
		// Check if the email contains @
		if (strpos($email, '@') !== false) {
			
			// Split the email into username and domain parts
			list($username, $userDomain) = explode('@', $email, 2);

			// Check if the user's domain is in the allowed list
			if (in_array($userDomain, $acceptable_domains)) {
				
				// Username belongs to an allowed domain
				
				// Get the database object
				$db = Factory::getDbo();

				// Query the user by email1 or email2
				$query = $db->getQuery(true)
					->select('userid')
					->from($db->quoteName('#__ppcr_user_info'))
					->where(
						$db->quoteName('email1') . ' = ' . $db->quote($email)
						. ' or ' . $db->quoteName('email2') . ' = ' . $db->quote($email)
						//. ' or ' . $db->quoteName('username') . ' = ' . $db->quote($username)
						//. ' or ' . $db->quoteName('username2') . ' = ' . $db->quote($username)
					);
				$db->setQuery($query);
				$userid = $db->loadResult();
				
				//if a user is found in ppcr_user_info table:
				if ($userid) {
					$query = $db->getQuery(true)
						->select('*')
						->from($db->quoteName('#__users'))
						->where($db->quoteName('id') . ' = ' . $db->quote($userid))
						->where($db->quoteName('block') . ' != 1');
					$db->setQuery($query);
					$userData = $db->loadAssoc();
					//error_log("userData :" . print_r($userData,true));
					
					if ($userData) {
						$userData["params"] = array(); //Add empty params array for user object.
						
						// Load the user object
						$user = new User();
						$user->bind($userData);
						return $user;
					}
				}
			} else {
				if ($this->debug) error_log("Domain not allowed: " . $userDomain);
				return null;
			}
		} else {
			if ($this->debug) error_log("Not an email: " . $email);
			return null;
		}
		
		if ($this->debug) error_log("User not found for email: " . $email);
		return null;
	}
	
	private function getUserByEmail($email)
	{
		if ($this->debug) error_log('getUserByEmail executed\n');
		
		// Get the database object
		$db = Factory::getDbo();

		// Query the user by email
		$query = $db->getQuery(true)
			->select('*')
			->from($db->quoteName('#__users'))
			->where($db->quoteName('email') . ' = ' . $db->quote($email));
		$db->setQuery($query);

		// Load the result
		$userData = $db->loadAssoc();
		//error_log("userData :" . print_r($userData,true));
		
		if ($userData) {
			$userData["params"] = array();
			
			// Load the user object
			$user = new User();
			$user->bind($userData);
			return $user;
		}

		return null; // User not found
	}

    private function redirectForAuthorization($state = null)
    {
		$app = Factory::getApplication();
		$clientKey = $app->isClient('administrator') ? 'admin' : 'site';
		$session = Factory::getSession();
		
		// Always try to reuse an existing state
		$storedState = $session->get("oauth2.state.$clientKey");
	
		if (empty($state)) {
			if (!empty($storedState)) {
				// Reuse existing state
				$state = $storedState;
			} else {
				// Generate new state
				$state = bin2hex(random_bytes(16)); // Generate a random state to prevent CSRF
				$session->fork(false); // prevents Joomla 6 session regeneration
				$session->set("oauth2.state.$clientKey", $state); //NEW 29-07-2025
			}
		} else {
			// Ensure state is stored
			$session->set("oauth2.state.$clientKey", $state);
		}

        $authorizeUrl = $this->authUrl . '?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => $this->app_scope,
            'state' => $state,
        ]);

        $app->redirect($authorizeUrl);
    }
	
	private function redirectWithError($message)
	{
		$app = Factory::getApplication();
		$clientKey = $app->isClient('administrator') ? 'admin' : 'site';
		$app->enqueueMessage($message, 'error');
		
		$this->redirectForAuthorization(Factory::getSession()->get("oauth2.state.$clientKey"));
	}

	private function fetchAccessToken($authCode)
	{
		if ($this->debug) error_log("fetchAccessToken executed");
		
		// Log the authCode to check if it's being passed correctly
		if ($this->debug) error_log("Auth Code: " . print_r($authCode, true));

		$httpFactory = new HttpFactory(); // Create an instance of the HttpFactory
		$http = $httpFactory->getHttp(); // Create the HTTP client instance
		$postFields = [
			'grant_type' => 'authorization_code',
			'code' => $authCode,
			'redirect_uri' => $this->redirectUri,
			'scope' => $this->app_scope,
			'client_id' => $this->clientId,
			'client_secret' => $this->clientSecret,
		];

		try {
			// Log before making the request
			if ($this->debug) error_log("Sending request to tokenUrl: " . $this->tokenUrl);

			$response = $http->post($this->tokenUrl, $postFields);
			
			// Log the full response body for debugging
			if ($this->debug) error_log("Full Response: " . print_r($response, true));

			// Log the response status code
			if ($this->debug) error_log("HTTP Status Code: " . $response->status);

			// Decode the response body
			$body = method_exists($response, 'getBody') // Joomla 4/5/6
				? $response->getBody()
				: $response->body;

			$tokenData = json_decode($body, true);

			// Log the decoded token data
			if ($this->debug) error_log("Decoded Token Data: " . print_r($tokenData, true));

			if (isset($tokenData['error'])) {
				Factory::getApplication()->enqueueMessage($tokenData['error'], 'error');
				return false;
			} elseif (isset($tokenData['error_description'])) {
				Factory::getApplication()->enqueueMessage($tokenData['error_description'], 'error');
				return false;
			}

			return $tokenData;
		} catch (Exception $e) {
			error_log("Error fetching: " . $e->getMessage());
			Factory::getApplication()->enqueueMessage($e->getMessage(), 'error');
			return false;
		}
	}

	private function refreshAccessToken($refreshToken)
	{
		$http = HttpFactory::getHttp();

		$response = $http->post($this->tokenUrl, [
			'refresh_token' => $refreshToken,
			'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
			'grant_type' => 'refresh_token',
		]);

		$body = method_exists($response, 'getBody') // Joomla 4/5/6
				? $response->getBody()
				: $response->body;
				
		$data = json_decode($body, true);

		if (isset($data['error'])) {
			Factory::getApplication()->enqueueMessage('OAuth2 error: ' . $data['error_description'], 'error');
			return false;
		}

		// Return new access token
		return $data;
	}
	
	private function saveTokens($userId, $tokenData)
	{
		//Factory::getApplication()->enqueueMessage(print_r($tokenData, true), 'message');
		if ($this->debug) error_log('saveTokens executed');
		// Ensure the tokenData array has all necessary keys
		$db = Factory::getDbo();
		$query = $db->getQuery(true);
		
		if (empty($userId)) {
			Factory::getApplication()->enqueueMessage('User is not logged in.', 'error');
			return; // Stop execution if user is not authenticated
		}	
		
		// Check if a record already exists for the user
		$query
			->clear()
			->select('id')
			->from($db->quoteName('#__jbrasso_oauth_tokens'))
			->where($db->quoteName('user_id') . ' = ' . $db->quote($userId));
		
		$db->setQuery($query);
		$existingRecord = $db->loadResult();

		if ($existingRecord) {
			// Update the existing record
			$query
				->clear()
				->update($db->quoteName('#__jbrasso_oauth_tokens'))
				->set($db->quoteName('access_token') . ' = ' . $db->quote($tokenData['access_token']))
				->set($db->quoteName('refresh_token') . ' = ' . (isset($tokenData['refresh_token']) ? $db->quote($tokenData['refresh_token']) : 'NULL'))
				->set($db->quoteName('expires_in') . ' = ' . $db->quote($tokenData['expires_in']))
				->set($db->quoteName('updated_at') . ' = ' . $db->quote(date('Y-m-d H:i:s')))
				->where($db->quoteName('user_id') . ' = ' . $db->quote($userId));
		} else {	
			// Insert a new record if none exists
			
			// Prepare the data for insertion/updating
			$columns = ['user_id', 'access_token', 'refresh_token', 'expires_in', 'created_at', 'updated_at'];
			$values = [
				$db->quote($userId),
				$db->quote($tokenData['access_token']),
				isset($tokenData['refresh_token']) ? $db->quote($tokenData['refresh_token']) : 'NULL',
				isset($tokenData['expires_in']) ? $db->quote($tokenData['expires_in']) : 0,
				$db->quote(date('Y-m-d H:i:s')),
				$db->quote(date('Y-m-d H:i:s'))
			];

			// Construct the SQL query for insertion
			$query
				->clear()
				->insert($db->quoteName('#__jbrasso_oauth_tokens'))
				->columns($db->quoteName($columns))
				->values(implode(',', $values));
		}
		
		try {
			// Execute the query
			$db->setQuery($query);
			$db->execute();
		} catch (\RuntimeException $e) {
			Factory::getApplication()->enqueueMessage('Error saving tokens: ' . $e->getMessage(), 'error');
			throw new Exception('Error saving tokens: ' . $e->getMessage());
		}
	}

	private function loadTokens()
	{
		$db = Factory::getDbo();
		
		if ($this->debug) error_log('jbrasso: loadTokens executed');
		$user = Factory::getUser();
		
		if (is_object($user) && isset($user->id)) {
			$userId = (int) $user->id;
		} //check for Kerberos remote_user variable
		elseif (!empty($_SERVER['REMOTE_USER']) && empty($user->id)) {
			$username = $_SERVER['REMOTE_USER'];
			$query = $db->getQuery(true);
			$query->select('id')
				->from('#__users')
				->where('username = ' . $db->quote($username));
			$db->setQuery($query);
			$userId = $db->loadResult();
		}
		else {
			//$userId = 0;
			if ($this->debug) {
				error_log('jbrasso: loadTokens aborted. No user ID available.');
			}
			return null;
		}
				
		// Load tokens (e.g., from a database or session)
		$query = $db->getQuery(true);
		$query->select('*')
			->from('#__jbrasso_oauth_tokens')
			->where('user_id = ' . (int) $userId);
		$db->setQuery($query);
		$result = $db->loadAssoc();
		
		if ($this->debug) {
			error_log('jbrasso: loadTokens loaded: ' . print_r($result, true));
		}
		return $result ?: null;
	}
	
	public function logout()
	{		
		$app = Factory::getApplication();
		
		// Clear stored tokens
		$this->clearTokens(); 
		
		// Clear Joomla session
		$session = Factory::getSession();
		$session->destroy(); // Destroys the Joomla session
		if ($this->debug) error_log('User session has been destroyed.');
		
		// Construct the remember me cookie name
		$rememberMeCookieName = 'joomla_remember_me_' . UserHelper::getShortHashedUserAgent();

		// Destroy the cookie by setting it with an expired time
		$app->input->cookie->set($rememberMeCookieName, '', time() - 3600, '/');

		if ($this->debug) {
			error_log('Remember Me cookie destroyed on logout.');
		}
		
		//Build logout URL for Microsoft
		$logoutUrl = $this->logout_url;
		$postLogoutRedirectUri = Uri::root() . '?plugin=jbrasso&task=logout';
		$redirectUrl = $logoutUrl . '?post_logout_redirect_uri=' . urlencode($postLogoutRedirectUri);

		// Redirect the user to logout
		$app->redirect($redirectUrl);
	}
	
	protected function clearTokens()
	{
		if ($this->debug) error_log('Clearing tokens from storage.');

		// Example: Delete tokens from the database
		$user = Factory::getUser();

		if ($user && !$user->guest) {
			$db = Factory::getDbo();
			$query = $db->getQuery(true)
				->delete($db->quoteName('#__jbrasso_oauth_tokens'))
				->where($db->quoteName('user_id') . ' = ' . (int)$user->id);
			$db->setQuery($query);
			$db->execute();

			$query = $db->getQuery(true)
				->delete($db->quoteName('#__user_keys'))
				->where($db->quoteName('user_id') . ' = ' . $db->quote($user->id));
			$db->setQuery($query)->execute();
		}
	}
	
}
