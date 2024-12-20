<?php
/**
 * @package     jbraSso.Plugins
 * @author      Giannis Brailas <jbrailas@rns-systems.eu>
 * @copyright   Copyright (C) 2024 Giannis Brailas. All rights reserved.
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
    private $clientSecret;
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
		$input = Factory::getApplication()->input;
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
				return;
			}
            return;
        }
	
		if ($plugin === 'jbrasso' && $app_name === 'azure' && $task === 'oauthcallback') {
			$this->handleOAuthCallback();
			return;
		}
		
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

        // No valid tokens; Redirect to the OAuth 2.0 authorization server
		$this->redirectForAuthorization(Factory::getSession()->get('oauth2.state'));
    }
	
	private function isAccessTokenValid($tokens)
	{
		if (empty($tokens['access_token']) || empty($tokens['expires_in']) || empty($tokens['created_at'])) {
			// Token data is incomplete
			if ($this->debug) error_log('Token data is incomplete.');
			return false;
		}

		// Calculate expiration time
		$currentTime = time(); // Current time in seconds
		$expirationTime = $tokens['created_at'] + $tokens['expires_in']; // When the token expires

		if ($currentTime >= $expirationTime) {
			// Token has expired
			if ($this->debug) error_log('Access token has expired.');
			return false;
		}

		// Token is still valid
		if ($this->debug) error_log('Access token is valid.');
		return true;
	}
	
	private function handleTokenRefresh($refreshToken)
	{
		$newTokens = $this->refreshAccessToken($refreshToken);

		if ($newTokens) {
			
			// proceed with user info processing, saving tokens and login
			$this->processUserSession($newTokens);
			
			/*
			$user = $this->processUserInfo($newTokens);

			if (!empty($user->id)) {
				$this->saveTokens($user->id, $newTokens);
				$this->autoLoginUser($user);
			} else {
				if ($this->debug) error_log('Failed to retrieve user info after token refresh.');
				 //$this->redirectForAuthorization();
				//$this->redirectForAuthorization(Factory::getSession()->get('oauth2.state'));
				$this->redirectWithError('Failed to process user after token refresh.');
			}*/
		} else {
			if ($this->debug) error_log('Failed to refresh tokens.');
			$this->redirectWithError('Failed to refresh access token. Please log in again.');
		}
	}
	
	private function processUserSession($tokens)
	{
		$user = $this->processUserInfo($tokens);

		if (!empty($user->id)) {
			$this->saveTokens($user->id, $tokens);
			$this->autoLoginUser($user);
		} else {
			if ($this->debug) error_log('Failed to retrieve user info for valid tokens.');
			 //$this->redirectForAuthorization();
			$this->redirectForAuthorization(Factory::getSession()->get('oauth2.state'));
		}
	}

    private function handleOAuthCallback()
    {
        $input = Factory::getApplication()->input;
        $authCode = $input->getString('code');
        $state = $input->getString('state');
        $storedState = Factory::getSession()->get('oauth2.state');

        // Validate state parameter
        if ($state !== $storedState) {
            Factory::getApplication()->enqueueMessage('Invalid state parameter.', 'error');
            return;
        }
		
		// authorization code provided
		if ($authCode) {

			// Fetch access token using the authorization code
			$tokenData = $this->fetchAccessToken($authCode);
			
			//if no tokenData found
			if (!$tokenData) {
				if ($this->debug) error_log('No tokenData found!');
				// Redirect to authorization endpoint for a new code
				$authUrl = $this->authUrl . '?' . http_build_query([
					'response_type' => 'code',
					'client_id' => $this->clientId,
					'redirect_uri' => $this->redirectUri,
					'state' => $state,
				]);
				Factory::getApplication()->redirect($authUrl);
			} else {
				if ($this->debug)  error_log('tokenData found');
				// proceed with user info processing, saving tokens and login
				$this->processUserSession($tokenData);
				
				/*// Save tokens and proceed with user info processing
				$user = $this->processUserInfo($tokenData);
				if ($this->debug)  error_log("user->id is: ". $user->id);
				if (!empty($user->id))
					$this->saveTokens($user->id, $tokenData);
				// Auto-login the user after processing
				$this->autoLoginUser($user);*/
			}
		
		} else {
			// No authorization code provided, check for an existing token
			$tokens = $this->loadTokens();
			
			if ($tokens) {
				if (!$this->isAccessTokenValid($tokens)) {
					// Access token expired, try refreshing it
					$newTokens = $this->refreshAccessToken($tokens['refresh_token']);

					if ($newTokens) {
						// proceed with user info processing, saving tokens and login
						$this->processUserSession($newTokens);
						/*
						$user = $this->processUserInfo($newTokens);
						if ($this->debug) error_log("user->id is:: ". $user->id);
						if (!empty($user->id))
							$this->saveTokens($user->id, $newTokens);
						// Auto-login the user after processing
						$this->autoLoginUser($user);
						*/
					} else {
						// Failed to refresh tokens, require re-authorization
						Factory::getApplication()->enqueueMessage('Failed to refresh access token. Please log in again.', 'error');
						$authUrl = $this->authUrl . '?' . http_build_query([
							'response_type' => 'code',
							'client_id' => $this->clientId,
							'redirect_uri' => $this->redirectUri,
							'state' => $state,
						]);
						Factory::getApplication()->redirect($authUrl);
					}
				} else {
					// Access token is valid
					// proceed with user info processing, saving tokens and login
					$this->processUserSession($tokens);
					
					/*// Access token is valid, proceed with user info processing
					$user = $this->processUserInfo($tokens);
					if ($this->debug) error_log("user->id is::: ". $user->id);
					if (!empty($user->id))
						$this->saveTokens($user->id, $tokens);
					// Auto-login the user after processing
					$this->autoLoginUser($user);*/
				}	
			} else {
				if ($this->debug) error_log('No access token found');
				// No token available, require authorization
				Factory::getApplication()->enqueueMessage('No access token found. Please log in.', 'error');
				
				$authUrl = $this->authUrl . '?' . http_build_query([
					'response_type' => 'code',
					'client_id' => $this->clientId,
					'redirect_uri' => $this->redirectUri,
					'state' => $state,
				]);
				Factory::getApplication()->redirect($authUrl);
			}
		}
    }
	
	private function processUserInfo($tokenData)
	{
		if ($this->debug) error_log('processUserInfo executed');
		//$httpFactory = new HttpFactory(); // Create an instance of the HttpFactory
        //$http = $httpFactory->getHttp(); // Create the HTTP client instance
		
		//$accessToken = $tokenData['access_token'];
		//$accessToken = str_replace(PHP_EOL, '', $tokenData['access_token']);
		$accessToken = $tokenData['access_token'];
		
		//Factory::getApplication()->enqueueMessage('Access Token: ' . $accessToken, 'message');
		//debug! get access_token using the above code and test it using the following
		//curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" https://graph.microsoft.com/v1.0/me
		
		try {
			//$headers = [
			//	'Authorization' => 'Bearer ' . $accessToken,
			//	'User-Agent:web'
			//];
			
			// Make a request to the OAuth provider to get user information
			//$response = $http->get($this->apiUrl, [], $headers);
			
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

			// Process the user information (e.g., create or update user)
			$user = $this->getUserByEmail($userInfo['mail']);
			if (empty($user)) {
				// User does not exist; create a new user
				$user = $this->createUser($userInfo);
			} else {
				// User exists; update user information if necessary
				$user = $this->updateUser($user, $userInfo);
				
			}

			return $user;
			
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
				$usr_info->name = $userInfo['surname'] . " " . $userInfo['givenName'];
				$usr_info->disabled = $block;
				if (!empty($userInfo['displayName']))
					$usr_info->en_name = $userInfo['displayName'];
				if (!empty($userInfo['mobilePhone']))
					$usr_info->mobile = $userInfo['mobilePhone'];
				if (!empty($userInfo['businessPhones'][0]))
					$usr_info->tel1 = $userInfo['businessPhones'][0];
				
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
        if (!empty($userInfo)) {
            // If user doesn't exist, create a new Joomla user
            $user = new User();
            $user->email = $userInfo['mail'];
            $user->name = $userInfo['displayName'];
            $user->username = $userInfo['userPrincipalName'];
            $user->password_clear = UserHelper::genRandomPassword(12); // Temporary random password

            if (!$user->save()) {
                Factory::getApplication()->enqueueMessage('Failed to create user account.', 'error');
                return;
            }
			
			//then insert the user at __ppcr_user_info
			$db = Factory::getDbo();
			$query = $db->getQuery(true);
			$query = 'INSERT INTO ' . $db->quoteName('#__ppcr_user_info') . 
					' (userid, username, name, disabled) select id, username, name, block from ' . 
					$db->quoteName('#__users') . 
					' where id not in (select userid from ' . $db->quoteName('#__ppcr_user_info')  . ')';
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

		if ($user instanceof User) {
			// Ensure the user object is properly loaded
			$user->set('guest', 0);
			$user->set('aid', 1); // Access level, adjust as needed
			
			// Assign the user's ACL groups
			$user->set('groups', $user->getAuthorisedGroups());

			// Store the user in the session
			$session = Factory::getSession();
			$session->set('user', $user);

			// Prepare the login response
			$options = [];
			$response = [
				'username' => $user->username,
				'fullname' => $user->name,
				'email'    => $user->email,
				'status'   => 'success',
			];

			// Trigger the onUserLogin event
			$results = $app->triggerEvent('onUserLogin', [$response, $options]);

			// Check if login event plugins processed the request
			if (in_array(false, ArrayHelper::toInteger($results), true)) {
				if ($this->debug) error_log("Failed to trigger login event");
				$app->enqueueMessage('Failed to trigger login event.', 'error');
				return false;
			} else {
				// Redirect to the home page or a welcome page
				//$app->redirect(Route::_('index.php', false));
				
				// Determine the redirection URL based on context
				if ($app->isClient('administrator')) {
					// Redirect to the admin dashboard
					$adminUrl = Uri::root() . 'administrator/index.php';
					$app->redirect(Route::_($adminUrl));
				} else {
					// Redirect to the main site homepage
					$siteUrl = Uri::base();
					$app->redirect(Route::_($siteUrl));
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
		$userData["params"] = array();
		//if ($this->debug) error_log("userData :" . print_r($userData,true));

		if ($userData) {
			// Load the user object
			$user = new User();
			$user->bind($userData);
			return $user;
		}

		return null; // User not found
	}

    private function redirectForAuthorization($state)
    {
		if (empty($state)) {
			$state = bin2hex(random_bytes(16)); // Generate a random state to prevent CSRF
			Factory::getSession()->set('oauth2.state', $state);
		}

        $authorizeUrl = $this->authUrl . '?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => $this->app_scope,
            'state' => $state,
        ]);

        Factory::getApplication()->redirect($authorizeUrl);
    }
	
	private function redirectWithError($message)
	{
		Factory::getApplication()->enqueueMessage($message, 'error');
		//$this->redirectForAuthorization();
		$this->redirectForAuthorization(Factory::getSession()->get('oauth2.state'));
	}

    private function fetchAccessToken($authCode)
    {
		if ($this->debug) error_log("fetchAccessToken executed");
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
            $response = $http->post($this->tokenUrl, $postFields);
            $tokenData = json_decode($response->body, true);

            if (isset($tokenData['error'])) {
                Factory::getApplication()->enqueueMessage($tokenData['error'], 'error');
                return false;
            }elseif (isset($tokenData['error_description'])) {
                Factory::getApplication()->enqueueMessage($tokenData['error_description'], 'error');
                return false;
            }

            return $tokenData;
        } catch (Exception $e) {
            Factory::getApplication()->enqueueMessage($e->getMessage(), 'error');
            return false;
        }
    }

    private function fetchUserInfo($accessToken)
    {
        $httpFactory = new HttpFactory(); // Create an instance of the HttpFactory
        $http = $httpFactory->getHttp(); // Create the HTTP client instance
        
        try {
            $headers = [
                'Authorization' => 'Bearer ' . $accessToken,
            ];
            $response = $http->get($this->apiUrl, [], $headers);
            $userInfo = json_decode($response->body, true);

            if (isset($userInfo['error_description'])) {
                Factory::getApplication()->enqueueMessage($userInfo['error_description'], 'error');
                return false;
            }
			elseif (isset($userInfo['error'])) {
				if ($this->debug) error_log("userInfo_error: " . $userInfo['error']);
				//Factory::getApplication()->enqueueMessage($userInfo['error'], 'error');
                return false;
            }
			
            return $userInfo;
			
        } catch (Exception $e) {
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

		$data = json_decode($response->body, true);

		if (isset($data['error'])) {
			Factory::getApplication()->enqueueMessage('OAuth error: ' . $data['error_description'], 'error');
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
		if ($this->debug) error_log('loadTokens executed');
		$user = Factory::getUser();
		$userId = is_object($user) && isset($user->id) ? (int) $user->id : 0;
		
		// Load tokens (e.g., from a database or session)
		$db = Factory::getDbo();
		$query = $db->getQuery(true);

		$query->select('*')
			->from('#__jbrasso_oauth_tokens')
			->where('user_id = ' . (int) $userId);

		$db->setQuery($query);
		return $db->loadAssoc();
	}
	
	public function logout()
	{
		// Start the session if not already started
		//if (session_status() == PHP_SESSION_NONE) {
		//	session_start();
		//}

		// Clear OAuth tokens if stored in the session
		//if (isset($_SESSION['oauth_tokens'])) {
		//	unset($_SESSION['oauth_tokens']);
		//	if ($this->debug) error_log('OAuth tokens have been cleared.');
		//}
		
		// Clear stored tokens
		$this->clearTokens(); 
		
		// Clear Joomla session
		$session = Factory::getSession();
		$session->destroy(); // Destroys the Joomla session

		// Clear other session variables related to the user
		//$_SESSION = []; // Reset session variables

		// Destroy the session completely
		//session_destroy();
		if ($this->debug) error_log('User session has been destroyed.');
		
		//Build logout URL for Microsoft
		$logoutUrl = $this->logout_url;
		$postLogoutRedirectUri = Uri::root() . '?plugin=jbrasso&task=logout';
		$redirectUrl = $logoutUrl . '?post_logout_redirect_uri=' . urlencode($postLogoutRedirectUri);

		// Redirect the user to logout
		//$redirectUrl = Uri::root() . 'index.php?option=com_users&view=login';
		Factory::getApplication()->redirect($redirectUrl);
	}
	
	protected function clearTokens()
	{
		if ($this->debug) error_log('Clearing tokens from storage.');

		// Example: Delete tokens from the database (adjust table and column names as needed)
		$user = Factory::getUser();

		if ($user && !$user->guest) {
			$db = Factory::getDbo();
			$query = $db->getQuery(true)
				->delete($db->quoteName('#__jbrasso_oauth_tokens')) // Replace with your token table name
				->where($db->quoteName('user_id') . ' = ' . (int)$user->id);
			$db->setQuery($query);
			$db->execute();
		}
	}
	
}
