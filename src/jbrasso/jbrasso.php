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
        
		if (Factory::getApplication()->isClient('administrator')) {
			// Redirect URI for the administrator context
			$this->redirectUri = Uri::root() . 'administrator/index.php?plugin=jbrasso&app_name=' . $this->app_name . '&task=oauthcallback';
		} else {
			// Redirect URI for the site context
			$this->redirectUri = Uri::root() . 'index.php?plugin=jbrasso&app_name=' . $this->app_name . '&task=oauthcallback';
		}
		//$this->redirectUri = Uri::root() . 'index.php?plugin=jbrasso&app_name=' . $this->app_name . '&task=oauthcallback';
    }

    public function onAfterRoute()
    {
        // Only trigger on public pages and if the user is not logged in
        $user = Factory::getUser();
        if (!$user->guest) {
            return;
        }

        $input = Factory::getApplication()->input;
		
		// Check if the request is for your plugin
		$plugin = $input->getCmd('plugin');
		$app_name = $input->getCmd('app_name');
		$task = $input->getCmd('task');
	
       // if ($input->getCmd('option') === 'com_users' && $input->getCmd('task') === 'user.oauthcallback') {
       if ($plugin === 'jbrasso' && $app_name === 'azure' && $task === 'oauthcallback') {
			$this->handleOAuthCallback();
            return;
        }

        // Redirect to the OAuth 2.0 authorization server
        $this->redirectToAuthorization();
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
				// Redirect to authorization endpoint for a new code
				$authUrl = $this->authUrl . '?' . http_build_query([
					'response_type' => 'code',
					'client_id' => $this->clientId,
					'redirect_uri' => $this->redirectUri,
					'state' => $state,
				]);
				Factory::getApplication()->redirect($authUrl);
			} else {
				// Save tokens and proceed with user info processing
				$user = $this->processUserInfo($tokenData);
				if (!empty($user->id))
					$this->saveTokens($user->id, $tokenData);
			}

			// Fetch user information
			/*$userInfo = $this->fetchUserInfo($token['access_token']);
			if (!$userInfo) {
				Factory::getApplication()->enqueueMessage('Failed to fetch user information.', 'error');
				return;
			}

			// Auto-login the user
			$this->autoLoginUser($userInfo);*/
		
		} else {
			// No authorization code provided, check for an existing token
			$tokens = $this->loadTokens();
			
			if ($tokens) {
				if (!$this->isAccessTokenValid($tokens)) {
					// Access token expired, try refreshing it
					$newTokens = $this->refreshAccessToken($tokens['refresh_token']);

					if ($newTokens) {
						$user = $this->processUserInfo($newTokens);
						if (!empty($user->id))
							$this->saveTokens($user->id, $newTokens);
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
					// Access token is valid, proceed with user info processing
					$this->processUserInfo($tokens);
				}	
			} else {
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
		$httpFactory = new HttpFactory(); // Create an instance of the HttpFactory
        $http = $httpFactory->getHttp(); // Create the HTTP client instance
		
		//$accessToken = $tokenData['access_token'];
		//$accessToken = str_replace(PHP_EOL, '', $tokenData['access_token']);
		$accessToken = $tokenData['access_token'];
		
		//Factory::getApplication()->enqueueMessage('Access Token: ' . $accessToken, 'message');
		//debug! get access_token using the above code and test it using the following
		//curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" https://graph.microsoft.com/v1.0/me
		
		try {
			$headers = [
				'Authorization' => 'Bearer ' . $accessToken,
				'User-Agent:web'
			];
			
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
			if (!$user) {
				// User does not exist; create a new user
				$user = $this->createUser($userInfo);
			} else {
				// User exists; update user information if necessary
				///////$this->updateUser($user, $userInfo);
			}

			// Auto-login the user after processing
			//$this->autoLoginUser($user);

			return $this->autoLoginUser($user);
			
		} catch (Exception $e) {
            Factory::getApplication()->enqueueMessage($e->getMessage(), 'error');
            return false;
        }
	}
	
	private function createUser($userInfo) {

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
        }
		else {
               Factory::getApplication()->enqueueMessage('userInfo not found.', 'error');
               return;
            }
		
		return $user;
	}

    private function autoLoginUser($user)
    {
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

			
			
			/*$credentials = [
				'username' => $user->username,
				'password' => UserHelper::genRandomPassword(12), // This won't be validated as we're bypassing
			];
			
			
			$options = ['silent' => true]; // Bypass normal login verification
			$options['remember'] = 1; //this will keep user logged in

			// Log in the user programmatically
			$loginResult = $app->login($credentials, $options);

			if (!$loginResult) {
				Factory::getApplication()->enqueueMessage('Auto-login failed for: ' .  $user->username, 'error');
				return;
			}
			*/
			// Check if login event plugins processed the request
			if (in_array(false, ArrayHelper::toInteger($results), true)) {
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
			Factory::getApplication()->enqueueMessage('Failed to auto-login user: Invalid user object.', 'error');
			return false;
		}
    }
	
	private function getUserByEmail($email)
	{
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
		//error_log("userData :" . print_r($userData,true));

		if ($userData) {
			// Load the user object
			$user = new User($db);
			$user->bind($userData);
			return $user;
		}

		return null; // User not found
	}

    private function redirectToAuthorization()
    {
        $state = bin2hex(random_bytes(16)); // Generate a random state to prevent CSRF
        Factory::getSession()->set('oauth2.state', $state);

        $authorizeUrl = $this->authUrl . '?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => $this->app_scope,
            'state' => $state,
        ]);

        Factory::getApplication()->redirect($authorizeUrl);
    }

    private function fetchAccessToken($authCode)
    {
		$httpFactory = new HttpFactory(); // Create an instance of the HttpFactory
        $http = $httpFactory->getHttp(); // Create the HTTP client instance
        $postFields = [
            'grant_type' => 'authorization_code',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUri,
			'app_scope' => $this->app_scope,
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
                Factory::getApplication()->enqueueMessage($userInfo['error'], 'error');
                return false;
            }
			error_log($userInfo['error']);
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
	
		// Ensure the tokenData array has all necessary keys
		//$userId = Factory::getUser()->id;
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
			->from($db->quoteName('#__oauth_tokens'))
			->where($db->quoteName('user_id') . ' = ' . $db->quote($userId));
		
		$db->setQuery($query);
		$existingRecord = $db->loadResult();

		if ($existingRecord) {
			// Update the existing record
			$query
				->clear()
				->update($db->quoteName('#__oauth_tokens'))
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
		// Load tokens (e.g., from a database or session)
		$db = Factory::getDbo();
		$query = $db->getQuery(true);

		$query->select('*')
			->from('#__jbrasso_oauth_tokens')
			->where('user_id = ' . (int) Factory::getUser()->id);

		$db->setQuery($query);
		return $db->loadAssoc();
	}
	
	
}
