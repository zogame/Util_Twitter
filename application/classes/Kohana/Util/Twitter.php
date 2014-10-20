<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Twitter API Utilty
 *
 * @author Yoshiharu Shibata <shibata@zoga.me>
 * @uses TwitterOAuth application/vendor/twitteroauth/twitteroauth
 * @link https://github.com/abraham/twitteroauth
 */
class Kohana_Util_Twitter {

	/**
	 * @var array config default
	 */
	protected $_twitter_config = array(
		'consumer_key'    => '',
		'consumer_secret' => '',
		'oauth_callback'  => '/auth/callback',
		'user_agent'      => 'Mozilla/5.0 (compatible; Kohana_Util_Twitter +http://kohanaframework.org/)',
		'timeout'         => 5,
		'connecttimeout'  => 5,
		'retry'           => 5,
		'interval'        => 5,
	);

	/**
	 * @var int logging level
	 */
	protected $_log_level;

	/**
	 * @var object Session
	 */
	protected $_session;

	/**
	 * @var object JSON stdClass
	 */
	protected $_credentials;

	/**
	 * @var string authenticated oauth_token
	 */
	public $_oauth_token;

	/**
	 * @var string authenticated oauth_token_secret
	 */
	public $_oauth_token_secret;

	/**
	 * Constructs a new class and loads a config if given
	 *
	 * @param   array  $config  config options
	 * @return  void
	 */
	public function __construct($config = array())
	{
		$this->_log_level = Log::NOTICE;
		$this->initialize($config);
	}

	/**
	 * Creates and returns a new class.
	 * 
	 * @param   array  $config  Config Options
	 * @return  Util_Twitter
	 */
	public static function factory($config = array())
	{
		return new Util_Twitter($config);
	}

	/**
	 * initialized setting
	 * 
	 * @param   array  $config  Config Options
	 * @return  void
	 */
	public function initialize($config = array())
	{
		// load default settings.
		$config_file = Kohana::$config->load('twitter')->as_array();

		// merge settings.
		if ($config_file)
		{
			$this->_twitter_config = Arr::merge($this->_twitter_config, $config_file);
		}
		if ($config)
		{
			$this->_twitter_config = Arr::merge($this->_twitter_config, $config);
		}
	}

	/**
	 * TwitterOAuth connection (required authorized user)
	 * 
	 * @param  string $oauth_token        access_token
	 * @param  string $oauth_token_secret access_token_secret
	 * @return object TwitterOAuth (connected)
	 */
	public function connect($oauth_token = NULL, $oauth_token_secret = NULL)
	{
		$connection = new TwitterOAuth($this->_twitter_config['consumer_key'], $this->_twitter_config['consumer_secret'], $oauth_token, $oauth_token_secret);
		$connection->useragent      = $this->_twitter_config['user_agent'];
		$connection->timeout        = $this->_twitter_config['timeout'];
		$connection->connecttimeout = $this->_twitter_config['connecttimeout'];

		return $connection;
	}

	/**
	 * Twitter OAuth
	 * 
	 * - authorize first
	 * 
	 * @return boolean FALSE: failure
	 * @uses TwitterOAuth
	 */
	public function oauth()
	{
		$this->_session = Session::instance();

		$connection = $this->connect();

		$callback = URL::site($this->_twitter_config['oauth_callback'], TRUE);

		for ($i = 0; $i < $this->_twitter_config['retry']; $i++)
		{
			// call api, request tokens
			$request_token = $connection->getRequestToken($callback);

			if ((int)$connection->http_code === 200)
			{
				break;
			}

			sleep($this->_twitter_config['interval']);
		}

		if ((int)$connection->http_code !== 200)
		{
			echo 'Could not connect to Twitter. Refresh the page or try again later.';
			return FALSE;
		}

		// Save temporary credentials to session.
		$this->_session->set('oauth_token', $request_token['oauth_token']);
		$this->_session->set('oauth_token_secret', $request_token['oauth_token_secret']);

		// Build authorize URL and redirect user to Twitter.
		$url = $connection->getAuthorizeURL($request_token['oauth_token']);
		HTTP::redirect($url, 302);
	}

	/**
	 * Twitter OAuth callback
	 * 
	 * - authorize finaly
	 * 
	 * @return boolean TRUE: success, FALSE: failure
	 * @uses TwitterOAuth
	 */
	public function oauth_callback()
	{
		$this->_session = Session::instance();

		$oauth_token = $this->_session->get('oauth_token');
		$oauth_token_secret = $this->_session->get('oauth_token_secret');

		$new_token = Request::current()->query('oauth_token');

		if (strcmp($oauth_token, $new_token) !== 0)
		{
			// token invalid
			Kohana::$log->add($this->_log_level, 'Session timeout.');
			return FALSE;
		}

		$oauth_verifier = Request::current()->query('oauth_verifier');

		// Create TwitteroAuth object with app key/secret and token key/secret from default phase
		$connection = $this->connect($oauth_token, $oauth_token_secret);

		for ($i = 0; $i < $this->_twitter_config['retry']; $i++)
		{
			// call api, access tokens
			$access_token = $connection->getAccessToken($oauth_verifier);

			if ((int)$connection->http_code === 200)
			{
				$this->_oauth_token = $access_token['oauth_token'];
				$this->_oauth_token_secret = $access_token['oauth_token_secret'];
				break;
			}

			sleep($this->_twitter_config['interval']);
		}

		if ((int)$connection->http_code !== 200)
		{
			Kohana::$log->add($this->_log_level, 'Could not connect to Twitter.');
			return FALSE;
		}

		// Account check and get gredentials
		$this->_credentials = $this->verify_credentials($this->_oauth_token, $this->_oauth_token_secret);

		if ( ! $this->_credentials)
		{
			Kohana::$log->add($this->_log_level, 'Could not verify to your account.');
			return FALSE;
		}

		$this->_session->delete('oauth_token');
		$this->_session->delete('oauth_token_secret');

		return TRUE;
	}

	/**
	 * get oauth_token
	 * 
	 * @return string
	 */
	public function oauth_token()
	{
		return $this->_oauth_token;
	}

	/**
	 * get oauth_token_secret
	 * 
	 * @return string
	 */
	public function oauth_token_secret()
	{
		return $this->_oauth_token_secret;
	}

	/**
	 * get credentials
	 * 
	 * @return object JSON stdClass
	 */
	public function credentials()
	{
		return $this->_credentials;
	}

	/**
	 * short hand account/verify_credentials
	 * 
	 * @param  string $oauth_token        access_token (not request_token)
	 * @param  string $oauth_token_secret access_token_secret (not request_token_secret)
	 * @return object JSON stdClass
	 */
	public function verify_credentials($oauth_token, $oauth_token_secret)
	{
		$connection = $this->connect($oauth_token, $oauth_token_secret);
		
		for ($i = 0; $i < $this->_twitter_config['retry']; $i++)
		{
			// call api, verify_credentials
			$content = $connection->get('account/verify_credentials');

			if ((int)$connection->http_code === 200)
			{
				break;
			}

			sleep($this->_twitter_config['interval']);
		}
		
		if ( ! $content)
		{
			Kohana::$log->add($this->_log_level, 'Could not connect to Twitter.');
			return FALSE;
		}

		return $content;
	}

	/**
	 * short hand statuses/update
	 * 
	 * @param  string $oauth_token        access_token (not request_token)
	 * @param  string $oauth_token_secret access_token_secret (not request_token_secret)
	 * @param  string $tweet              tweet string
	 * @return object JSON stdClass
	 */
	public function tweet($oauth_token, $oauth_token_secret, $tweet)
	{
		$connection = $this->connect($oauth_token, $oauth_token_secret);

		for ($i = 0; $i < $this->_twitter_config['retry']; $i++)
		{
			// call api, update
			$content = $connection->post('statuses/update', array('status' => $tweet));

			if ((int)$connection->http_code === 200)
			{
				break;
			}

			sleep($this->_twitter_config['interval']);
		}

		if ( ! $content)
		{
			Kohana::$log->add($this->_log_level, 'Could not connect to Twitter.');
			return FALSE;
		}

		return $content;
	}
}
// Load TwitterOAuth
require_once Kohana::find_file('vendor', 'twitteroauth/twitteroauth');

