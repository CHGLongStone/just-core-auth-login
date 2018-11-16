<?php
/**
* Class LOGIN_SERVICE 
* 
* @author	Jason Medland<jason.medland@gmail.com>
* @package	JCORE\SERVICE\AUTH
* 
*/
 

namespace JCORE\SERVICE\AUTH;
use JCORE\TRANSPORT\SOA\SOA_BASE as SOA_BASE;
use JCORE\DAO\DAO as DAO;
use JCORE\AUTH\AUTH_INTERFACE as AUTH_INTERFACE;

#use JCORE\SERVICE\CLIENT\CLIENT_ENTITY as CLIENT_ENTITY;

/**
* Class LOGIN_SERVICE 
* https://github.com/CHGLongStone/just-core-auth-login
* 
* Very basic auth mechanism to white list API calls from other servers
* this is ONLY in place to limit access to an API based on white list
* there is no other authentication hook behind this fro granular control
* implementation ripped straight from here: 
*  https://sunnyis.me/blog/secure-passwords/
* input from here:
*  http://www.openwall.com/articles/PHP-Users-Passwords
*  https://github.com/ircmaxell/password_compat
*  http://php.net/manual/en/function.password-hash.php
* 
* @package JCORE\SERVICE\AUTH 
*/
class LOGIN_SERVICE extends SOA_BASE implements AUTH_INTERFACE{ 
	/**
	* serviceRequest
	* 
	* @access protected 
	* @var string
	*/
	protected $serviceRequest = null;
	/**
	* serviceResponse
	* 
	* @access public 
	* @var string
	*/
	public $serviceResponse = null;
	/**
	* error
	* 
	* @access public 
	* @var string
	*/
	public $error = null;
	
	/**
	* DESCRIPTOR: an empty constructor, the service MUST be called with 
	* the service name and the service method name specified in the 
	* in the method property of the JSONRPC request in this format
	* 		""method":"AJAX_STUB.aServiceMethod"
	* 
	* @param null 
	* @return null  
	*/
	public function __construct(){
		$this->testInstall($args=null);
		return;
	}
	/**
	* DESCRIPTOR: init
	* 
	* @access public 
	* @param array args
	* @return null
	*/
	public function init($args){
		#echo __METHOD__.__LINE__.'$args<pre>['.var_export($args, true).']</pre>'.'<br>'; 
		/**
		* 
		*/
		$this->cfg = $GLOBALS["CONFIG_MANAGER"]->getSetting('AUTH','LOGIN_SERVICE','AUTH_TYPE');
		#echo __METHOD__.__LINE__.'$this->cfg<pre>['.var_export($this->cfg, true).']</pre>'.'<br>'; 
		return;
	}
	/**
	* DESCRIPTOR: testInstall
	* 
	* @access public 
	* @param array args
	* @return null
	*/
	public function testInstall($args){
		
		if (isset($_SERVER['APPLICATION_ENV']) && $_SERVER['APPLICATION_ENV'] != 'production') {
			if(true !== function_exists('\password_hash')){
				echo 'native password_* functions not available'.PHP_EOL;
			}else{
				\PasswordCompat\binary\check() ? $test="Pass" : $test="Fail";
				if("Fail" == $test){
					echo 'Test for functionality of compat library: ' .$test.'<br>'.PHP_EOL.'
					see https://github.com/ircmaxell/password_compat <br>'.PHP_EOL.'
					phpversion ['.phpversion ().']<br>
					';
					echo "\n";
				}
			}
			
		}
		return;
	}
	/**
	* DESCRIPTOR: authenticate against:
	* abstracted for JCORE-AUTH-AUTH_HARNESS
	*   UserLogin
	*   UserSession
	*   APICall
	*   APICallToken
	* 
	* @access public 
	* @param array params
	* @return bool
	*/
	public function authenticate($params = null){
		if(!isset($params["AUTH_TYPE"])){
			return false;
		}
		switch(strtolower($params["AUTH_TYPE"])){//authType
			case "user":
				$this->authenticateUserLogin($params);
				break;
			case "session":
				$this->authenticateUserSession($params);
				break;
			case "api":
				#action 
				$this->authenticateAPICall($params);
				break;
			case "token":
				#action 
				$this->authenticateAPICallToken($params);
				break;
			
			default:
				return false;
				break;
		}
		
		if(isset($this->serviceResponse["status"]) && 'OK' == $this->serviceResponse["status"]){
			return true;
		}
		return false;
	}
	
	
	/**
	* DESCRIPTOR: authorize
	* ACL hook stub
	* 
	* @access public 
	* @param array params
	* @return bool
	*/
	public function authorize($params = null){
		
		return false;
	}
	/**
	* DESCRIPTOR: authenticateUserLogin
	* authenticate a login 
	*   - email
	*   - password
	* - get the user role ACL hook
	* 
	* @access public 
	* @param array args
	* @return array
	*/
	public function authenticateUserLogin($args){
		
		$this->init($args);
		$this->testInstall($args);
		$this->DAO = new DAO();
		$config = $this->cfg['USER'];
		$searchCriteria = array(
				'email' => $args["email"],
		);
		$config["search"] = $searchCriteria;
		$this->DAO->initializeBySearch($config);
		$stored_hash = $this->DAO->get($config["table"], 'password');
		
		if(true ===  \password_verify($args['password'], $stored_hash)){
			$result['status'] = 'OK';
			$result['user_id'] = $this->DAO->get($config["table"], $config["pk_field"]);
			$result['comp_id'] = $this->DAO->get($config["table"], 'client_fk');
			$result['role_id'] = $this->DAO->get($config["table"], 'user_role_fk');
			/*


			*/
			$this->serviceResponse = $result;
		}else{
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
		}
		
		return $this->serviceResponse;
	}
	
	
	/**
	* DESCRIPTOR: authenticateUserSession 
	* user_id or user_email
	* 
	* @access public 
	* @param array args
	* @return array
	*/
	public function authenticateUserSession($args){

		if(
			!isset($_SESSION) 
			||
			(
				!isset($_SESSION['user_id']) 
				|| 
				!is_numeric($_SESSION['user_id'])
			)
			|| 
			!isset($_SESSION['user_email'])
		){
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
			return $this->serviceResponse;
		}
		$this->init($args);
		$config = $this->cfg['SESSION'];
		$searchCriteria = array(
				'email' => $_SESSION["user_email"],
		);
		$config["search"] = $searchCriteria;
		$this->DAO = new DAO();

		$this->DAO->initializeBySearch($config);
		$user_id = $this->DAO->get($config["table"], $config["pk_field"]);
		if($user_id  == $_SESSION['user_id']){
			$result['status'] = 'OK';
			$this->serviceResponse = $result;
			return $this->serviceResponse;
		}
		return false;
	}
	/**
	* DESCRIPTOR: authenticateAPICall
	* http header based 
	*   this->cfg["API"]["API_KEY"]
	*   this->cfg["API"]["PASS_PHRASE"]
	*   
	* 
	* @access public 
	* @param array args
	* @return array
	*/
	public function authenticateAPICall($args){
		$this->init($args);
		/*
		echo __METHOD__.__LINE__.'$_SERVER<pre>['.var_export($_SERVER, true).']</pre>'.PHP_EOL; 
		echo __METHOD__.__LINE__.'$this->cfg<pre>['.var_export($this->cfg, true).']</pre>'.PHP_EOL; 
		echo __METHOD__.__LINE__.'$this->cfg["API"]<pre>['.var_export($this->cfg["API"], true).']</pre>'.PHP_EOL; 
		echo __METHOD__.__LINE__.'$this->cfg["API"]["API_KEY"]<pre>['.var_export($this->cfg["API"]["API_KEY"], true).']</pre>'.PHP_EOL; 
		echo __METHOD__.__LINE__.'$_SERVER['.$this->cfg["API"]["API_KEY"].']<pre>['.var_export($_SERVER[$this->cfg["API"]["API_KEY"]], true).']</pre>'.PHP_EOL; 
		echo __METHOD__.__LINE__.'$args<pre>['.var_export($args, true).']</pre>'.PHP_EOL; 
		
		abstract these 2 to config params HTTP_PASS_PHRASE, HTTP_API_KEY
		echo __METHOD__.__LINE__.'$_SERVER["HTTP_PASS_PHRASE"]<pre>['.var_export($_SERVER["HTTP_PASS_PHRASE"], true).']</pre>'.PHP_EOL; 
		echo __METHOD__.__LINE__.'$_SERVER["HTTP_API_KEY"]<pre>['.var_export($_SERVER["HTTP_API_KEY"], true).']</pre>'.PHP_EOL; 
		echo 'apache_request_headers '.print_r(apache_request_headers());
		echo 'apache_response_headers '.print_r(apache_response_headers());
		echo 'get_headers '.print_r(get_headers());
		*/
		
		if(
			!isset($_SERVER[$this->cfg["API"]["API_KEY"]]) 
			|| 
			!isset($_SERVER[$this->cfg["API"]["PASS_PHRASE"]])
		){
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
			return $this->serviceResponse;
		}
		$this->init($args);
		$config = $this->cfg['API'];
		$searchCriteria = array(
				'api_key' => $_SERVER[$this->cfg["API"]["API_KEY"]],
		);
		$config["search"] = $searchCriteria;
		$this->DAO = new DAO();
		#echo __METHOD__.__LINE__.'$config<pre>['.var_export($config, true).']</pre>'.PHP_EOL; 
		$this->DAO->initializeBySearch($config);
		$stored_hash = $this->DAO->get($config["table"], 'pass_phrase');
		#echo __METHOD__.__LINE__.'$stored_hash<pre>['.var_export($stored_hash, true).']</pre>'.PHP_EOL; 
		
		if(true ===  \password_verify($_SERVER[$this->cfg["API"]["PASS_PHRASE"]], $stored_hash)){
			$result['status'] = 'OK';
			$result['client_id'] = $this->DAO->get($config["table"], $config["pk_field"]);
			/*
			$result['comp_id'] = $this->DAO->get($config["table"], $config["pk_field"]);
			$result['role_id'] = $this->DAO->get($config["table"], $config["pk_field"]);
			*/
			$this->serviceResponse = $result;
		}else{
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
		}
	}
	
	/**
	* DESCRIPTOR: authenticateAPICallToken
	* check a "PUBLIC_TOKEN" in an auth whitelist
	* 
	* @access public 
	* @param array args
	* @return array
	*/
	public function authenticateAPICallToken($args){
		/*
		echo __METHOD__.__LINE__.'$_SERVER<pre>['.var_export($_SERVER, true).']</pre>'.PHP_EOL; 
		echo __METHOD__.__LINE__.'$args<pre>['.var_export($args, true).']</pre>'.PHP_EOL; 
		
		abstract these 2 to config params HTTP_PASS_PHRASE, HTTP_API_KEY
		echo __METHOD__.__LINE__.'$_SERVER["HTTP_PASS_PHRASE"]<pre>['.var_export($_SERVER["HTTP_PASS_PHRASE"], true).']</pre>'.PHP_EOL; 
		echo __METHOD__.__LINE__.'$_SERVER["HTTP_API_KEY"]<pre>['.var_export($_SERVER["HTTP_API_KEY"], true).']</pre>'.PHP_EOL; 
		#print_r(apache_response_headers());
		#print_r(get_headers());
		*/
		if(
			!isset($_REQUEST['PUBLIC_TOKEN']) 
		){
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
			return $this->serviceResponse;
		}
		$this->init($args);
		$config = $this->cfg['TOKEN'];
		#echo __METHOD__.__LINE__.'$config<pre>['.var_export($config, true).']</pre>'.PHP_EOL; 
		if(
			true === in_array($_REQUEST['PUBLIC_TOKEN'],$config['TOKEN_HAYSTACK'])
		){
			$result['status'] = 'OK';
			$this->serviceResponse = $result;
			return $this->serviceResponse;
		}else{
			return false;
		}
	}
	
	
	/**
	* DESCRIPTOR: stubbeh 
	* 
	* 
	* @access public 
	* @param array args
	* @return array
	*/
	public function resetPassword_confirmEmail($args){
		#echo __METHOD__.__LINE__.'<br>';
		#echo __METHOD__.__LINE__.'$args<pre>['.var_export($args, true).']</pre>'.'<br>'; 
		#echo __METHOD__.__LINE__.'$_SESSION<pre>['.var_export($_SESSION, true).']</pre>'.'<br>'; 
		#echo __METHOD__.__LINE__.'$_SERVER<pre>['.var_export($_SERVER, true).']</pre>'.'<br>'; 
		$this->init($args);
		#$this->testInstall($args);
		$this->DAO = new DAO();
		$config = $this->cfg['USER'];
		$searchCriteria = array(
				'email' => $args["email"],
		);
		$config["search"] = $searchCriteria;
		$this->DAO->initializeBySearch($config);
		$stored_email = $this->DAO->get($config["table"], 'email');
		$testHash = false;
		if( $stored_email == $args["email"]){
			#echo __METHOD__.__LINE__.'$stored_email<pre>['.var_export($stored_email, true).']</pre>'.'<br>'; 
			$MAIL = $this->cfg['PASSWORD_RECOVER'];
			$TEMPLATER = new \JCORE\TEMPLATER\TEMPLATER();
			$test = $TEMPLATER->set_filenames(array('mailcontent' => JCORE_TEMPLATES_DIR.$MAIL["TEMPLATE"]));
			
			$USER_NAME = $this->DAO->get($config["table"], 'first_name').' '.$this->DAO->get($config["table"], 'last_name');
			#if(true ===  \password_verify($args['password'], $stored_hash)){
			$timestamp = date("Y-m-d H:i:s");
			
			$hashValues = array(
				'email' => $stored_email,
				'timestamp' => $timestamp,
				
			);	
			#echo __METHOD__.__LINE__.'$hashValues<pre>['.var_export($hashValues, true).']</pre>'.'<br>'; 
			$hashString = json_encode($hashValues);
			#echo __METHOD__.__LINE__.'$hashString<pre>['.var_export($hashString, true).']</pre>'.'<br>'; 
			$reset_hash = \password_hash($hashString, PASSWORD_DEFAULT);
			#echo __METHOD__.__LINE__.'$reset_hash<pre>['.var_export($reset_hash, true).']</pre>'.'<br>'; 
			
			
			$setVal = $this->DAO->set($config["table"], 'reset_hash', $reset_hash);
			#echo __METHOD__.__LINE__.'$setVal<pre>['.var_export($setVal, true).']</pre>'.'<br>'; 
			$setVal = $this->DAO->set($config["table"], 'reset_time', $timestamp);
			#echo __METHOD__.__LINE__.'$setVal<pre>['.var_export($setVal, true).']</pre>'.'<br>'; 
			$setVal = $this->DAO->set($config["table"], 'reset_attempts', 0);
			#echo __METHOD__.__LINE__.'$setVal<pre>['.var_export($setVal, true).']</pre>'.'<br>'; 
			$setVal = $this->DAO->save($config["table"]);
			#echo __METHOD__.__LINE__.'$setVal<pre>['.var_export($setVal, true).']</pre>'.'<br>'; 
			
			$testHash = \password_verify($hashString, $reset_hash);
			#echo __METHOD__.__LINE__.'$testHash<pre>['.var_export($testHash, true).']</pre>'.'<br>'; 
			$configClient = array(
				"DSN" => $GLOBALS['DSN'],
				"table" => $config["parent_table"],
				"pk_field" => $config["parent_table_pk"],
				
			);
			/*
			$DAO2 = new JCORE\DAO\DAO($config);		
			*/
			$CLIENT_ENTITY = new DAO();
			$searchCriteria = array(
				"client_pk" => $this->DAO->get($config["table"], 'client_fk'),
			);
			$configClient["search"] = $searchCriteria;
			#echo __METHOD__.__LINE__.'$configClient<pre>['.var_export($configClient, true).']</pre>'.'<br>'; 
			$CLIENT_ENTITY->initializeBySearch($configClient);
			$COMPANY_NAME = $CLIENT_ENTITY->get($config["parent_table"], 'company_name');
			#echo __METHOD__.__LINE__.'$CLIENT_ENTITY->tables['.$config['parent_table'].']["values"]<pre>['.var_export($CLIENT_ENTITY->tables[$config['parent_table']]["values"], true).']</pre>'.'<br>'; 
		;
			$OPTS = array(	
				'COMPANY_NAME' => $COMPANY_NAME,
				'USER_NAME' => $USER_NAME,
				'RESET_LINK' => $_SERVER["HTTP_REFERER"].'?email='.$stored_email.'&reset_password='.$reset_hash,
			);

			$TEMPLATER->assign_vars( $OPTS );
			$RECOVERY_EMAIL = $TEMPLATER->sparse('mailcontent', true, $retvar = 'returnString');
		
			#echo __METHOD__.__LINE__.'$RECOVERY_EMAIL<pre>['.var_export($RECOVERY_EMAIL, true).']</pre>'.'<br>'; 
			
            $headers = "From: ".$COMPANY_NAME." <info@northernsts.com> \n";
            $headers .= "To-Sender: \n";
            $headers .= "X-Mailer: PHP\n"; // mailer
            $headers .= "Reply-To: info@northernsts.com\n"; // Reply address
            $headers .= "Return-Path: info@northernsts.com.com\n"; //Return Path for errors
            $headers .= "Content-Type: text/html; charset=iso-8859-1"; //Enc-type
            $subject = "Your Lost Password";
            $raw_data = mail($stored_email,$subject,$RECOVERY_EMAIL,$headers);

			#$file = '/var/log/httpd/'.$_SERVER["SERVER_NAME"].'.mail.log';
			$file = $GLOBALS["APPLICATION_ROOT"].'log/'.$_SERVER["SERVER_NAME"].'.mail.log';
			file_put_contents($file, 'raw_data::'.$raw_data."\r\n", FILE_APPEND);

			$testHash = true;
			
			
			
		}
		
		if(true === $testHash){
			$result['status'] = 'OK';
			$result['user_id'] = $this->DAO->get($config["table"], $config["pk_field"]);
			$result['comp_id'] = $this->DAO->get($config["table"], 'client_fk');
			$result['role_id'] = $this->DAO->get($config["table"], 'user_role_fk');
			/*


			*/
			$this->serviceResponse = $result;		
		
		}else{
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
		}
		
		return $this->serviceResponse;
	}
	
	
	/**
	* DESCRIPTOR: stubbeh 
	* 
	* 
	* @access public 
	* @param array args
	* @return array
	*/
	public function authenticatePasswordReset($args){
		#echo __METHOD__.__LINE__.'<br>';
		#echo __METHOD__.__LINE__.'$args<pre>['.var_export($args, true).']</pre>'.'<br>'; 
		$this->init($args);
		#$this->testInstall($args);
		$this->DAO = new DAO();
		$config = $this->cfg['USER'];
		$searchCriteria = array(
				'email' => $args["email"],
		);
		$config["search"] = $searchCriteria;
		$this->DAO->initializeBySearch($config);
		$reset_hash = $this->DAO->get($config["table"], 'reset_hash');
		#echo __METHOD__.__LINE__.'$reset_hash<pre>['.var_export($reset_hash, true).']</pre>'.'<br>'; 
		#echo __METHOD__.__LINE__.'$reset_password<pre>['.var_export($args['reset_password'], true).']</pre>'.'<br>'; 
		
		
			
			
		$email = $this->DAO->get($config["table"], 'email');
		$reset_time = $this->DAO->get($config["table"], 'reset_time');
		$reset_attempts = $this->DAO->get($config["table"], 'reset_attempts');
		
		/**
		* test token is the one that was set
		*/
		$testHash = false;
		if($args['reset_password'] ==  $reset_hash){
			
			/**
			* hash the stored email and timestamp again to verify untampered 
			*/
			$hashValues = array(
				'email' => $email,
				'timestamp' => $reset_time,
			);	
			
			$hashString = json_encode($hashValues);
			
			#echo __METHOD__.__LINE__.'$hashString<pre>['.var_export($hashString, true).']</pre>'.'<br>'; 
			$testHash = \password_verify($hashString, $args['reset_password']);
			#echo __METHOD__.__LINE__.'$testHash<pre>['.var_export($testHash, true).']</pre>'.'<br>'; 
			
			
			

		}
		
		if(true === $testHash){
			$result['status'] = 'OK';
			$result['user_id'] = $this->DAO->get($config["table"], $config["pk_field"]);
			$result['comp_id'] = $this->DAO->get($config["table"], 'client_fk');
			$result['role_id'] = $this->DAO->get($config["table"], 'user_role_fk');
			/*


			*/
			$this->serviceResponse = $result;		
		
		}else{
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
		}
		
		return $this->serviceResponse;
	}	
	
	
	/**
	* DESCRIPTOR: stubbeh 
	* 
	* 
	* @access public 
	* @param array args
	* @return array
	*/
	public function resetPassword($args){
		#echo __METHOD__.__LINE__.'<br>';
		#echo __METHOD__.__LINE__.'$args<pre>['.var_export($args, true).']</pre>'.'<br>'; 
		
		if($args["password"] != $args["rpassword"]){
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
		}
		
		
		
		$this->init($args);
		#$this->testInstall($args);
		$this->DAO = new DAO();
		$config = $this->cfg['USER'];
		$searchCriteria = array(
				'email' => $args["email"],
		);
		$config["search"] = $searchCriteria;
		$this->DAO->initializeBySearch($config);
		$reset_hash = $this->DAO->get($config["table"], 'reset_hash');
		#echo __METHOD__.__LINE__.'$reset_hash<pre>['.var_export($reset_hash, true).']</pre>'.'<br>'; 
		#echo __METHOD__.__LINE__.'$reset_password<pre>['.var_export($args['reset_password'], true).']</pre>'.'<br>'; 
		
		
			
			
		$email = $this->DAO->get($config["table"], 'email');
		$reset_time = $this->DAO->get($config["table"], 'reset_time');
		$reset_attempts = $this->DAO->get($config["table"], 'reset_attempts');
		
		/**
		* test token is the one that was set
		*/
		$testHash = false;
		if($args['reset_password'] ==  $reset_hash){
			/**
			* hash the stored email and timestamp again to verify untampered 
			*/
			$hashValues = array(
				'email' => $email,
				'timestamp' => $reset_time,
			);	
			
			$hashString = json_encode($hashValues);
			#echo __METHOD__.__LINE__.'$hashString<pre>['.var_export($hashString, true).']</pre>'.'<br>'; 
			$testHash = \password_verify($hashString, $args['reset_password']);
			#echo __METHOD__.__LINE__.'$testHash<pre>['.var_export($testHash, true).']</pre>'.'<br>'; 
		}
		
		if(true === $testHash){
			
			$new_password = \password_hash($args["password"], PASSWORD_DEFAULT);
			
			$this->DAO->set($config["table"], 'password', $new_password);
			#$this->DAO->set($config["table"], 'reset_time', NULL);
			$this->DAO->set($config["table"], 'reset_hash', NULL);
			$this->DAO->set($config["table"], 'reset_attempts', 0);
			
			$this->DAO->save($config["table"]);

			
			
			$result['status'] = 'OK';
			$result['user_id'] = $this->DAO->get($config["table"], $config["pk_field"]);
			$result['comp_id'] = $this->DAO->get($config["table"], 'client_fk');
			$result['role_id'] = $this->DAO->get($config["table"], 'user_role_fk');
			/*


			*/
			$this->serviceResponse = $result;		
		
		}else{
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
		}
		
		return $this->serviceResponse;
	}
	
	
	/**
	* DESCRIPTOR: stubbeh 
	* 
	* 
	* @access public 
	* @param array args
	* @return array
	*/
	public function createHostSPFRecord($args=null){
		#echo __METHOD__.__LINE__.'<br>';
		#echo __METHOD__.__LINE__.'$args<pre>['.var_export($args, true).']</pre>'.'<br>'; 
		/**
		http://www.openspf.org/SPF_Record_Syntax
		"v=spf1 a:cs2668.mojohost.com  -all"
		*/
		if(isset($args["hostname"])){
			$hostname = $args["hostname"];
		}else{
			$hostname = gethostname();
		}
		
		#echo __METHOD__.__LINE__.'$hostname<pre>['.var_export($hostname, true).']</pre>'.'<br>'; 
		
		$SPFRecord = "v=spf1 a:".$hostname."  -all";

		$this->serviceResponse = array();
		$this->serviceResponse["SPFRecord"] = $SPFRecord;
		return $this->serviceResponse;
	}
	/**
	* DESCRIPTOR: stubbeh 
	* 
	* 
	* @access public 
	* @param array args
	* @return array
	*/
	public function aServiceMethod($args){
		#echo __METHOD__.__LINE__.'<br>';
		#echo __METHOD__.__LINE__.'$args<pre>['.var_export($args, true).']</pre>'.'<br>'; 
		if(!isset($args["action"])){
			$this->error = new StdClass();
			$this->error->code = "FAILED_CALL";
			$this->error->message = ' NO SERVICE ACTION DEFINED';
			$this->error->data = 'no service call made';
			return false;
		}

		$this->serviceResponse = array();
		$this->serviceResponse["title"] = 'Block Eight';
		$this->serviceResponse["type"] = 'page';
		return true;
	}
	
}



?>
