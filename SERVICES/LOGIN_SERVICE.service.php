<?php
/**
 * Very basic auth mechanism to white list API calls from other servers
 * this is ONLY in place to limit access to an API based on white list
 * there is no other authentication hook behind this fro granular control
 * implementation ripped straight from here: 
 * https://sunnyis.me/blog/secure-passwords/
 * input from here:
 * http://www.openwall.com/articles/PHP-Users-Passwords
 * 
 * 
 * @author	Jason Medland<jason.medland@gmail.com>
 * @package	JCORE
 * @subpackage	AUTH
 */
 

/**
 * Class PHPASS
 *
 * @package JCORE\AUTH
*/
namespace SERVICE\AUTH;
use JCORE\TRANSPORT\SOA\SOA_BASE as SOA_BASE;
use JCORE\DAO\DAO as DAO;
use JCORE\AUTH\AUTH_INTERFACE as AUTH_INTERFACE;


use SERVICE\CRUD\CRUD as CRUD;
#use SERVICE\AUTH\PHPASS as PHPASS;

/**
 * Class AJAX_STUB
 *
 * @package SERVICE\AUTH 
*/
class LOGIN_SERVICE extends SOA_BASE implements AUTH_INTERFACE{ 
	/** 
	* 
	*/
	protected $serviceRequest = null;
	/** 
	* 
	*/
	public $serviceResponse = null;
	/** 
	* 
	*/
	public $error = null;
	
	/**
	* DESCRIPTOR: an empty constructor, the service MUST be called with 
	* the service name and the service method name specified in the 
	* in the method property of the JSONRPC request in this format
	* 		""method":"AJAX_STUB.aServiceMethod"
	* 
	* @param param 
	* @return return  
	*/
	public function __construct(){
		return;
	}
	
	public function init($args){
		/**
		* echo __METHOD__.__LINE__.'$args<pre>['.var_export($args, true).']</pre>'.'<br>'; 
		*/
		$this->cfg = $GLOBALS["CONFIG_MANAGER"]->getSetting('AUTH','LOGIN_SERVICE','AUTH_TYPE');
		return;
	}
	
	/**
	* DESCRIPTOR: an example namespace call 
	* 
	* @params array 
	* @return this->serviceResponse  
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
	* DESCRIPTOR: complete the implementation
	* 
	* @args array 
	* @return this->serviceResponse  
	*/
	public function authorize($params = null){
		
		return false;
	}
	/**
	* DESCRIPTOR: authenticate a login
	* 
	* 
	* @args array 
	* @return this->serviceResponse  
	*/
	public function authenticateUserLogin($args){
		
		$this->init($args);
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
			$this->serviceResponse = $result;
		}else{
			$result['error'] = 'failed to authenticate';
			$this->serviceResponse = $result;
		}
		
		return $this->serviceResponse;
	}
	
	
	/**
	* DESCRIPTOR: an example namespace call 
	* @param param 
	* @return return  
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
	* DESCRIPTOR: an example namespace call 
	* @param param 
	* @return return  
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