# FSR-api-class
# PHP-API-CLASS
<?php
define("FsrPublicKey",'');
define("FsrPrivateKey",'');
define("FsrEndPoint",'https://www.endpoint/api');

 if (!function_exists('json_last_error')) {
 	function json_last_error(){
 		return;
 	}
 }
    if (!function_exists('json_last_error_msg')) {
        function json_last_error_msg() {
            static $ERRORS = array(
                JSON_ERROR_NONE => 'No error',
                JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
                JSON_ERROR_STATE_MISMATCH => 'State mismatch (invalid or malformed JSON)',
                JSON_ERROR_CTRL_CHAR => 'Control character error, possibly incorrectly encoded',
                JSON_ERROR_SYNTAX => 'Syntax error',
                JSON_ERROR_UTF8 => 'Malformed UTF-8 characters, possibly incorrectly encoded'
            );

            $error = json_last_error();
            return isset($ERRORS[$error]) ? $ERRORS[$error] : 'Unknown error';
        }
    }


function safety_json_encode($data) {
		// We might have been tolerant to some common cases such as convert 
		// INF/NAN as 0 by using JSON_PARTIAL_OUTPUT_ON_ERROR option, but
		// sadly `json_last_error()` only get the last error means it may
		// override worse errors such as malfored utf-8 which we can't ignore!
		// Poor H P !!
		$result = @json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
		$err = json_last_error();
		// strictly no error
		if ($err === JSON_ERROR_NONE && $result) {
			// Escape </script> to prevent XSS
			// Note: Commonly `str_replace()` is not safe for corrupted string
			// But in our case, `json_encode()` already ensure `$result` as a
			// valid utf-8 string.
			return str_replace('</script>', '<\/script>', $result);
		}
		error_log(
			'json encode error: ' . json_last_error_msg() .
			', trace: ' . print_r(debug_backtrace(), true)
		);
		// When error, PHP 5.5 may return `false`, which output nothing.
		// PHP 5.4 (or PHP 5.5 with JSON_PARTIAL_OUTPUT_ON_ERROR option on)
		// may return "{null: ...}" if the key is a malfored utf-8 string, 
		// which is not valid JSON string.
		// Instead of such meaningless and harmful result which may cause
		// JavaScript error or potential XSS, we return 'null' to denote the
		// failure.
		return; //must return NOTHING or it isn't valid JSON
	}

class FsrAPI
{
    // property declaration
    protected $public_key = FsrPublicKey;
    protected $private_key = FsrPrivateKey;
    protected $endpoint = FsrEndPoint;

	
	
	public function capability_check(){
	//checking for curl
	$arr = array();
	$error = false;
		if(!function_exists('curl_exec')){
		$arr['error'] = true;
		$arr['message'] = 'Curl is not available.. please enable or install Curl. See here: http://curl.haxx.se';
		}
		if($arr['error']){
		echo stripslashes(json_encode($arr));
		exit;
		}
	}


    // method declaration
    public function create_newcall($arr,$opts=array()) {
    $this->capability_check();
    $nonce = sha1(uniqid(rand()));
    $nonce_ts = date('c');
			$content = json_encode($arr['params'], JSON_NUMERIC_CHECK);
			$str = "";
			foreach($arr['params'] as $k=>$v)
				if(strtoupper($arr['method']) == "GET")//only build URI for get requests
				$str .= "/".$v;
			$hash = hash_hmac('sha256', $nonce.$nonce_ts.$content, $this->private_key);
			$headers = array(
			'X-Public: '.$this->public_key,
			'X-Hash: '.$hash,
			'Nonce: '.$nonce,
			'Created: '.$nonce_ts,
			'X-Requested-With: '. $arr['X-Requested-With']
			);

			if(!isset($arr['debug'])){
			$arr['debug'] = 0;
			}else{
				if($arr['debug'] !==1 && $arr['debug'] !== 0 && $arr['debug'] == true && $arr['debug'] == false)
				$arr['debug'] = 0;
			}
			if(!is_numeric($arr['debug']))
			$arr['debug'] = 0;
			$created = array("headers"=>$headers, "path"=>$this->endpoint.$arr['path'].$str,"debug"=>$arr['debug'], "content"=>$content,"method"=>$arr['method']);
			//return $created;
			return $this::fetch($created,$opts);
    }
}

// basics taken from :: http://innvo.com/php-curl-class - With thanks!
class FsrCurlApi extends FsrAPI {
	static $hndl; // Handle
	static $b = ''; // Response body
	static $h = ''; // Response head
	static $i = array();
	
	static function head($ch,$data) {
		FsrCurlApi::$h .= $data;
		return strlen($data);
	}
	
	static function body($ch,$data) {
		FsrCurlApi::$b .= $data;
		return strlen($data);
	}
	
	static function sendviapost($current,$add){
		if(count($add)>0){
			foreach($add as $key => $val){
				$current[$key]=$val;
			}
		}
		return $current;
	}
	
	static function fetch($arr=array(),$opts2 = array())
    {   
    
    	if(count($opts2)>0){
    		foreach($opts as $key=>$val)
    		$opts[$key] = $val;
    	}
		$opts[CURLOPT_USERAGENT] = $_SERVER['HTTP_USER_AGENT'];    
    	$opts[CURLOPT_ENCODING] = 'gzip,deflate';
    	$opts[CURLOPT_TIMEOUT] = 5;
    	$opts[CURLOPT_HEADERFUNCTION] = array('FsrCurlApi','head');
    	$opts[CURLOPT_WRITEFUNCTION] = array('FsrCurlApi','body');
    	$opts[CURLOPT_RETURNTRANSFER] = false;
		$opts[CURLOPT_HTTPHEADER] = $arr['headers'];
		if(strtoupper($arr['method']) == "POST")//add post parameters to request
		$opts = FsrCurlApi::sendviapost($opts,array(CURLOPT_POSTFIELDS=>$arr['content']));	
		$url = $arr['path'];
		FsrCurlApi::$h = $arr['headers'];
		FsrCurlApi::$i = array();
		FsrCurlApi::$hndl = curl_init($url);
		curl_setopt_array(FsrCurlApi::$hndl,$opts);
		curl_exec(FsrCurlApi::$hndl);
		FsrCurlApi::$i = curl_getinfo(FsrCurlApi::$hndl);
		curl_close(FsrCurlApi::$hndl);
		$h = "";
		$h = fsrCurlApi::$h;
		$headers['headers'] = $h;
		if($arr['debug'])
		return safety_json_encode($headers);
		
	}
}
?>
