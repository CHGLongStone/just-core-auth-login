<?php 
/**
* this should be in 
* [APPLICATION_ROOT]/CONFIG/AUTOLOAD/auth.login.local.php
* or
* [APPLICATION_ROOT]/CONFIG/AUTOLOAD/auth.global.php
* 
*/

return array(
    'AUTH' => array(
		'LOGIN_SERVICE' => array(
			'AUTH_TYPE' => array(
				'USER' => array(
					'DSN' => 'JCORE',
					'table' => 'user',
					'pk_field' => 'user_pk',
					'foundation' => true,
					#'search' => array(), added in the implementation
				),
				'SESSION' => array(
					'DSN' => 'JCORE',
					'table' => 'user',
					'pk_field' => 'user_pk',
					'foundation' => true,
					#'search' => array(), added in the implementation
				),
				'API' => array(
					'DSN' => 'JCORE',
					'table' => 'client',
					'pk_field' => 'client_pk',
					'foundation' => true,
					#'search' => array(), added in the implementation
					'PASS_PHRASE' => 'REDIRECT_HTTP_PASS_PHRASE',
					'API_KEY' => 'REDIRECT_HTTP_API_KEY',
				),
				/***
				* if you want sign up to require a token ie. no public access
				* you can put a few here before you set up a proper management function 
				*/
				'TOKEN' => array(
					'TOKEN_HAYSTACK' => array(
						'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
						'YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY',
						'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ',
					),
				),
			),
		),
    ),
);

?>