<?php 
/**
* this should be in APPLICATION_ROOT/CONFIG/AUTOLOAD/auth.login.local.php
* or
* this should be in APPLICATION_ROOT/CONFIG/AUTOLOAD/auth.login.global.php
* 
*/

return array(
    'AUTH' => array(
		'LOGIN_SERVICE' => array(
			'AUTH_TYPE' => array(
				'USER' => array(
					'DSN' => 'YOUR_PRIMARY_DATA_STORE',
					'table' => 'user',
					'pk_field' => 'user_pk',
					'foundation' => true,
					#'search' => array(), added in the implementation
				),
				'SESSION' => array(
					'DSN' => 'YOUR_PRIMARY_DATA_STORE',
					'table' => 'user',
					'pk_field' => 'user_pk',
					'foundation' => true,
					#'search' => array(), added in the implementation
				),
				
			),
		),
    ),
);

?>