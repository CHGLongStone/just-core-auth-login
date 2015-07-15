# just-core-auth-login
Basic login service supporting user session and database stored credentials

The service expects but does note require the just-core [authentication harness](https://github.com/CHGLongStone/just-core/blob/master/CORE/AUTH/AUTH_HARNESS.class.php) see the harness example mentioned below to see how to register authentication services.

## Installation 

#### Composer
Add the project to your composer file `"just-core/auth-login" : "dev-master",` you will also need the supporting project "ircmaxell/password-compat" : "v1.0.4" to leverage the native password_hash() and password_verify() functions if your project is running on a version of PHP older than 5.5.0 (PHP >= 5.3.7 required).

```
{
	"name" : "your project",
	"description" : "info about your project",
	"license" : "GNU",
	"version" : "1.0.0",
	"require" : {
		"php" : ">=5.3.7",
		"just-core/foundation" : "0.5.*",
		"just-core/foundation" : "dev-master",
		"just-core/auth-login" : "dev-master",
		"ircmaxell/password-compat" : "v1.0.4"
	},
	"autoload" : {
		"classmap" : [
			"SERVICES"
		]
	}
}

```
#### Configuration
You will also need to take the example files `CONFIG.AUTOLOAD.auth.login.local` and `harness.example.php` modify the examples and make them available in your application, ie.
```
[application_root]/.../[http_exposed_dir]/harness.php
[application_root]/CONFIG/AUTOLOAD/auth.login.local
```

