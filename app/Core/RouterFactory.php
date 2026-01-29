<?php

declare(strict_types=1);

namespace App\Core;

use Nette;
use Nette\Application\Routers\RouteList;


final class RouterFactory
{
	use Nette\StaticClass;

	public static function createRouter(): RouteList
	{
		$router = new RouteList;
		$router->addRoute('/', 'Home:default');
		$router->addRoute('/download', 'Home:download');
		$router->addRoute('/download_windows', 'Home:downloadWindows');
		$router->addRoute('/donate', 'Home:donate');
		$router->addRoute('/about', 'Home:about');
		$router->addRoute('/statistics', 'Home:statistics');
		$router->addRoute('/faq', 'Home:faq');
		$router->addRoute('/login', 'Authentication:login');
		$router->addRoute('/reg', 'Authentication:registration');
		$router->addRoute('/editProfile', 'Authentication:editProfile');
		$router->addRoute('/logout', 'Authentication:logout');
		$router->addRoute('/verification', 'Authentication:verification');
		$router->addRoute('/passwordReset', 'Authentication:passwordReset');
		$router->addRoute('/ovkintegration', 'Authentication:OpenVKIntegration');
		return $router;
	}
}
