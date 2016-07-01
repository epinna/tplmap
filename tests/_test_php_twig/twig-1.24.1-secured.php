<?php 

require_once './lib/Twig-1.24.1/lib/Twig/Autoloader.php';
Twig_Autoloader::register();

$tpl=$_GET['inj'];

$loader = new Twig_Loader_Array(array(
    'tpl' => $tpl,
));
$twig = new Twig_Environment($loader);

echo $twig->render('tpl');
 ?>