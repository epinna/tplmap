<?php

require_once './lib/Twig-1.24.1/lib/Twig/Autoloader.php';
Twig_Autoloader::register();

$inj=$_GET["inj"];
if(!isset($_GET["tpl"])) {
  $tpl="${inj}";
}
else {
  $tpl=$_GET["tpl"];
}

$loader = new Twig_Loader_Array(array(
    'tpl' => $tpl,
));
$twig = new Twig_Environment($loader);

echo $twig->render('tpl');
 ?>
