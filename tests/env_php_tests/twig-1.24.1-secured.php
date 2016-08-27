<?php

function generateRandomString($length = 10) {
    return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
}

require_once './lib/Twig-1.24.1/lib/Twig/Autoloader.php';
Twig_Autoloader::register();

// Run render via CLI
if (php_sapi_name() == "cli") {
    $_GET["inj"] = '';
    $_GET["tpl"] = "";
} 

$inj=$_GET["inj"];
if(isset($_GET["tpl"])) {
  // Keep the formatting a-la-python
  $tpl=str_replace("%s", $inj, $_GET["tpl"]);
}
else {
  $tpl=$inj;
}

error_log('DEBUG: ' . $tpl);

$loader = new Twig_Loader_Array(array(
    'tpl' => $tpl,
));
$twig = new Twig_Environment($loader);

echo generateRandomString() . $twig->render('tpl') . generateRandomString();
 ?>
