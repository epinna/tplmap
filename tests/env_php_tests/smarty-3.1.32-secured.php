<?php

function generateRandomString($length = 10) {
    return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
}

require('lib/smarty-3.1.32/libs/Smarty.class.php');
$smarty = new Smarty;

// clear out all cache files
$smarty->clearAllCache();

$inj=$_GET["inj"];
if(isset($_GET["tpl"]) && $_GET["tpl"] != "") {
  // Keep the formatting a-la-python
  $tpl=str_replace("%s", $inj, $_GET["tpl"]);
}
else {
  $tpl=$inj;
}

error_log('DEBUG< : ' . $tpl);
$rendered = $smarty->fetch('string:'.$tpl);
error_log('DEBUG> : ' . $rendered);

if(!$_GET["blind"]) {
  echo generateRandomString() . $rendered . generateRandomString();
}
else {
  echo generateRandomString();
}
?>
