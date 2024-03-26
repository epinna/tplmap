<?php

function generateRandomString($length = 10) {
    return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
}

$inj=$_GET["inj"];
if(isset($_GET["tpl"]) && $_GET["tpl"] != "") {
  // Keep the formatting a-la-python
  $tpl=str_replace("%s", $inj, $_GET["tpl"]);
}
else {
  $tpl=$inj;
}

if(!$_GET["blind"]) {
  echo generateRandomString();
  error_log('DEBUG< : ' . $tpl);
  $rendered = eval($tpl);
  error_log('DEBUG> : ' . $rendered);
  echo generateRandomString();
}
else {
  error_log('DEBUG< : ' . $tpl);
  ob_start();
  $rendered = eval($tpl);
  ob_end_clean();
  error_log('DEBUG> : ' . $rendered);
  echo generateRandomString();
}
?>
