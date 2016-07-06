<?php
require('lib/smarty-3.1.29/libs/Smarty.class.php');
$smarty = new Smarty;

$inj=$_GET["inj"];
if(!isset($_GET["tpl"])) {
  $tpl="${inj}";
}
else {
  $tpl=$_GET["tpl"];
}

echo($smarty->fetch('string:'.$tpl));
?>
