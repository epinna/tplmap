<?php
require('smarty/Smarty.class.php');
$smarty = new Smarty;
if(!array_key_exists('tpl', $_GET)) {
  $tpl="${_GET['inj']}";
}
else {
  $tpl=$_GET['inj'];
}
echo($smarty->fetch('string:'.$tpl));
?>