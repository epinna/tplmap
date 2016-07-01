<?php
require('smarty/Smarty.class.php');
$smarty = new SmartyBC;
if(!array_key_exists('tpl', $_GET)) {
  $tpl="${_GET['inj']}";
}
else {
  $tpl=$_GET['inj'];
}
echo($smarty->fetch('string:'.$tpl));
?>