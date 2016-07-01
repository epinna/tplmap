<?php
require('smarty-3.1.29/libs/Smarty.class.php');
$smarty = new SmartyBC;

$tpl=$_GET['inj'];
echo($smarty->fetch('string:'.$tpl));
?>