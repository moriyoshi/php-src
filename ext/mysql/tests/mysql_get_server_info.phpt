--TEST--
mysql_get_server_info()
--SKIPIF--
<?php require_once('skipif.inc'); ?>
<?php require_once('skipifemb.inc'); ?>
--FILE--
<?php
    include "connect.inc";
        
    if (false !== ($tmp = @mysql_get_server_info(NULL)))
        printf("[002] Expecting boolean/false, got %s/%s\n", gettype($tmp), $tmp);        
    
    require "table.inc";    
    if (!is_string($info = mysql_get_server_info($link)) || ('' === $info))
        printf("[003] Expecting string/any_non_empty, got %s/%s\n", gettype($info), $info);        
        
    $def_info = mysql_get_server_info();
    if ($def_info !== $info) {
        printf("[004] Server info for the default link and the specified link differ, [%d] %s\n",
            mysql_errno(), mysql_error());
            
        var_dump($def_info);
        var_dump($info);            
    }
                
    if (ini_get('unicode.semantics') && !is_unicode($info)) {
        printf("[005] Expecting Unicode error message!\n");
        var_inspect($info);
    }

    print "done!";
?>
--EXPECTF--
done!
