--TEST--
Phar::convertToPhar() gzipped
--SKIPIF--
<?php if (!extension_loaded("phar")) die("skip"); ?>
<?php if (!extension_loaded("zlib")) die("skip"); ?>
--INI--
phar.require_hash=0
phar.readonly=0
--FILE--
<?php

$fname = dirname(__FILE__) . '/' . basename(__FILE__, '.php') . '.phar';
$fname2 = dirname(__FILE__) . '/' . basename(__FILE__, '.php') . '2.phar';

$phar = new Phar($fname);
$phar->stopBuffering();
var_dump($phar->isTar());
var_dump(strlen($phar->getStub()));

$phar->convertToTar();
var_dump($phar->isTar());
var_dump($phar->getStub());

$phar['a'] = 'hi there';

$phar->convertToPhar(Phar::GZ);
var_dump($phar->isPhar());
var_dump($phar->isCompressed());
var_dump(strlen($phar->getStub()));

copy($fname . '.gz', $fname2);

$phar = new Phar($fname2);
var_dump($phar->isPhar());
var_dump($phar->isCompressed() == Phar::GZ);
var_dump(strlen($phar->getStub()));

?>
===DONE===
--CLEAN--
<?php 
unlink(dirname(__FILE__) . '/' . basename(__FILE__, '.clean.php') . '.phar.gz');
unlink(dirname(__FILE__) . '/' . basename(__FILE__, '.clean.php') . '2.phar');
__HALT_COMPILER();
?>
--EXPECT--
bool(false)
int(6573)
bool(true)
string(60) "<?php // tar-based phar archive stub file
__HALT_COMPILER();"
bool(true)
int(4096)
int(6573)
bool(true)
bool(true)
int(6573)
===DONE===
