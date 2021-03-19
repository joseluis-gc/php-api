<?php

require_once('db.php');
require_once('../model/response.php');

try
{
    $writeDB = DB::connectWriteDB();
    $readDB  =DB::connectReadDB();
}
catch(PDOException $ex)
{
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage('Db connection failed');
    $response->send();
    exit;
}