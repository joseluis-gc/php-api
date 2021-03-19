<?php

require_once 'db.php';
require_once '../model/response.php';

try{
    $writeDB = DB::connectWriteDB();
}
catch(PDOException $ex){
    error_log('Connection error' . $ex, 0);
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage('Database connection error.');
    $response->send();
    exit;    
}

if(array_key_exists('sessionid', $_GET)){

}
elseif(empty($_GET)){


    if($_SERVER['REQUEST_METHOD'] !== 'POST'){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage('Request Method not Allowed.');
        $response->send();
        exit;
    }


    //against bruteforcer
    sleep(1);

    if($_SERVER['CONTENT_TYPE'] !== 'application/json'){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage('Content type header not Allowed.');
        $response->send();
        exit;
    }

    $raw_post_data = file_get_contents('php://input');

    if(!$json_data = json_decode($raw_post_data)){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage('Content type not Allowed.');
        $response->send();
        exit;
    }

    if(isset($json_data->username) || isset($json_data->password)){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        (!isset($json_data->username) ? $response->addMessage('Username not provided.') : false);
        (!isset($json_data->password) ? $response->addMessage('Password not provided.') : false);
        $response->send();
        exit;   
    }

    if(strlen($json_data->username) < 1 || strlen($json_data->username) > 255   || strlen($json_data->password) < 1 || strlen($json_data->password) > 255 ){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        (strlen($json_data->username) < 1 ? $response->addMessage('Username not provided.') : false);
        (strlen($json_data->username) > 255 ? $response->addMessage('User name cannot be over 255 characters.') : false);
        (strlen($json_data->username) < 1 ? $response->addMessage('Password not provided.') : false);
        (strlen($json_data->username) > 255 ? $response->addMessage('Password cannot be over 255 characters.') : false);
        $response->send();
        exit;   
    } 

    

}
else{
    $response = new Response();
    $response->setHttpStatusCode(404);
    $response->setSuccess(false);
    $response->addMessage('Endpoint not found.');
    $response->send();
    exit;    
}