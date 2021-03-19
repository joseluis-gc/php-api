<?php

require_once 'db.php';
require_once '../model/response.php';

try{
    $writeDB = DB::connectWriteDB();
}
catch(PDOException $ex){
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage('Database connection error.');
    $response->send();
    exit;    
}

if($_SERVER['REQUEST_METHOD'] !== 'POST'){
    $response = new Response();
    $response->setHttpStatusCode(405);
    $response->setSuccess(false);
    $response->addMessage('Request Method Not Allowed.');
    $response->send();
    exit;    
}


if($_SERVER['CONTENT_TYPE'] !== 'application/json'){
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    $response->addMessage('Content type Not Allowed.');
    $response->send();
    exit;    
}


$raw_post_data = file_get_contents('php://input');

if(!$json_data = json_decode($raw_post_data)){
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    $response->addMessage('Request body is not valid.');
    $response->send();
    exit;    
}

if(!isset($json_data->fullname) || !isset($json_data->username) || !isset($json_data->password)){

    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    (!isset($json_data->fullname) ? $response->addMessage('Full name not supplied.') : false);
    (!isset($json_data->username) ? $response->addMessage('User name not supplied.') : false);
    (!isset($json_data->password) ? $response->addMessage('Password not supplied.') : false);
    $response->send();
    exit;
}


if(strlen($json_data->fullname) < 1 || strlen($json_data->fullname) > 255 || strlen($json_data->username) < 1 || strlen($json_data->username) > 255  ||  strlen($json_data->password) < 1 || strlen($json_data->password) > 255){
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    (strlen($json_data->fullname) < 1 ? $response->addMessage('Full name cannot be blank.') : false);
    (strlen($json_data->fullname) > 255 ? $response->addMessage('Full name cannot be over 255.') : false);
    (strlen($json_data->username) < 1 ? $response->addMessage('User name cannot be blank.') : false);
    (strlen($json_data->username) > 255 ? $response->addMessage('User name cannot be over 255.') : false);
    (strlen($json_data->password) < 1 ? $response->addMessage('Password cannot be blank.') : false);
    (strlen($json_data->password) > 255 ? $response->addMessage('Password cannot be over 255.') : false);
    $response->send();
    exit;
}


$fullname = trim($json_data->fullname);
$username = trim($json_data->username);
$password = $json_data->password;

try{

    $query = $writeDB->prepare('SELECT user_id FROM users WHERE user_name = :username');
    $query->bindParam(':username', $username, PDO::PARAM_STR);
    $query->execute();

    $row_count = $query->rowCount();

    if($row_count !== 0){
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage('This username is already taken.');
        $response->send();
        exit;
    }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);


    $query_string = "INSERT INTO users (user_fullname, user_name, user_password) VALUES ('$fullname', '$username', '$hashed_password')";
    $query = $writeDB->prepare("INSERT INTO users (user_fullname, user_name, user_password) VALUES (:fullname, :username, :password)");
    $query->bindParam(':fullname', $fullname, PDO::PARAM_STR);
    $query->bindParam(':username', $username, PDO::PARAM_STR);
    $query->bindParam(':password', $hashed_password, PDO::PARAM_STR);
    $query->execute();

    $row_count = $query->rowCount();

    if($row_count === 0){
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage('Error while creating your account.'.$query_string);
        $response->send();
        exit;
    }

    $last_user_id = $writeDB->lastInsertId();

    $return_data = array();
    $return_data['user_id'] = $last_user_id;
    $return_data['full_name'] = $fullname;
    $return_data['user_name'] = $username;

    $response = new Response();
    $response->setHttpStatusCode(201);
    $response->setSuccess(true);
    $response->addMessage('User Created.');
    $response->setData($return_data);
    $response->send();
    exit;


}
catch(PDOException $ex){
    error_log('Database Query Error -' . $ex, 0);
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage('Couldn\'t create user.');
    $response->send();
    exit;
}












