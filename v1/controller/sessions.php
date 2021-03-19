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

    try{


        $user_name = $json_data->username;
        $user_password = $json_data->password;

        $query = $writeDB->prepare('SELECT user_id, user_fullname, user_name, user_active, user_login_attempts FROM users WHERE user_name = :username');
        $query->bindParam(':username', $user_name, PDO::PARAM_STR);
        $query->exeute();

        $row_count = $query->rowCount();
        
        if($row_count === 0){
            $response = new Response();
            $response->setHttpStatusCode(401);//unauthorized
            $response->setSuccess(false);
            $response->addMessage('Username or password are incorrect.');
            $response->send();
            exit;    
        }

        $row = $query->fetch(PDO::FETCH_ASSOC);

        $returned_id = $row['user_id'];
        $returned_fullname = $row['user_fullname'];
        $returned_user_name = $row['user_name'];
        $returned_password = $row['user_password'];
        $returned_user_active = $row['user_active'];
        $returned_user_login_attempts = $row['user_login_attempts'];

        //validate user active
        if($returned_user_active !== 'Y'){
            $response = new Response();
            $response->setHttpStatusCode(401);//unauthorized
            $response->setSuccess(false);
            $response->addMessage('User is not active.');
            $response->send();
            exit;    
        }

        //count login attempts
        if($returned_user_login_attempts >= 3){
            $response = new Response();
            $response->setHttpStatusCode(401);//unauthorized
            $response->setSuccess(false);
            $response->addMessage('User account is locked.');
            $response->send();
            exit;    
        }

        //validate password
        if(!password_verify($user_password, $returned_password)){
            $query = $writeDB->prepare('UPDATE users SET user_login_attempts = user_login_attempts + 1 WHERE user_id = :userid');
            $query->bindParam(':userid', $returned_id, PDO::PARAM_INT);
            $query->execute();

            $response = new Response();
            $response->setHttpStatusCode(401);//unauthorized
            $response->setSuccess(false);
            $response->addMessage('Incorrect login credentials.');
            $response->send();
            exit;    
        }

        //client has to secure this!!!
        $access_token = base64_encode(bin2hex(openssl_random_pseudo_bytes(24).time()));
        $refresh_token = base64_encode(bin2hex(openssl_random_pseudo_bytes(24).time()));


        $access_token_expiry_seconds = 1200;
        $refresh_token_expiry_seconds = 1209600;

    }
    catch(PDOException $ex){
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage('Login failed.');
        $response->send();
        exit;    
    }


    try{

        //create transaction
        $writeDB->beginTransaction();

        $query = $writeDB->prepare('UPDATE users SET user_login_attempts = 0 WHERE user_id = :userid');
        $query->bindParam(':userid', $returned_id, PDO::PARAM_INT);
        $query->execute();
        
        $query = $writeDB->prepare('INSERT INTO user_sessions ( user_id, access_token, access_expiry, refresh_token, refresh_token_expiry) VALUES (:userid, :accesstoken, date_add(NOW(), INTERVAL :accesstokenexpiryseconds SECOND), :refreshtoken, date_add(NOW(), INTERVAL :refreshtokenexpiryseconds SECOND))');
        $query->bindParam(':userid', $returned_id, PDO::PARAM_INT);
        $query->bindParam(':accesstoken', $access_token, PDO::PARAM_STR);
        $query->bindParam(':accesstokenexpiryseconds', $access_token_expiry_seconds, PDO::PARAM_INT);


    }
    catch(PDOException $ex){

        $writeDB->rollBack();//rollback transaction

        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage('There was an issue login in, please try Again.');
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