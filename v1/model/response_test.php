<?php
    require_once('response.php');

    $response = new Response();
    $response->setSuccess(true);
    $response->setHttpStatusCode(200);
    $response->addMessage('Test 1');
    $response->addMessage('Test 2');
    $response->send();