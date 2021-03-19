<?php

require_once "db.php";
require_once "../model/task.php";
require_once "../model/response.php";
try{
    $writeDB = DB::connectWriteDB();
    $readDB  = DB::connectReadDB();
}
catch(PDOException $ex){
    error_log("Connection error - " . $ex, 0); //php error log
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage('Database connection error');
    $response->send();
    exit;
}

if(array_key_exists("taskid", $_GET)){
    $task_id = $_GET['taskid'];

    if($task_id == '' || !is_numeric($task_id)){
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage('Invalid task id');
        $response->send();
        exit;
    }

    if($_SERVER['REQUEST_METHOD'] === 'GET'){

        try{
            
            $query = $readDB->prepare('SELECT task_id, task_title, task_description, DATE_FORMAT(task_deadline, "%d/%m/%Y %H:%i:%s") as task_deadline, task_complete FROM tbl_tasks WHERE task_id = :taskid');
            $query->bindParam(':taskid', $task_id, PDO::PARAM_INT);
            $query->execute();

            //echo $test  = 'SELECT task_id, task_title, task_description, DATE_FORMAT(task_deadline, "%d/%m/%Y %H:%i:%s"), task_complete FROM tbl_tasks WHERE task_id = :'.$task_id.'';

            $row_count = $query->rowCount();

            if($row_count === 0){
                
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage('Task not found');
                $response->send();
                exit;    
            }

            while($row = $query->fetch(PDO::FETCH_ASSOC)){
                $task = new Task($row['task_id'], $row['task_title'], $row['task_description'], $row['task_deadline'], $row['task_complete']);

                $tasksArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $row_count;
            $returnData['tasks'] = $tasksArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;



        }
        catch(TaskException $ex){

            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;

        }
        catch(PDOException $ex){
            error_log("Query Error - " . $ex, 0); //php error log
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Failed to get Task - Query Error ');
            $response->send();
            exit;
        }


    }
    elseif($_SERVER['REQUEST_METHOD'] === 'DELETE'){

        try{

            $query = $writeDB->prepare('DELETE FROM tbl_tasks WHERE task_id = :taskid');
            $query->bindParam('taskid', $task_id, PDO::PARAM_INT);
            $query->execute();

            $row_count = $query->rowCount();

            if($row_count === 0)
            {    
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage('Task not found');
                $response->send();
                exit;
            }

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->setData('Task Deleted');
            $response->send();
            exit;

    
        }
        catch(PDOException $ex){
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Failed to delete DB error');
            $response->send();
            exit;
        }

    }
    elseif($_SERVER['REQUEST_METHOD'] === 'PATCH'){


        try{

            if($_SERVER['CONTENT_TYPE'] !== "application/json")
            {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage('Content type not allowed');
                $response->send();
                exit;    
            }

            $rawPatchData = file_get_contents('php://input');

            if(!$json_data = json_decode($rawPatchData))
            {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage('Request body is not valid json.');
                $response->send();
                exit;    
            }

            $title_updated = false;
            $description_updated = false;
            $deadline_updated = false;
            $completed_updated = false;

            $query_fields = '';

            if(isset($json_data->title))
            {
                $title_updated = true;
                $query_fields .= 'task_title = :title, ';
            }

            if(isset($json_data->description))
            {
                $description_updated = true;
                $query_fields .= 'task_description = :description, ';
            }

            if(isset($json_data->deadline))
            {
                $deadline_updated = true;
                $query_fields .= 'task_deadline = STR_TO_DATE(:deadline, "%d/%m/%Y %H:%i:%s"), ';
            }

            if(isset($json_data->completed))
            {
                $completed_updated = true;
                $query_fields .= 'task_complete = :completed, ';
            }

            $query_fields = rtrim($query_fields, ", ");


            if($title_updated === false && $description_updated === false && $deadline_updated === false && $completed_updated === false)
            {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("No fields to update where provided.");
                $response->send();
                exit;
            }


            $query = $writeDB->prepare('SELECT task_id, task_title, task_description, DATE_FORMAT(task_deadline, "%d/%m/%Y %H:%i:%s") as task_deadline, task_complete FROM tbl_tasks WHERE task_id = :taskid');
            $query->bindParam(':taskid', $task_id, PDO::PARAM_INT);
            $query->execute();

            $row_count = $query->rowCount();

            if($row_count === 0)
            {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage('Task not found.');
                $response->send();
                exit;
            }

            while($row = $query->fetch(PDO::FETCH_ASSOC))
            {
                $task = new Task($row['task_id'], $row['task_title'], $row['task_description'], $row['task_deadline'], $row['task_complete'], );
            }


            $query_string = 'UPDATE tbl_tasks SET '.$query_fields.' WHERE task_id = :taskid';
            $query = $writeDB->prepare($query_string);

            if($title_updated === true){
                $task->setTitle($json_data->title);
                $up_title = $task->getTitle();
                $query->bindParam(':title', $up_title, PDO::PARAM_STR);
            }

            if($description_updated === true){
                $task->setDescription($json_data->description);
                $up_description = $task->getDescription();
                $query->bindParam(':description', $up_description, PDO::PARAM_STR);
            }

            if($deadline_updated === true){
                $task->setDeadline($json_data->deadline);
                $up_deadline = $task->getDeadline();
                $query->bindParam(':deadline', $up_deadline, PDO::PARAM_STR);
            }

            
            if($completed_updated === true){
                $task->setCompleted($json_data->completed);
                $up_completed = $task->getCompleted();
                $query->bindParam(':completed', $up_completed, PDO::PARAM_INT);
            }

            $query->bindParam(':taskid', $task_id, PDO::PARAM_INT);
            $query->execute();

            $row_count = $query->rowCount();

            if($row_count === 0)
            {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage('Task not updated.');
                $response->send();
                exit;    
            }



            $query = $writeDB->prepare('SELECT task_id, task_title, task_description, DATE_FORMAT(task_deadline, "%d/%m/%Y %H:%i:%s") AS task_deadline, task_complete FROM tbl_tasks WHERE task_id = :taskid');
            $query->bindParam(':taskid', $task_id, PDO::PARAM_INT);
            $query->execute();

            $row_count = $query->rowCount();

            if($row_count === 0)
            {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage('Task not found after update.');
                $response->send();
                exit;    
            }


            $tasksArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC))
            {
                $task = new Task($row['task_id'], $row['task_title'], $row['task_description'], $row['task_deadline'], $row['task_complete'], );
                $tasksArray[] = $task->returnTaskAsArray(); 
            }

            $returnData = array();
            $returnData['rows_returned'] = $row_count;
            $returnData['tasks']  = $tasksArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage('Task updated!');
            $response->setData($returnData);
            $response->send();
            exit;   



        }
        catch(TaskException $ex){
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        }
        catch(PDOException $ex){
            error_log('Database query error' . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Query error on update method.');
            //$response->addMessage('Query error on update method.' .$query_string. $task_id.$up_title.$up_description.$up_deadline.$up_completed);
            $response->send();
            exit;
        }


    }
    else{
        
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage('Invalid server request, not allowed');
        $response->send();
        exit;

    }
}

elseif(array_key_exists("completed", $_GET))
{
    $completed = $_GET['completed'];

    if($completed !== '0' && $completed !== '1')
    {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage('Invalid parameter on completed');
        $response->send();
        exit;
    }
    if($_SERVER['REQUEST_METHOD'] === 'GET' )
    {
        try{
            
            $query = $readDB->prepare('SELECT task_id, task_title, task_description, DATE_FORMAT(task_deadline, "%d/%m/%Y %H:%i:%s") AS task_deadline, task_complete FROM tbl_tasks WHERE task_complete = :completed');
            $query->bindParam(':completed', $completed, PDO::PARAM_INT);
            $query->execute();

            $row_count = $query->rowCount();

            $tasksArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)){
                $task = new Task($row['task_id'], $row['task_title'], $row['task_description'], $row['task_deadline'], $row['task_complete']);
                $tasksArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();
            $returnData['row_returned'] = $row_count;
            $returnData['tasks'] = $tasksArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;


        }
        catch(TaskException $ex){
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Task" . $ex->getMessage());
            $response->send();
            exit;
        }
        catch(PDOException $ex){
            error_log("Data Base Query Error -".$ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Failed to get tasks');
            $response->send();
            exit;
        }
    }
    else{
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage('Server Request method not allowed');
        $response->send();
        exit;            
    }

} 

elseif(array_key_exists("page", $_GET))
{
    if($_SERVER['REQUEST_METHOD'] === 'GET' ){
        $page = $_GET['page'];


        if($page == '' || !is_numeric($page))
        {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage('Invalid value for page parameter');
            $response->send();
            exit;       
        }

        $limit_per_page = 20;

        try{
            $query = $readDB->prepare('SELECT COUNT(task_id) AS totalNoOfTasks FROM tbl_tasks');
            $query->execute();

            $row = $query->fetch(PDO::FETCH_ASSOC);

            $tasksCount = intval($row['totalNoOfTasks']);

            $numOfPages = ceil($tasksCount/$limit_per_page);

            if($numOfPages == 0){
                $numOfPages = 1;
            }
            
            if($page > $numOfPages || $page == 0){
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage('Page not found'.$page.$numOfPages);
                $response->send();
                exit;  
            }
            

            $offset = ($page == 1 ? 0 : ($limit_per_page * ($page - 1)));

            $query = $readDB->prepare('SELECT task_id, task_title, task_description, DATE_FORMAT(task_deadline, "%d/%m/%Y %H:%i:%s") AS task_deadline, task_complete FROM tbl_tasks LIMIT :pglimit  offset :offset');
            $query->bindParam('pglimit', $limit_per_page, PDO::PARAM_INT);
            $query->bindParam('offset', $offset, PDO::PARAM_INT);
            $query->execute();

            $row_count = $query->rowCount();

            $tasksArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)){
                $task = new Task($row['task_id'], $row['task_title'], $row['task_description'], $row['task_deadline'], $row['task_complete']);
                $tasksArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();
            $returnData['row_returned'] = $row_count;
            $returnData['total_rows'] = $tasksCount;
            $returnData['total_pages'] = $numOfPages;
            ($page < $numOfPages ? $returnData['has_next_page'] = true : $returnData['has_next_page'] = false );
            ($page > 1 ? $returnData['has_previous_page'] = true : $returnData['has_previous_page'] = false );
            $returnData['tasks'] = $tasksArray;



            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;


        }
        catch(TaskException $ex){
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit; 
        }
        catch(PDOException $ex){
            error_log("Database Query Error - " .$ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Db Query Error.');
            $response->send();
            exit; 
        }

    }
    else{

        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage('Server Request method not allowed');
        $response->send();
        exit;       
    }
}

elseif(empty($_GET))
{
    if($_SERVER["REQUEST_METHOD"] === "GET" )
    {
        try{

            $query = $readDB->prepare('SELECT task_id, task_title, task_description, DATE_FORMAT(task_deadline, "%d/%m/%Y %H:%i:%s") AS task_deadline, task_complete FROM tbl_tasks');
            $query->execute();

            $row_count = $query->rowCount();

            $tasksArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)){
                $task = new Task($row['task_id'], $row['task_title'], $row['task_description'], $row['task_deadline'], $row['task_complete']);
                $tasksArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();
            $returnData['row_returned'] = $row_count;
            $returnData['tasks'] = $tasksArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;


        }
        catch(TaskException $ex){
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        }
        catch(PDOException $ex){

            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Query Error on DB');
            $response->send();
            exit;

        }
    }
    elseif($_SERVER["REQUEST_METHOD"] === "POST" )
    {
        try{

            if($_SERVER['CONTENT_TYPE'] !== 'application/json')
            {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage('Content Type is not allowed');
                $response->send();
                exit;
            }

            $rawPostData = file_get_contents('php://input');

            if(!$json_data = json_decode($rawPostData))
            {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage('Request body is not valid json');
                $response->send();
                exit;
            }

            if(!isset($json_data->title) || !isset($json_data->completed))
            {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                (!isset($json_data->title) ? $response->addMessage('Title field cannot be empty') : false);
                (!isset($json_data->completed) ? $response->addMessage('Completed status cannot be empty') : false);
                $response->send();
                exit;
            }

            $new_task = new Task(null, $json_data->title, (isset($json_data->description) ? $json_data->description : null), (isset($json_data->deadline) ? $json_data->deadline : null), $json_data->completed );

            $title          = $new_task->getTitle();
            $description    = $new_task->getDescription();
            $deadline       = $new_task->getDeadline();
            $completed      = $new_task->getCompleted();
        
            $query = $writeDB->prepare('INSERT INTO tbl_tasks (task_title, task_description, task_deadline, task_complete) VALUES (:title, :description, STR_TO_DATE(:deadline, \'%d/%m/%Y %H:%i:%s\'), :completed)');
            $query->bindParam(':title', $title, PDO::PARAM_STR);
            $query->bindParam(':description', $description, PDO::PARAM_STR);
            $query->bindParam(':deadline', $deadline, PDO::PARAM_STR);
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);

            $query->execute();

            $row_count = $query->rowCount();

            if($row_count === 0)
            {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage('Failed to create record');
                $response->send();
                exit;
            }

            $lastTaskId = $writeDB->lastInsertId();

            $query = $writeDB->prepare('SELECT task_id, task_title, task_description, DATE_FORMAT(task_deadline, "%d/%m/%Y %H:%i:%s") AS task_deadline, task_complete FROM tbl_tasks WHERE task_id = :taskid');
            $query->bindParam(':taskid', $lastTaskId, PDO::PARAM_INT);
            $query->execute();

            $row_count = $query->rowCount();

            if($row_count === 0)
            {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage('Could not find record');
                $response->send();
                exit;    
            }

            $tasksArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC))
            {
                $task = new Task($row['task_id'],  $row['task_title'], $row['task_description'], $row['task_deadline'], $row['task_complete'],);
                $tasksArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $row_count;
            $returnData['tasks'] = $tasksArray;

            $response = new Response();
            $response->setHttpStatusCode(201);
            $response->setSuccess(true);
            $response->addMessage('Task created successfully');
            $response->setData($returnData);
            $response->send();
            exit;

        }
        catch(TaskException $ex){
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        }
        catch(PDOException $ex){
            error_log('Database Query Error' . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Error Creating Record in Db' . $ex);
            $response->send();
            exit;
        }
    }
    else
    {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage('Invalid Request Method.');
        $response->send();
        exit;
    }
}
else
{
    $response = new Response();
    $response->setHttpStatusCode(404);
    $response->setSuccess(false);
    $response->addMessage('Endpoint not found');
    $response->send();
    exit;
}