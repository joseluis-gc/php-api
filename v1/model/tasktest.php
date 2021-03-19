<?php
require_once('task.php');

try{

    $task = new Task(1, "title", "Description", '03/03/2020 15:00:00', 0);
    header("Content-type: application/json;charset=UTF-8");
    echo json_encode($task->returnTaskAsArray());


}catch(TaskException $ex){
    echo "Error" . $ex->getMessage();
}