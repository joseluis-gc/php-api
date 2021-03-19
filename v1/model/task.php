<?php

class TaskException extends Exception{

}

class Task{
    private $id;
    private $title;
    private $description;
    private $deadline;
    private $completed;


    public function __construct($id, $title, $description, $deadline, $completed)
    {
        $this->setId($id);
        $this->setTitle($title);
        $this->setDescription($description);
        $this->setDeadline($deadline);
        $this->setCompleted($completed);
    }


    public function getId(){
        return $this->id;
    }

    public function getTitle(){
        return $this->title;
    }

    
    public function getDescription(){
        return $this->description;
    }

    
    public function getDeadline(){
        return $this->deadline;
    }

    
    public function getCompleted(){
        return $this->completed;
    }


    public function setId($id){
        if(($id !==null) && (!is_numeric($id) || $id <= 0 || $id > 2147483647 || $this->id !== null) ){
            throw new TaskException("Task Id Error");
        }
        
        $this->id = $id;
    }

    public function setTitle($title){
        if(strlen($title) < 0 || strlen($title) > 255){
            throw new TaskException("Task Title Error");
        }

        $this->title = $title;
    }


    public function setDescription($description){
        if(($description !== null) && (strlen($description) > 2000)){
            throw new TaskException("Task Description Error");
        }

        $this->description = $description;
    }

    public function setDeadline($deadline){
        if(($deadline !== null) && date_format(date_create_from_format('d/m/Y H:i:s', $deadline), 'd/m/Y H:i:s') != $deadline ){
            throw new TaskException("Task Deadline Error");
        }

        $this->deadline = $deadline;
    }


    public function setCompleted($completed){
        if($completed === null){
            throw new TaskException("Task Completed Error");
        }
        $this->completed = $completed;
    }


    public function returnTaskAsArray(){
        $task = array();
        $task['id'] = $this->getId();
        $task['title'] = $this->getTitle();
        $task['description'] = $this->getDescription();
        $task['deadline'] = $this->getDeadline();
        $task['completed'] = $this->getCompleted();

        return $task;
    }

}