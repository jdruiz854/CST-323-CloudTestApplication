<?php

require_once "config.php";

$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") 
{
    
    //validates the username to make sure it matches the criteria or is not already in use.
    if (empty(trim($_POST["username"]))) 
    {
        $username_err = "Please enter a username.";
    }
    elseif (!preg_match('/^[a-zA-Z0-9_]+$/', trim($_POST["username"])))
    {
        $username_err = "Username can only contain letters, numbers and underscores.";
    }
    else 
    {
        $sql = "SELECT id FROM users WHERE username = ?";
        
        if ($stmt = $mysqli->prepare($sql))
        {
            $stmt->bind_param("s", $param_username);
            
            $param_username = trim($_POST["username"]);
            
            if (mysqli_stmt_execute($stmt))
            {
                mysqli_stmt_store_result($stmt);
                
                if (mysqli_stmt_num_rows($stmt) == 1)
                {
                    $username_err = "This username is already taken.";
                }
                else
                {
                    $username = trim($_POST["username"]);
                }
            }
            else
            {
                echo "Something went wrong. Please try again later.";
            }
            
    }
    
        mysqli_stmt_close($stmt);
    }  
    
}

if (empty(trim($_POST["password"]))) 
{
    $password_err = "Please enter a password." ;
} 
elseif (strlen(trim($_POST["password"])) < 6)
{
    $password_err = "Password must have at least 6 characters. Please try again.";
}
else 
{
    $password = trim($_POST["password"]);
}

if (empty(trim($_POST["confirm_password"]))) 
{
    $confirm_password_err = "Please confirm your password.";
}
else 
{
    $confirm_password = trim($_POST["confirm_password"]);
    if(empty($password_err) && ($password != $confirm_password))
    {
        $confirm_password_err = "Password did not match. Please try again.";
    }
}

if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) 
{
    $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    
    if ($stmt = mysqli_prepare($link, $sql)) 
    {
        mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
        
        $param_username = $username;
        $param_password = password_hash($password, PASSWORD_DEFAULT);
    }
}



















