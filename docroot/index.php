<?php
echo "<!DOCTYPE html>
<html>
<head>
<title>Page Title</title>
</head>
<body>
  <h1>Hello World!</h1>
  <form method=\"post\">
    First name: <input type=\"text\" name=\"fname\"><br>
    Last name: <input type=\"text\" name=\"lname\"><br>
    <input type=\"submit\" value=\"submit\">
  </form>
</body>
</html>";
var_dump($_POST);