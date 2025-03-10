<?php
$data = $_POST['data'];
$file_path = "data.txt";

// Append the data to a local text file
file_put_contents($file_path, $data . PHP_EOL, FILE_APPEND);

// Sleep for a specified duration (e.g., 30 seconds)
sleep(10);

// Remove the contents of the text file
file_put_contents($file_path, "");

echo "Data removed from the file.";
?>
