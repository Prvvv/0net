<?php
header('Content-Type: text/plain');

// Check if the screenshot file is received
if (isset($_FILES['screenshot']) && $_FILES['screenshot']['error'] === UPLOAD_ERR_OK) {
    // Move the uploaded file to the server's current directory
    $uploadPath = __DIR__ . '/' . basename($_FILES['screenshot']['name']);
    move_uploaded_file($_FILES['screenshot']['tmp_name'], $uploadPath);

    echo "Screenshot uploaded successfully.";

    // Sleep for 10 seconds
    sleep(10);

    // Delete the uploaded file after 6 seconds
    if (file_exists($uploadPath)) {
        unlink($uploadPath);
        echo "\nFile deleted successfully after 6 seconds.";
    } else {
        echo "\nError: Uploaded file not found.";
    }
} else {
    echo "Error uploading screenshot.";
}
?>
