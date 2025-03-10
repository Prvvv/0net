<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

header("Access-Control-Allow-Origin: *");

function logToTxt($message) {
    $file = fopen("responses.txt", "a"); // Open the file in append mode
    fwrite($file, $message . "\n"); // Write the message to the file
    fclose($file); // Close the file
}

function isDuplicateRequest($ip) {
    $lockFile = fopen("lock.txt", "a+");

    if (flock($lockFile, LOCK_EX | LOCK_NB)) {
        $content = file_get_contents("ips.txt");
        $ips = explode("\n", $content);
        if (in_array($ip, $ips)) {
            flock($lockFile, LOCK_UN);
            fclose($lockFile);
            return true; // Duplicate request
        } else {
            $content .= $ip . "\n";
            file_put_contents("ips.txt", $content);
            flock($lockFile, LOCK_UN);
            fclose($lockFile);
            return false; // Not a duplicate request
        }
    } else {
        fclose($lockFile);
        return true; // Unable to acquire lock (another request is being processed)
    }
}

// Clear the text files every 2 seconds
if (filemtime("ips.txt") < time() - 2) {
    file_put_contents("ips.txt", "");
}

if (filemtime("responses.txt") < time() - 2) {
    file_put_contents("responses.txt", "");
}

$public_ip = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];

if (!isDuplicateRequest($public_ip)) {
    $response_message = "Public IP: $public_ip, User Agent: $user_agent";
    logToTxt($response_message);
    echo $response_message;
} else {
    echo "Duplicate request from the same IP.";
}
?>

