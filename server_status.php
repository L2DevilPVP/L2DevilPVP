<?php
header('Content-Type: application/json');

// Configuración de la base de datos
$servername = "localhost"; // Cambia si tu base de datos está en otro host
$username = "root";        // Usuario de MySQL
$password = "whatdafuck25927864";            // Contraseña de MySQL
$dbname = "l2jdb";         // Nombre de la base de datos

// Conectar a MySQL
$conn = new mysqli($servername, $username, $password, $dbname);

// Verificar conexión
if ($conn->connect_error) {
    echo json_encode(["error" => "Database connection failed"]);
    exit;
}

// Comprobar estado del Login Server
$loginStatus = "Offline";
$result = $conn->query("SELECT * FROM gameservers WHERE server_id = 1");
if ($result->num_rows > 0) {
    $loginStatus = "Online";
}

// Comprobar estado del Game Server
$gameStatus = "Offline";
$result = $conn->query("SELECT * FROM gameservers WHERE status = 1");
if ($result->num_rows > 0) {
    $gameStatus = "Online";
}

// Cerrar conexión
$conn->close();

// Responder con JSON
echo json_encode([
    "login_status" => $loginStatus,
    "game_status" => $gameStatus
]);
?>
