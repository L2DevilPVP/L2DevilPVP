<?php
header('Content-Type: application/json');

// Conexión a la base de datos
$servername = "localhost";
$username = "root";
$password = "whatdafuck25927864";
$dbname = "l2jdb";

$conn = new mysqli($servername, $username, $password, $dbname);

// Verificar conexión
if ($conn->connect_error) {
    echo json_encode(["error" => "Database connection failed"]);
    exit;
}

// Obtener cantidad de cuentas
$result = $conn->query("SELECT COUNT(*) AS total_accounts FROM accounts");
$row = $result->fetch_assoc();
$total_accounts = $row['total_accounts'];

// Obtener cantidad total de personajes
$result = $conn->query("SELECT COUNT(*) AS total_characters FROM characters");
$row = $result->fetch_assoc();
$total_characters = $row['total_characters'];

// Obtener cantidad de jugadores en línea
$result = $conn->query("SELECT COUNT(*) AS online_players FROM characters WHERE online = 1");
$row = $result->fetch_assoc();
$online_players = $row['online_players'];

// Cerrar conexión
$conn->close();

// Enviar respuesta JSON
echo json_encode([
    "total_accounts" => $total_accounts,
    "total_characters" => $total_characters,
    "online_players" => $online_players
]);
?>
