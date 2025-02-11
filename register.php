<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = trim($_POST["username"]);
    $pass = trim($_POST["password"]);

    // Verificar que los campos no estén vacíos
    if (empty($user) || empty($pass)) {
        die("Usuario y contraseña son obligatorios.");
    }

    // Conexión a la base de datos
    $conn = new mysqli("localhost", "root", "whatdafuck25927864", "l2jdb");

    if ($conn->connect_error) {
        die("Error de conexión: " . $conn->connect_error);
    }

    // Función para encriptar la contraseña en el formato de L2JFrozen (SHA1 + Base64)
    function encrypt_password($password) {
        return base64_encode(pack("H*", sha1($password)));
    }

    $hashed_pass = encrypt_password($pass);

    // Verificar si el usuario ya existe
    $stmt = $conn->prepare("SELECT login FROM accounts WHERE login = ?");
    $stmt->bind_param("s", $user);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        die("El usuario ya existe.");
    }

    $stmt->close();

    // Insertar el nuevo usuario en la base de datos
    $stmt = $conn->prepare("INSERT INTO accounts (login, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $user, $hashed_pass);

    if ($stmt->execute()) {
        echo "Cuenta creada con éxito.";
    } else {
        echo "Error al registrar: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();
}
?>
