<?php
include 'conexion.php'; // Conectar a la base de datos

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Obtener datos del formulario
    $email = trim($_POST['email']);
    $login = trim($_POST['login']);
    $password = trim($_POST['password']);
    $repeat_password = trim($_POST['repeat_password']);

    // Verificar que no estén vacíos
    if (empty($email) || empty($login) || empty($password) || empty($repeat_password)) {
        die("Error: All fields are required.");
    }

    // Verificar que las contraseñas coincidan
    if ($password !== $repeat_password) {
        die("Error: Passwords do not match.");
    }

    // Encriptar la contraseña con SHA1 + Base64
    function encrypt_password($password) {
        return base64_encode(pack("H*", sha1($password)));
    }

    $hashed_pass = encrypt_password($password);

    // Verificar si el usuario ya existe
    $stmt = $conexion->prepare("SELECT login FROM accounts WHERE login = ?");
    $stmt->bind_param("s", $login);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        die("Error: The user already exists.");
    }

    $stmt->close();

    // Insertar el usuario en la base de datos
    $stmt = $conexion->prepare("INSERT INTO accounts (login, password, email, password_visible) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $login, $hashed_pass, $email, $password);

    if ($stmt->execute()) {
        echo "Cuenta creada con éxito.";
        header("Location: ../registro.php?registro=exito");
        exit();
    } else {
        echo "Error registering account.";
    }

    $stmt->close();
    $conexion->close();
} else {
    echo "Error: Access not allowed.";
}
?>
