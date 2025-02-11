<?php
// Configuración de la base de datos
$host = "localhost";
$user = "root"; // Cambia si usas otro usuario
$pass = "whatdafuck25927864"; // Cambia si tienes contraseña en MySQL
$dbname = "l2jdb";

// Conectar a la base de datos
$conn = new mysqli($host, $user, $pass, $dbname);

// Verificar conexión
if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

// Consulta para obtener el Top 10 PKs
$sql = "SELECT char_name, level, pkkills, race FROM characters ORDER BY pkkills DESC LIMIT 10";
$result = $conn->query($sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>L2DevilPVP - Top PK</title>

    <!-- Bootstrap core CSS -->
    <link href="css/bootstrap.min.css" rel="stylesheet">
</head>
<body>

<nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
    <a class="navbar-brand" href="index.html">Back</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExampleDefault"
            aria-controls="navbarsExampleDefault" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button>
</nav>

<br><br><br>
<div class="container">
    <center><h1>Top PK</h1></center>
    <table class="table table-hover table-inverse">
        <thead>
        <tr>
            <th>#</th>
            <th>Nombre</th>
            <th>Nivel</th>
            <th>PKs</th>
            <th>Raza</th>
        </tr>
        </thead>
        <tbody>
        <?php
        if ($result->num_rows > 0) {
            $pos = 1;
            while ($row = $result->fetch_assoc()) {
                $char_name = $row["char_name"];
                $level = $row["level"];
                $pkkills = $row["pkkills"];
                $race = $row["race"];

                // Definir la imagen de la raza según el valor de "race"
                $race_img = "img/races/" . $race . "_0.gif";

                echo "<tr>
                        <th scope='row'>$pos</th>
                        <td>$char_name</td>
                        <td>$level</td>
                        <td>$pkkills</td>
                        <td><img src='$race_img'></td>
                      </tr>";
                $pos++;
            }
        } else {
            echo "<tr><td colspan='5'>No hay datos disponibles</td></tr>";
        }
        ?>
        </tbody>
    </table>
    <hr>

    <footer>
        <p>L2<strong>DevilPVP</strong></p>
    </footer>
</div> <!-- /container -->

<!-- Bootstrap core JavaScript -->
<script src="js/jquery-3.2.1.slim.min.js"></script>
<script src="js/popper.min.js"></script>
<script src="js/bootstrap.min.js"></script>

</body>
</html>

<?php
// Cerrar la conexión
$conn->close();
?>
