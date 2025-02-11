<?php
// Conexión a la base de datos
$host = "localhost";
$user = "root"; // Cambia esto si usas otro usuario
$pass = "whatdafuck25927864"; // Si tienes contraseña, agrégala aquí
$db = "l2jdb"; // Nombre de la base de datos

$conn = new mysqli($host, $user, $pass, $db);

// Verificar conexión
if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

// Consulta para obtener el Top PvP
$sql = "SELECT char_name, level, pvpkills, race FROM characters ORDER BY pvpkills DESC LIMIT 10";
$result = $conn->query($sql);
?>

<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <title>L2DevilPVP</title>
  <link href="css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
  <nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
    <a class="navbar-brand" href="index.html">Back</a>
  </nav>

  <br><br><br>
  <div class="container">
    <center><h1>Top PvP</h1></center>
    <table class="table table-hover table-inverse">
      <thead>
        <tr>
          <th>#</th>
          <th>Nombre</th>
          <th>Nivel</th>
          <th>PvPs</th>
          <th>Raza</th>
        </tr>
      </thead>
      <tbody>
        <?php
        if ($result->num_rows > 0) {
            $rank = 1;
            while ($row = $result->fetch_assoc()) {
                echo "<tr>
                        <th scope='row'>{$rank}</th>
                        <td>{$row['char_name']}</td>
                        <td>{$row['level']}</td>
                        <td>{$row['pvpkills']}</td>
                        <td><img src='img/races/{$row['race']}_0.gif'></td>
                      </tr>";
                $rank++;
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
  </div>

  <script src="js/jquery-3.2.1.slim.min.js"></script>
  <script src="js/popper.min.js"></script>
  <script src="js/bootstrap.min.js"></script>
</body>
</html>

<?php
$conn->close();
?>
