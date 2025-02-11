<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>L2devilPVP</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100;0,300;0,400;0,500;0,700;0,900;1,100;1,300;1,400;1,500;1,700;1,900&display=swap" rel="stylesheet">


    <link rel="stylesheet" href="css/estilos.css">
</head>
<body>

        <main>

            <div class="contenedor__todo">
                <div class="caja__trasera">
                    <div class="caja__trasera-login">
                        <h3>¿Your data is saved in a database and is secure.</h3>
                        <p>
                        Your data will be archived in a database and is secure, avoiding future damage.</p>
                        <a href="index.html">
                        <button id="btn__iniciar-sesion">BACK</button>
                        </a>
                    </div>
                    <div class="caja__trasera-register">
                        <h3>¿You still don't have an account?</h3>
                        <p>Created New account</p>
                        <button id="btn__registrarse">Regíster</button>
                    </div>
                </div>

                <!--Formulario de Login y registro-->
                <div class="contenedor__login-register">
                    <!--Login-->
                    

                    <!--Register-->
                    <form action="php/registro_usuario.php" method="POST" class="formulario__register">
    <h2>Register L2devilPVP</h2>
    <input type="email" placeholder="email" name="email" required>
    <input type="text" placeholder="User" name="login" required>
    <input type="password" placeholder="password" name="password" required>
    <input type="password" placeholder="Repetir password" name="repeat_password" required>
    <button type="submit">Regíster</button>
</form>



                </div>
            </div>

        </main>

        <script src="assets/js/script.js"></script>
</body>
</html>