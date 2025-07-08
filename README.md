<?php
session_start();
require 'conexion.php';
require 'vendor/autoload.php';

use Sonata\GoogleAuthenticator\GoogleAuthenticator;

$nombre = $_POST['nombre'] ?? '';
$apellido = $_POST['apellido'] ?? '';
$correo = $_POST['correo'] ?? '';
$clave = $_POST['clave'] ?? '';
$sexo = $_POST['sexo'] ?? '';

if (!$nombre || !$apellido || !$correo || !$clave || !$sexo) {
    die("Todos los campos son obligatorios.");
}

// Validar si el correo ya existe
$sql_check = "SELECT id FROM usuarios WHERE correo = ?";
$stmt = $conn->prepare($sql_check);
$stmt->bind_param("s", $correo);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    die("❌ Este correo ya está registrado. <a href='registro.php'>Volver</a>");
}
$stmt->close();

// Generar secreto y hashear contraseña
$g = new GoogleAuthenticator();
$secret = $g->generateSecret();
$clave_hash = password_hash($clave, PASSWORD_DEFAULT);

// Guardar nuevo usuario
$sql_insert = "INSERT INTO usuarios (nombre, apellido, correo, HashMagic, sexo, secret_2fa)
               VALUES (?, ?, ?, ?, ?, ?)";
$stmt = $conn->prepare($sql_insert);
$stmt->bind_param("ssssss", $nombre, $apellido, $correo, $clave_hash, $sexo, $secret);

if ($stmt->execute()) {
    $_SESSION['usuario_id'] = $conn->insert_id;
    $_SESSION['Usuario'] = $correo;
    $_SESSION['secret_2fa'] = $secret;

    // ✅ Generar manualmente la URL otpauth para Google Authenticator
    $nombreCuenta = urlencode($correo);
    $nombreSistema = urlencode('Sistema2FA');
    $urlQR = "otpauth://totp/{$nombreCuenta}?secret={$secret}&issuer={$nombreSistema}";

    echo '<!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Registro Exitoso</title>
        <link rel="stylesheet" href="Estilos\estilosregistro.css">
    </head>
    <body>
    <div class="qr-container">
        <h2>Registro exitoso</h2>
        <p>Escanea este código QR con Google Authenticator o ingresa el código manualmente:</p>
        <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode($urlQR) . '" alt="Código QR 2FA" />
        <br><br>
        <strong>Código secreto manual:</strong><br>
        <code>' . htmlspecialchars($secret) . '</code>
        <br><br>
        <a href="login_form.php">Ir al login</a>
    </div>
    </body>
    </html>';
} else {
    echo "Error al registrar: " . $stmt->error;
}
$stmt->close();
$conn->close();
?>
