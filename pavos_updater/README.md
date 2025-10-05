# Pavos Updater

Este programa actualiza los pavos (V-Bucks) de todas las cuentas de Fortnite en la base de datos.

## Uso

1. Asegúrate de que las variables de entorno estén configuradas correctamente en el archivo `.env` en el directorio raíz del proyecto:
   - `DB_HOST`: Host de la base de datos
   - `DB_PORT`: Puerto de la base de datos
   - `DB_USER`: Usuario de la base de datos
   - `DB_PASSWORD`: Contraseña de la base de datos
   - `DB_NAME`: Nombre de la base de datos

2. Compila el programa:
   ```bash
   go build -o pavos_updater.exe pavos.go
   ```

3. Ejecuta el programa:
   ```bash
   ./pavos_updater.exe
   ```

## Funcionalidad

- Se conecta a la base de datos PostgreSQL usando las variables de entorno
- Obtiene todas las cuentas de juego de la base de datos
- Para cada cuenta, actualiza los pavos consultando la API de Epic Games
- Muestra un resumen del proceso con el número de cuentas actualizadas exitosamente y los errores

## Salida

El programa mostrará:
- Estado de conexión a la base de datos
- Progreso de actualización para cada cuenta
- Resumen final con estadísticas de éxito y errores


