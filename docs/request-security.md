# Permisos y limites de peticiones

`@EnableMethodSecurity` habilita `@PreAuthorize`. El login permite acceso
publico; `/api/auth/me` exige autenticacion. Ademas, `AuthService.currentUser`
comprueba que el UUID solicitado coincida con el subject del JWT o que el
solicitante tenga rol ADMIN. El controlador `/me` siempre usa el subject del
token; no permite seleccionar otro usuario por parametro.

Para futuros metodos de administracion utiliza:

```java
@PreAuthorize("hasRole('ADMIN')")
```

Los roles del JWT se convierten en autoridades con prefijo ROLE_. Los permisos
se comprueban antes de ejecutar el metodo mediante el proxy de Spring. Las
llamadas internas dentro del mismo objeto no atraviesan ese proxy.

## Rate limit

Cada peticion pasa por un filtro antes de validar el Bearer token. Por defecto:

- 120 peticiones por IP en una ventana fija de 60 segundos para todas las rutas.
- 5 POST de login por IP en su propia ventana fija de 60 segundos, incluyendo
  intentos correctos, fallidos y solicitudes invalidas.
- Login tambien consume el limite general. Otros endpoints no consumen su cuota
  especifica de login.

El exceso devuelve HTTP 429, ProblemDetail y Retry-After en segundos. Cambia
estos valores en `.env.local` si lo necesitas:

```dotenv
RATE_LIMIT_REQUESTS=120
RATE_LIMIT_LOGIN_REQUESTS=5
RATE_LIMIT_WINDOW_SECONDS=60
RATE_LIMIT_MAX_CLIENTS=10000
```

El almacenamiento esta en memoria, es seguro frente a concurrencia y conserva
como maximo 10000 IPs. Al alcanzar la capacidad elimina entradas expiradas; si
no hay espacio, rechaza IPs nuevas temporalmente en lugar de borrar contadores
activos. Las ventanas se reinician al vencer y todos los contadores se pierden
al reiniciar la aplicacion. Una ventana fija puede admitir rafagas alrededor
de su limite temporal. No hay bloqueo permanente de cuentas.

La identidad es la IP de la conexion (`remoteAddr`), sin confiar en cabeceras
X-Forwarded-For. Se deshabilita el procesamiento de cabeceras reenviadas para
evitar que el cliente cambie su identidad. Detras de un proxy, todas las
peticiones pueden compartir la IP de ese proxy: configura un proxy de confianza
y la estrategia de identidad antes de desplegar en esa arquitectura. Para
varias replicas, mueve el contador a Redis o al gateway para compartir cuotas.

## Prueba en Postman

Envia seis POST a `/api/auth/login` dentro de un minuto desde la misma IP. El
sexto devuelve 429 aunque uses credenciales validas. Espera Retry-After antes
de repetir. `/api/auth/me` sin token devuelve 401; con un JWT valido devuelve
la identidad autenticada. Un metodo que exige ADMIN devuelve 403 para otro rol.
