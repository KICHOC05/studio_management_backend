# Admin inicial y login JWT

## Estructura

- `auth.repositories`: acceso a usuarios, roles y asignaciones para autenticacion.
- `auth.services`: bootstrap transaccional del admin, verificacion de credenciales y emision de JWT.
- `auth.controllers`: endpoints HTTP.
- `auth.dto`: solicitudes y respuestas sin entidades JPA ni hashes de contrasena.
- `auth.config`: ejecutor del bootstrap al iniciar la aplicacion.
- `security`: BCrypt, firma/validacion JWT, reglas de acceso y errores de filtros.

El login usa `users`, `roles` y `user_roles` de V1. El logout agrega
`revoked_access_tokens` mediante V2; se aplica al siguiente arranque con Flyway.
V2 tambien inserta ADMIN, INSTRUCTOR y CLIENT sin duplicar los roles existentes
ni cambiar sus IDs. `user.enums.RoleCode` representa estos valores en Java;
`roles.code` se mantiene como VARCHAR(50), sin cambiar el esquema de V1.
El UUID publico de `users` se genera mediante el callback JPA existente.

El servidor alojado es MariaDB aunque MySQL Connector/J presente metadatos
compatibles con MySQL. `spring.jpa.database-platform` selecciona MariaDBDialect
explicitamente para generar SQL de ese motor, incluido SELECT ... FOR UPDATE.
Se conserva el controlador y sslMode=PREFERRED; no cambia el esquema. La prueba
MariaDbLockSqlTests verifica el SELECT de bloqueo real generado con ese dialecto
y evita la clausula FOR UPDATE OF que el servidor rechazo.

## Crear el primer administrador

En `.env.local`, completa:

```dotenv
INITIAL_ADMIN_ENABLED=true
INITIAL_ADMIN_EMAIL=tu-correo@example.com
INITIAL_ADMIN_PASSWORD=
```

Escribe una contrasena de al menos 12 caracteres, con un maximo de 72 bytes
UTF-8 (limite BCrypt). No uses comillas para los valores de este archivo,
que Spring carga como Java properties; las barras invertidas se duplican.
Los espacios al inicio de una contrasena necesitan escape en ese formato.
No se incluyen contrasenas predeterminadas ni se imprimen credenciales.

Ya se genero una clave aleatoria local `JWT_SECRET` en Base64 sin modificar
los secretos existentes. `.env.example` deja la clave vacia: para otro entorno,
genera 32 bytes aleatorios, codificalos como Base64 y guardalos en JWT_SECRET.
La aplicacion no inicia con una clave vacia o menor de 32 bytes. Conserva la
misma clave entre reinicios: cambiarla invalida los tokens ya emitidos.

Arranca desde la raiz:

```powershell
.\mvnw.cmd spring-boot:run
```

El arranque aplica migraciones pendientes y, si habilitaste el bootstrap,
crea un usuario `ACTIVE`, guarda su contrasena con BCrypt y le asigna el rol
`ADMIN`, previamente creado por Flyway. Si falta el rol, el inicializador falla
sin guardar el usuario. Todo se guarda en una transaccion en la
base configurada en `.env.local`.

Si ya existe una asignacion ADMIN, no crea otro ni cambia contrasenas. Si no
hay admin y el correo pertenece a una cuenta existente, falla sin promoverla.
Despues del primer arranque correcto, establece INITIAL_ADMIN_ENABLED=false
y borra INITIAL_ADMIN_PASSWORD de `.env.local`.

## Login

`POST http://localhost:8080/api/auth/login`

```json
{
  "email": "tu-correo@example.com",
  "password": "tu-contrasena"
}
```

Devuelve `accessToken`, `tokenType` (Bearer), `expiresIn` (segundos) y `user`
con `publicId`, `email` y `roles`. La respuesta usa Cache-Control: no-store.
Ademas envia una cookie `refresh_token` HttpOnly; el refresh no aparece en el
JSON. Cada login crea una sesion independiente y el JWT incluye `sid` con su
referencia. Los JWT anteriores sin `sid` requieren un nuevo inicio de sesion.
El correo se normaliza a minusculas. Solo las cuentas ACTIVE pueden entrar.
Correo desconocido, contrasena incorrecta y cuenta inactiva devuelven 401 con
el mismo mensaje. Las solicitudes con campos invalidos devuelven 400.

Para consultar la identidad, usa `GET /api/auth/me` con:

```http
Authorization: Bearer <accessToken>
```

## Logout

`POST http://localhost:8080/api/auth/logout`

Sin body. Requiere el token CSRF explicado abajo. Devuelve 204 sin contenido y
elimina la cookie refresh_token. El cliente tambien debe eliminar su access
token local despues de la respuesta correcta.

Si se envia la cookie refresh_token, autentica mediante ella e ignora el Bearer
aunque este vencido. Busca el hash vigente o consumido y bloquea la sesion antes
de marcar revoked_at. Acepta repetir logout con un refresh conocido de esa
sesion, incluso si esta revocada, vencida o su usuario esta inactivo; esto solo
autoriza revocar la sesion y nunca emitir tokens ni consultar datos.

Sin refresh cookie, conserva la alternativa Authorization: Bearer <accessToken>
valido y revoca tambien su jti. Una cookie desconocida o malformada devuelve 401
y se elimina. Sin CSRF valido devuelve 403 y no ejecuta el logout.

Todos los JWT de la sesion revocada dejan de ser aceptados porque se comprueba
su sid en cada peticion. Las otras sesiones del mismo usuario siguen vigentes.
No es un cierre de todas las sesiones.

Se consulta la revocacion y el estado de la sesion en cada validacion JWT:
debe pertenecer al subject, no estar revocada ni vencida y su usuario debe estar
ACTIVE. Esto persiste entre reinicios y se comparte entre instancias con la
misma base. Si no se puede
consultar el almacenamiento, el token se rechaza con 401. Las peticiones que ya
pasaron la validacion antes del logout pueden terminar normalmente.

Una tarea horaria elimina revocaciones cuyo vencimiento ya paso hace cinco
minutos, conservandolas mas alla de la tolerancia de reloj del validador. No se
almacenan los JWT completos. No se modifican V1 ni sus tablas existentes.

## Primera etapa del refresh token: duracion y almacenamiento

Cada login correcto ahora crea una fila independiente en `auth_sessions` dentro
de la misma transaccion. Se generan 32 bytes mediante SecureRandom (256 bits),
se codifican como Base64 URL sin padding y se almacena solamente su hash SHA-256
hexadecimal (64 caracteres). El token original no se registra en logs ni en la
base de datos. El access token conserva sus 15 minutos configurados.

`REFRESH_TOKEN_LIFETIME_DAYS=7` define el vencimiento absoluto de las sesiones
nuevas (configurable de 1 a 90 dias). `expires_at` se calcula en UTC al hacer
login y esta marcado como no actualizable en JPA: una futura rotacion debe
mantener ese vencimiento. Cambiar la configuracion solo afecta a nuevos logins.

La primera etapa preparo el almacenamiento. El login entrega el token por
cookie y vincula el JWT a la sesion; POST /api/auth/refresh ya permite rotarlo.

Se reutiliza la tabla `auth_sessions` de V1, sin agregar otra migracion.

## Cookie de refresh y sesion del JWT

La cookie tiene nombre `refresh_token`, ruta `/api/auth`, sin Domain (solo el
host que la emite), HttpOnly y SameSite=Strict. Su Max-Age se calcula usando
el tiempo restante hasta el vencimiento absoluto de la sesion. No almacenes
el refresh en localStorage ni lo copies al body de solicitudes.

`REFRESH_TOKEN_COOKIE_SECURE=true` es el valor predeterminado y debe mantenerse
con HTTPS. `.env.local` configura false para las pruebas HTTP en localhost.
Al pasar a HTTPS, establece true. El JSON de login conserva el contrato previo:
solo accessToken, tokenType, expiresIn y user. Los resultados internos con el
refresh no se serializan como respuestas y sus toString ocultan los tokens.

Para verificar en Postman:

1. POST /api/auth/login con el correo y contrasena habituales.
2. Revisa Set-Cookie y Cookies: debe aparecer refresh_token con HttpOnly.
3. Usa el accessToken del JSON como Bearer para GET /api/auth/me.
4. Obtiene GET /api/auth/csrf y agrega el header que indica su JSON.
5. POST /api/auth/logout con las cookies y ese header: devuelve 204 y Set-Cookie con Max-Age=0.
6. Reutiliza el accessToken en /me: devuelve 401.

Enviar solo la cookie no autentica /me, que usa Bearer explicito. Refresh y
logout usan la cookie con proteccion CSRF. Logout tambien admite Bearer valido
si no hay refresh cookie. En ambos casos exige CSRF.

## CORS y frontend

`.env.local` y `.env.example` incluyen:

```dotenv
CORS_ALLOWED_ORIGINS=http://localhost:5173
```

Puedes indicar varios origenes separados por comas. Deben ser origenes exactos
http/https, sin rutas, barra final, credenciales ni comodines. Una lista vacia
no habilita ningun origen cruzado. CORS permite credenciales y los headers
Authorization, Content-Type y X-XSRF-TOKEN; expone Retry-After. Los preflight de
origenes permitidos se procesan antes de la autenticacion y CSRF.

Desde el frontend usa `credentials: 'include'` en login, GET /csrf, refresh y
logout (o withCredentials en Axios). Mantiene cookies HttpOnly que JavaScript
no debe leer. Obten el token CSRF del JSON de GET /csrf y envialo en el header
indicado para refresh y logout. CORS no sustituye CSRF.

Secure=true es el valor predeterminado para ambas cookies con HTTPS. Solo
`.env.local` usa REFRESH_TOKEN_COOKIE_SECURE=false para HTTP local. SameSite
permanece Strict: si frontend y API usan sitios distintos en produccion,
revisa el despliegue y la politica de cookies; habilitar CORS por si solo no
modifica SameSite.

El frontend debe compartir una unica promesa de renovacion pendiente dentro
de cada pagina y reutilizar su resultado para las peticiones que esperan. Si
varias pestanas comparten la cookie, coordinalas tambien (por ejemplo, mediante
Web Locks y comunicacion entre pestanas). No implementes renovaciones paralelas
ni reintentes a ciegas un token anterior: su reutilizacion revoca la sesion.

## Migracion preparada para el historial de refresh tokens

`V3__create_consumed_refresh_tokens.sql` agrega `consumed_refresh_tokens`:

- `token_hash`: SHA-256 hexadecimal de 64 caracteres, clave primaria sensible
  a mayusculas; identifica un refresh consumido sin guardar el token original.
- `session_id`: clave foranea obligatoria hacia `auth_sessions.id`, con indice.
  Cada sesion puede tener multiples hashes consumidos.
- `consumed_at`: fecha obligatoria DATETIME(6), que la aplicacion suministrara
  en UTC cuando consuma el token.

La migracion solo crea la tabla vacia. No cambia `auth_sessions`, no reemplaza
sus hashes actuales y no modifica usuarios, roles ni migraciones anteriores.
No duplica expires_at: el vencimiento absoluto se obtiene de la sesion.
La FK usa RESTRICT, coherente con las relaciones de V1; para eliminar una
sesion habra que borrar antes su historial. El historial debe conservarse
hasta el vencimiento de la sesion mas la tolerancia de reloj.

El flujo de rotacion guarda el hash anterior aqui y reemplaza el hash vigente
en una misma transaccion con bloqueo de la sesion. Encontrar un hash consumido
identifica la sesion afectada y la revoca por reutilizacion. El historial no
se elimina al rotar: se conserva para detectar tokens anteriores. Su limpieza
programada queda pendiente; no se debe borrar antes de que venza la sesion.

Crear este archivo no ejecuta SQL. Con Flyway habilitado, V3 se aplicara
automaticamente al proximo arranque de la aplicacion. Para revisar el script
no es necesario arrancar la aplicacion ni conectarse a la base.

## Renovacion rotatoria

`POST http://localhost:8080/api/auth/refresh`, sin body y con autenticacion
configurada como No Auth en Postman. Usa la cookie refresh_token del login.
El endpoint ignora Authorization si se envia accidentalmente un Bearer vencido:
autentica exclusivamente mediante el refresh y requiere proteccion CSRF.

Antes de renovar:

1. Haz login y conserva las cookies de la respuesta.
2. Ejecuta GET /api/auth/csrf, sin autenticacion. Devuelve `headerName` y `token`,
   y establece la cookie XSRF-TOKEN HttpOnly. Conserva tambien esa cookie.
3. En POST /api/auth/refresh agrega el header cuyo nombre devuelve headerName
   (X-XSRF-TOKEN) y como valor el campo token del JSON. No copies el valor crudo
   de la cookie XSRF-TOKEN: el JSON contiene el valor protegido que espera Spring.
4. El servidor responde con otro accessToken y actualiza refresh_token mediante
   Set-Cookie. Postman debe reemplazar la cookie anterior automaticamente.

Puedes guardar el token CSRF como variable de Postman desde la respuesta GET:

```javascript
pm.environment.set("csrfToken", pm.response.json().token);
```

Despues usa `X-XSRF-TOKEN: {{csrfToken}}` al renovar o cerrar sesion, manteniendo las cookies.
El token CSRF puede reutilizarse mientras conserves su cookie; si se pierde,
vuelve a pedir GET /api/auth/csrf.

La renovacion busca el hash actual o consumido, bloquea la sesion mediante
PESSIMISTIC_WRITE y comprueba vencimiento, revocacion y estado ACTIVE. Lee los
roles actuales y emite otro JWT con el mismo sid. Guarda el hash anterior en
consumed_refresh_tokens y reemplaza el hash actual. Mantiene exactamente el
expires_at de la sesion: ninguna renovacion extiende sus siete dias absolutos.

La transaccion usa READ_COMMITTED para ver el historial despues de esperar
un bloqueo. La reutilizacion revoca la sesion y devuelve 401 sin revertir esa
revocacion. Fallos de almacenamiento o firma si revierten la operacion; no se
entregan tokens nuevos si falla el commit. Dos renovaciones simultaneas con el
mismo token provocan un unico ganador y una deteccion de reutilizacion; el
frontend debe coordinar una unica renovacion pendiente y no reintentar a ciegas
el mismo refresh si pierde la respuesta.

- Refresh ausente, desconocido, consumido, vencido o de sesion revocada/inactiva:
  401 y eliminacion de la cookie refresh_token.
- CSRF ausente o incorrecto: 403, sin ejecutar la renovacion.
- Mas de 10 renovaciones por minuto e IP: 429 con Retry-After.

`RATE_LIMIT_REFRESH_REQUESTS=10` configura esa cuota; tambien aplica el limite
general. Otras sesiones del mismo usuario no se revocan por reutilizacion.
No se necesita una nueva migracion: utiliza V3 y debe estar aplicada.

## Alcance de esta version

El JWT se firma con HS256, incluye issuer, audience, subject (UUID publico),
roles, jti y vencimiento. Se valida firma, emisor, audiencia y tiempo de validez.
JWT_ACCESS_TOKEN_MINUTES vale 15 por defecto y acepta de 1 a 60 minutos.
Spring Security tolera el pequeno desfase de reloj habitual entre servidores.
Los roles se convierten a autoridades ROLE_ADMIN, etc., y esta habilitada la
seguridad por metodo para futuros `@PreAuthorize("hasRole('ADMIN')")`.

Esta version implementa tokens de acceso y revocacion individual por logout.
Implementa renovacion y rotacion; `password_reset_tokens` queda para recuperacion
de contrasena. Al vencer la sesion de siete dias debes iniciar sesion de nuevo.
Los cambios de roles se reflejan en el proximo JWT emitido; las cuentas inactivas
y sesiones revocadas se rechazan en cada validacion.
`/me` si consulta el estado actual de la cuenta. Los limites de peticiones y
permisos estan documentados en `request-security.md`. Para despliegue publico
usa HTTPS.

## Verificacion sin base de datos

```powershell
.\mvnw.cmd '-Dtest=LocalApiConfigurationTests,JwtServiceTests,AuthServiceTests,InitialAdminServiceTests,RefreshRotationIntegrationTests' test
```

Las pruebas HTTP usan MockMvc. RefreshRotationIntegrationTests verifica
transacciones y bloqueos con H2 temporal en memoria y tablas de prueba; no
ejecuta las migraciones MySQL ni reemplaza una prueba con MySQL real. Ninguna
de estas pruebas usa las credenciales de .env.local ni escribe en la base remota.
