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
El correo se normaliza a minusculas. Solo las cuentas ACTIVE pueden entrar.
Correo desconocido, contrasena incorrecta y cuenta inactiva devuelven 401 con
el mismo mensaje. Las solicitudes con campos invalidos devuelven 400.

Para consultar la identidad, usa `GET /api/auth/me` con:

```http
Authorization: Bearer <accessToken>
```

## Logout

`POST http://localhost:8080/api/auth/logout`

Sin body. Envia `Authorization: Bearer <accessToken>`. Devuelve 204 sin contenido.
El cliente debe eliminar el token local despues de la respuesta correcta.
El JWT presentado queda revocado por su identificador `jti` en la base de datos;
usarlo otra vez, incluso para repetir logout, devuelve 401. Otros tokens del
mismo usuario siguen vigentes. No es un cierre de todas las sesiones.

Se consulta la revocacion en cada validacion JWT, por lo que persiste entre
reinicios y se comparte entre instancias que usan la misma base. Si no se puede
consultar el almacenamiento, el token se rechaza con 401. Las peticiones que ya
pasaron la validacion antes del logout pueden terminar normalmente.

Una tarea horaria elimina revocaciones cuyo vencimiento ya paso hace cinco
minutos, conservandolas mas alla de la tolerancia de reloj del validador. No se
almacenan los JWT completos. No se modifican V1 ni sus tablas existentes.

## Alcance de esta version

El JWT se firma con HS256, incluye issuer, audience, subject (UUID publico),
roles, jti y vencimiento. Se valida firma, emisor, audiencia y tiempo de validez.
JWT_ACCESS_TOKEN_MINUTES vale 15 por defecto y acepta de 1 a 60 minutos.
Spring Security tolera el pequeno desfase de reloj habitual entre servidores.
Los roles se convierten a autoridades ROLE_ADMIN, etc., y esta habilitada la
seguridad por metodo para futuros `@PreAuthorize("hasRole('ADMIN')")`.

Esta version implementa tokens de acceso y revocacion individual por logout.
No implementa refresh: `auth_sessions` y `password_reset_tokens` quedan para
esos flujos. Al vencer el token debes iniciar sesion de nuevo.
Cambios de roles/estado no revocan de inmediato un JWT ya emitido;
`/me` si consulta el estado actual de la cuenta. Los limites de peticiones y
permisos estan documentados en `request-security.md`. Para despliegue publico
usa HTTPS.

## Verificacion sin base de datos

```powershell
.\mvnw.cmd '-Dtest=LocalApiConfigurationTests,JwtServiceTests,AuthServiceTests,InitialAdminServiceTests' test
```

Estas pruebas usan repositorios simulados y peticiones MockMvc; no ejecutan
Flyway ni escriben en la base remota.
