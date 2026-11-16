# Pruebas locales de la API

`security.SecurityConfig` valida JWT en todos los perfiles, incluido `local`.
Solo `POST /api/auth/login` y `GET /actuator/health` son publicos. Las otras
rutas requieren `Authorization: Bearer <accessToken>`. La API es stateless,
sin formulario de login, HTTP Basic ni CSRF. La configuracion anterior que
permitia todas las rutas fue reemplazada por el login JWT.

Consulta `authentication.md` para configurar JWT y el administrador inicial.

Desde la raiz del proyecto:

```powershell
.\mvnw.cmd spring-boot:run '-Dspring-boot.run.profiles=local'
```

Este comando tambien ejecuta las migraciones Flyway pendientes en la base
configurada en `.env.local`. El perfil no cambia la conexion de base de datos.

`common.exceptions.GlobalExceptionHandler` maneja errores de controladores y
servicios con ProblemDetail (`application/problem+json`): validacion con
`@Valid` y JSON invalido (400), conflictos de integridad (409), autenticacion
(401), acceso denegado (403) y errores inesperados (500). Spring MVC conserva
sus estados habituales para rutas inexistentes, metodos no permitidos, etc.
Los errores inesperados se registran en el servidor sin devolver su mensaje
interno al cliente. Los errores de validacion incluyen `errors` con campo y
mensaje, sin incluir los valores recibidos.

Para devolver un error funcional sencillo desde un futuro servicio puedes usar:

```java
throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado");
```

El advice global no intercepta errores originados en los filtros de seguridad.
`security.SecurityProblemHandler` implementa `AuthenticationEntryPoint` y
`AccessDeniedHandler` para responder tambien con ProblemDetail en esos casos.
