# Migraciones de base de datos

La migracion `src/main/resources/db/migration/V1__create_auth_tables.sql` crea
`users`, `roles`, `user_roles`, `auth_sessions` y `password_reset_tokens`.
No inserta usuarios, roles ni otros datos iniciales.

Se excluyen `client_profiles` e `instructor_profiles`. Se pospone
`client_health_profiles` hasta disponer de `client_profiles`, para conservar
su relacion uno a uno mediante `client_id` unico y clave foranea.

El diagrama define campos y relaciones, pero no tipos ni longitudes. La V1 usa
identificadores BIGINT autoincrementales, UUID publicos como CHAR(36), hashes
ASCII sensibles a mayusculas y fechas DATETIME(6). Los campos marcados con `?`
(`revoked_at`, `used_at`) admiten NULL. No se agregan enumeraciones de estados,
roles iniciales ni borrados en cascada, porque no estan especificados.

## Como se selecciona la base de datos

Al arrancar desde la raiz del proyecto, Spring Boot importa `.env.local` como
un archivo de propiedades mediante `spring.config.import`. Las variables
DB_HOST, DB_PORT y DB_NAME forman `spring.datasource.url`; DB_USERNAME y
DB_PASSWORD proporcionan las credenciales. Flyway utiliza ese mismo datasource:
no necesita otra URL ni credenciales separadas.

Con los valores del ejemplo, el destino es la base `studio_management` del servidor
`localhost:3306`. La base debe existir y el usuario debe
tener permisos para crear tablas, indices y claves foraneas.

## Ejecutar cuando quieras aplicar la V1

1. Completa DB_PASSWORD en `.env.local` y comprueba el destino DB_HOST/DB_NAME.
   El archivo se lee como Java properties: no pongas comillas alrededor del
   valor; si contiene barras invertidas, escribelas duplicadas.
2. Desde la raiz del proyecto, ejecuta en PowerShell:

   ```powershell
   .\mvnw.cmd spring-boot:run
   ```

3. Durante el arranque, Flyway aplica V1 y registra el resultado en
   `flyway_schema_history`. Los siguientes arranques solo aplican versiones
   pendientes. Hibernate valida los mapeos, sin crear ni modificar tablas.
4. Comprueba el resultado con un cliente SQL conectado a esa misma base:

   ```sql
   SELECT DATABASE();
   SHOW TABLES;
   SELECT version, description, success
   FROM flyway_schema_history
   ORDER BY installed_rank;
   ```

Este flujo aplica las migraciones al arrancar la aplicacion; crear el archivo
SQL por si solo no modifica la base de datos. Para un arranque sin migraciones:

```powershell
.\mvnw.cmd spring-boot:run '-Dspring-boot.run.arguments=--spring.flyway.enabled=false'
```

No modifiques una V1 ya aplicada: crea una V2 para cambios posteriores. Si la
base ya tiene tablas y no tiene historial Flyway, revisa su estructura antes de
aplicar V1; no habilites baseline-on-migrate para omitir esa revision.
