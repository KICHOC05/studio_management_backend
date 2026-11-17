package com.codeboost.studio_management_backend.auth;

import com.codeboost.studio_management_backend.auth.models.AuthSession;
import com.codeboost.studio_management_backend.user.models.User;
import jakarta.persistence.LockModeType;
import org.hibernate.cfg.AvailableSettings;
import org.hibernate.cfg.Configuration;
import org.hibernate.dialect.MariaDBDialect;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.resource.jdbc.spi.StatementInspector;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class MariaDbLockSqlTests {
    @Test
    void configuredDialectExecutesPessimisticLockWithoutMySqlOfClause() throws Exception {
        // H2 executes the generated SELECT only; it is not used to simulate MariaDB metadata.
        var source = new DriverManagerDataSource("jdbc:h2:mem:lock_sql_" + UUID.randomUUID(), "sa", "");
        var jdbc = new JdbcTemplate(source);
        // Keep one connection open for the lifetime of this disposable in-memory database.
        try (var keeper = source.getConnection()) {
            jdbc.execute("create table users (id bigint primary key, public_id char(36), email_normalized varchar(254), password_hash varchar(255), status varchar(32), created_at timestamp(6))");
            jdbc.execute("create table auth_sessions (id bigint primary key, user_id bigint references users(id), refresh_token_hash varchar(255), expires_at timestamp(6), revoked_at timestamp(6))");
            jdbc.update("insert into users (id, public_id, email_normalized, password_hash, status) values (1, ?, 'user@example.com', 'unused', 'ACTIVE')", UUID.randomUUID().toString());
            jdbc.update("insert into auth_sessions (id, user_id, refresh_token_hash, expires_at) values (1, 1, 'hash', current_timestamp)");

            var properties = new Properties();
            try (var input = getClass().getResourceAsStream("/application.properties")) {
                assertNotNull(input);
                properties.load(input);
            }
            List<String> statements = new ArrayList<>();
            var configuration = new Configuration().addAnnotatedClass(User.class).addAnnotatedClass(AuthSession.class);
            configuration.setProperty(AvailableSettings.DIALECT, properties.getProperty("spring.jpa.database-platform"));
            configuration.setProperty("hibernate.boot.allow_jdbc_metadata_access", "false");
            configuration.setProperty(AvailableSettings.HBM2DDL_AUTO, "none");
            configuration.getProperties().put(AvailableSettings.JAKARTA_NON_JTA_DATASOURCE, source);
            configuration.getProperties().put(AvailableSettings.STATEMENT_INSPECTOR,
                    (StatementInspector) sql -> { statements.add(sql); return sql; });

            try (var factory = configuration.buildSessionFactory(); var session = factory.openSession()) {
                assertInstanceOf(MariaDBDialect.class,
                        factory.unwrap(SessionFactoryImplementor.class).getJdbcServices().getDialect());
                var transaction = session.beginTransaction();
                var result = session.createSelectionQuery("from AuthSession s where s.id = :id", AuthSession.class)
                        .setParameter("id", 1L).setLockMode(LockModeType.PESSIMISTIC_WRITE).getSingleResult();
                assertEquals(1L, result.getId());
                transaction.commit();
            }
            String lockingSql = statements.stream().map(sql -> sql.toLowerCase(Locale.ROOT))
                    .filter(sql -> sql.contains("for update")).findFirst().orElseThrow();
            assertFalse(lockingSql.contains("for update of"), lockingSql);
            assertTrue(lockingSql.endsWith("for update"), lockingSql);
        }
    }
}
