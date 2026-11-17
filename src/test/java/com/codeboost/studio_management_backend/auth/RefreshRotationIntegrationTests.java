package com.codeboost.studio_management_backend.auth;

import com.codeboost.studio_management_backend.auth.config.RefreshTokenProperties;
import com.codeboost.studio_management_backend.auth.dto.LoginResult;
import com.codeboost.studio_management_backend.auth.models.AuthSession;
import com.codeboost.studio_management_backend.auth.repositories.*;
import com.codeboost.studio_management_backend.auth.services.*;
import com.codeboost.studio_management_backend.security.JwtConfig;
import com.codeboost.studio_management_backend.user.enums.RoleCode;
import com.codeboost.studio_management_backend.user.models.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Exercises real transactions and row locks on a disposable in-memory database, never .env.local. */
@SpringJUnitConfig(RefreshRotationIntegrationTests.Config.class)
class RefreshRotationIntegrationTests {
    private static final Instant NOW = Instant.parse("2026-11-16T12:00:00Z");
    @Autowired private RefreshRotationService rotation;
    @Autowired private RefreshTokenService tokens;
    @Autowired private AuthSessionRepository sessions;
    @Autowired private ConsumedRefreshTokenRepository consumed;
    @Autowired private UserRepository users;
    @Autowired private RoleRepository roles;
    @Autowired private UserRoleRepository assignments;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private JwtService jwt;
    @Autowired private LogoutService logout;
    private User user;

    @BeforeEach
    void seed() {
        reset(jwt);
        jdbc.update("delete from consumed_refresh_tokens");
        jdbc.update("delete from auth_sessions");
        jdbc.update("delete from user_roles");
        jdbc.update("delete from roles");
        jdbc.update("delete from users");
        user = new User();
        user.setEmailNormalized("user@example.com");
        user.setPasswordHash("not-used-in-refresh");
        user.setStatus("ACTIVE");
        user = users.save(user);
        Role role = new Role();
        role.setCode(RoleCode.CLIENT);
        role = roles.save(role);
        UserRole assignment = new UserRole();
        assignment.setUser(user);
        assignment.setRole(role);
        assignments.save(assignment);
    }

    @Test
    void rotatesHashAtomicallyKeepsExpiryAndReadsCurrentRoles() {
        var original = tokens.issueForLogin(user);
        jdbc.update("update roles set code = 'ADMIN'");
        LoginResult result = rotation.refresh(original.token());
        assertEquals(List.of("ADMIN"), result.response().user().roles());
        assertEquals(900, result.response().expiresIn());
        assertNotEquals(original.token(), result.refreshToken().token());
        assertEquals(original.sessionId(), result.refreshToken().sessionId());
        assertEquals(original.expiresAt(), result.refreshToken().expiresAt());
        var saved = sessions.findById(original.sessionId()).orElseThrow();
        assertEquals(RefreshTokenService.hash(result.refreshToken().token()), saved.getRefreshTokenHash());
        assertTrue(consumed.existsById(RefreshTokenService.hash(original.token())));
        assertEquals(1, sessions.count());
    }

    @Test
    void reuseRevocationIsCommittedDespiteUnauthorizedException() {
        var original = tokens.issueForLogin(user);
        var replacement = rotation.refresh(original.token());
        assertThrows(RefreshTokenRejectedException.class, () -> rotation.refresh(original.token()));
        assertNotNull(sessions.findById(original.sessionId()).orElseThrow().getRevokedAt());
        assertThrows(RefreshTokenRejectedException.class, () -> rotation.refresh(replacement.refreshToken().token()));
    }

    @Test
    void simultaneousRefreshRequestsHaveOnlyOneWinnerAndRevokeOnReuse() throws Exception {
        var original = tokens.issueForLogin(user);
        var start = new CountDownLatch(1);
        Callable<Boolean> attempt = () -> {
            start.await();
            try { rotation.refresh(original.token()); return true; }
            catch (RefreshTokenRejectedException rejected) { return false; }
        };
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(attempt);
            var second = executor.submit(attempt);
            start.countDown();
            assertNotEquals(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
        }
        assertEquals(1, consumed.count());
        assertNotNull(sessions.findById(original.sessionId()).orElseThrow().getRevokedAt());
    }

    @Test
    void logoutWithConsumedRefreshRevokesOnlyThatFamilyAndSurvivesRepeatedLogout() {
        var original = tokens.issueForLogin(user);
        var otherDevice = tokens.issueForLogin(user);
        var rotated = rotation.refresh(original.token());
        logout.logoutByRefresh(original.token());
        logout.logoutByRefresh(original.token());
        assertNotNull(sessions.findById(original.sessionId()).orElseThrow().getRevokedAt());
        assertThrows(RefreshTokenRejectedException.class, () -> rotation.refresh(rotated.refreshToken().token()));
        assertNotNull(rotation.refresh(otherDevice.token()));
    }

    @Test
    void logoutStillWorksForExpiredRefreshSession() {
        var original = tokens.issueForLogin(user);
        jdbc.update("update auth_sessions set expires_at = ? where id = ?", LocalDateTime.ofInstant(NOW, ZoneOffset.UTC), original.sessionId());
        logout.logoutByRefresh(original.token());
        assertNotNull(sessions.findById(original.sessionId()).orElseThrow().getRevokedAt());
    }

    @Test
    void signingFailureDoesNotConsumeOrReplaceRefreshToken() {
        var original = tokens.issueForLogin(user);
        doThrow(new IllegalStateException("Signing unavailable")).when(jwt).issueToken(any(), anyLong());
        assertThrows(IllegalStateException.class, () -> rotation.refresh(original.token()));
        assertEquals(0, consumed.count());
        assertEquals(RefreshTokenService.hash(original.token()),
                sessions.findById(original.sessionId()).orElseThrow().getRefreshTokenHash());
    }

    @Test
    void rejectsUnknownMalformedExpiredRevokedAndInactiveSessions() {
        assertThrows(RefreshTokenRejectedException.class, () -> rotation.refresh(null));
        assertThrows(RefreshTokenRejectedException.class, () -> rotation.refresh("malformed"));
        assertThrows(RefreshTokenRejectedException.class, () -> rotation.refresh("A".repeat(43)));
        var expired = tokens.issueForLogin(user);
        jdbc.update("update auth_sessions set expires_at = ? where id = ?", LocalDateTime.ofInstant(NOW, ZoneOffset.UTC), expired.sessionId());
        assertThrows(RefreshTokenRejectedException.class, () -> rotation.refresh(expired.token()));
        var revoked = tokens.issueForLogin(user);
        jdbc.update("update auth_sessions set revoked_at = ? where id = ?", LocalDateTime.ofInstant(NOW, ZoneOffset.UTC), revoked.sessionId());
        assertThrows(RefreshTokenRejectedException.class, () -> rotation.refresh(revoked.token()));
        var inactive = tokens.issueForLogin(user);
        jdbc.update("update users set status = 'INACTIVE'");
        assertThrows(RefreshTokenRejectedException.class, () -> rotation.refresh(inactive.token()));
        assertEquals(0, consumed.count());
    }

    @Configuration
    @EnableTransactionManagement
    @EnableJpaRepositories(basePackageClasses = UserRepository.class)
    static class Config {
        @Bean DataSource dataSource() {
            var source = new DriverManagerDataSource("jdbc:h2:mem:refresh_rotation;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=5000", "sa", "");
            var jdbc = new JdbcTemplate(source);
            jdbc.execute("create table users (id bigint generated by default as identity primary key, public_id char(36) not null unique, email_normalized varchar(254) not null unique, password_hash varchar(255) not null, status varchar(32) not null, created_at timestamp(6) default current_timestamp not null)");
            jdbc.execute("create table roles (id bigint generated by default as identity primary key, code varchar(50) not null unique)");
            jdbc.execute("create table user_roles (user_id bigint not null references users(id), role_id bigint not null references roles(id), primary key(user_id, role_id))");
            jdbc.execute("create table auth_sessions (id bigint generated by default as identity primary key, user_id bigint not null references users(id), refresh_token_hash varchar(255) not null unique, expires_at timestamp(6) not null, revoked_at timestamp(6))");
            jdbc.execute("create table consumed_refresh_tokens (token_hash char(64) primary key, session_id bigint not null references auth_sessions(id), consumed_at timestamp(6) not null)");
            return source;
        }
        @Bean JdbcTemplate jdbc(DataSource source) { return new JdbcTemplate(source); }
        @Bean LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource source) {
            var factory = new LocalContainerEntityManagerFactoryBean();
            factory.setDataSource(source);
            factory.setPackagesToScan("com.codeboost.studio_management_backend.auth.models", "com.codeboost.studio_management_backend.user.models");
            factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
            factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "none"));
            return factory;
        }
        @Bean JpaTransactionManager transactionManager(EntityManagerFactory factory) { return new JpaTransactionManager(factory); }
        @Bean Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
        @Bean LogoutService logout(AuthSessionRepository sessions, ConsumedRefreshTokenRepository consumed, Clock clock) {
            return new LogoutService(mock(RevokedAccessTokenRepository.class), sessions, consumed, clock);
        }
        @Bean RefreshTokenService tokens(AuthSessionRepository sessions, Clock clock) {
            return new RefreshTokenService(sessions, new RefreshTokenProperties(), clock);
        }
        @Bean JwtService jwt(Clock clock) {
            var config = new JwtConfig();
            var key = config.jwtSigningKey(Base64.getEncoder().encodeToString(new byte[32]));
            return spy(new JwtService(config.jwtEncoder(key), clock, "test-issuer", 15));
        }
        @Bean RefreshRotationService rotation(AuthSessionRepository sessions, ConsumedRefreshTokenRepository consumed,
                                               UserRoleRepository roles, RefreshTokenService tokens, JwtService jwt, Clock clock) {
            return new RefreshRotationService(sessions, consumed, roles, tokens, jwt, clock);
        }
    }
}
