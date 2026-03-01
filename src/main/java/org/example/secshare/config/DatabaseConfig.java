package org.example.secshare.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@Configuration
public class DatabaseConfig {

    private static final Logger log = LoggerFactory.getLogger(DatabaseConfig.class);

    @Autowired
    private DataSourceProperties dataSourceProperties;

    @Bean
    @Primary
    public DataSource dataSource() {
        String databaseUrl = System.getenv("DATABASE_URL");
        
        if (databaseUrl != null && databaseUrl.startsWith("postgres://")) {
            try {
                URI dbUri = new URI(databaseUrl);
                String userInfo = dbUri.getUserInfo();
                
                if (userInfo == null || !userInfo.contains(":")) {
                    log.error("DATABASE_URL formatı geçersiz: user:password eksik");
                    throw new IllegalArgumentException("DATABASE_URL formatı geçersiz: user:password eksik");
                }
                
                String[] credentials = userInfo.split(":", 2);
                String username = URLDecoder.decode(credentials[0], StandardCharsets.UTF_8);
                String password = URLDecoder.decode(credentials[1], StandardCharsets.UTF_8);
                
                int port = dbUri.getPort() == -1 ? 5432 : dbUri.getPort();
                String dbUrl = "jdbc:postgresql://" + dbUri.getHost() + ':' + port + dbUri.getPath();
                
                log.info("DATABASE_URL parse edildi: host={}, port={}, database={}", 
                    dbUri.getHost(), port, dbUri.getPath());
                
                return DataSourceBuilder.create()
                        .url(dbUrl)
                        .username(username)
                        .password(password)
                        .driverClassName("org.postgresql.Driver")
                        .build();
            } catch (Exception e) {
                log.error("DATABASE_URL parse edilemedi: {}", e.getMessage(), e);
                throw new RuntimeException("DATABASE_URL parse edilemedi: " + e.getMessage(), e);
            }
        }
        
        log.info("DATABASE_URL bulunamadı, application.properties kullanılıyor");
        return DataSourceBuilder.create()
                .url(dataSourceProperties.getUrl())
                .username(dataSourceProperties.getUsername())
                .password(dataSourceProperties.getPassword())
                .driverClassName(dataSourceProperties.getDriverClassName())
                .build();
    }
}
