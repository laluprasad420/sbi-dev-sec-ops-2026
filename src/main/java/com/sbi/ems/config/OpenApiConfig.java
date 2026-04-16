package com.sbi.ems.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
//hello world 1
/**
 * OpenAPI / Swagger UI configuration.
 *
 * DevSecOps fixes:
 *   - Fixed organisation from "IBM" to "SBI" (was wrong)
 *   - Registered Bearer JWT security scheme so Swagger UI can send auth headers
 *   - DevSecOps note included: Swagger MUST be disabled in production
 *     (controlled via springdoc.swagger-ui.enabled=false in application-prod.properties)
 */
@Configuration
public class OpenApiConfig {

    @Value("${ems.app.name:SBI Employee Management System}")
    private String appName;

    @Value("${ems.app.version:1.0.0}")
    private String appVersion;

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                // ── API Info ─────────────────────────────────────────────────
                .info(new Info()
                        .title(appName + " — REST API")
                        .version(appVersion)
                        .description(
                            "**SBI Employee Management System** REST API\n\n" +
                            "DevSecOps Training Project — State Bank of India\n\n" +
                            "### Authentication\n" +
                            "1. Call `POST /api/v1/auth/login` with `hr.admin` / `Admin@SBI123`\n" +
                            "2. Copy the `token` from the response\n" +
                            "3. Click **Authorize** above and enter: `Bearer <your-token>`\n\n" +
                            "### Accounts\n" +
                            "| Username | Password | Role | Salary Access |\n" +
                            "|---|---|---|---|\n" +
                            "| `hr.admin` | `Admin@SBI123` | ADMIN | Full access |\n" +
                            "| `emp.user` | `User@SBI123` | USER | Salary masked |\n\n" +
                            "### DevSecOps Note\n" +
                            "⚠️ Swagger UI is **disabled in production** " +
                            "(springdoc.swagger-ui.enabled=false in application-prod.properties).\n" +
                            "Swagger is an attack surface — it documents every endpoint " +
                            "and parameter for potential attackers."
                        )
                        .contact(new Contact()
                                .name("SBI Technology Training Team")
                                .email("training@sbi.co.in"))
                        .license(new License()
                                .name("Internal Training Use Only")
                                .url("https://www.sbi.co.in")))

                // ── Servers ───────────────────────────────────────────────────
                .servers(List.of(
                        new Server()
                            .url("http://localhost:8090")
                            .description("Local Development")))

                // ── JWT Bearer Security Scheme ─────────────────────────────────
                // This registers the "Authorize" button in Swagger UI
                .components(new Components()
                        .addSecuritySchemes("bearerAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Enter your JWT token (without 'Bearer ' prefix)")))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }
}
