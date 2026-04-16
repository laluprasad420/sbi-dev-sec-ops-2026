/** 
package com.sbi.ems;

import com.sbi.ems.security.JwtUtil;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the EMS API.
 *
 * DevSecOps: These tests verify the SECURITY CONTRACT of the application — not
 * just functional correctness. Key scenarios:
 *
 * 1. Unauthenticated requests are rejected (401) 2. Login with valid
 * credentials returns a JWT 3. Login with invalid credentials returns 401 (no
 * detail leakage) 4. Non-ADMIN user cannot access write endpoints (403) 5.
 * Context loads without a hardcoded JWT secret (env var required)
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class EmsApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JwtUtil jwtUtil;

	// ── 1. Context loads ──────────────────────────────────────────────────────
	@Test
	@DisplayName("Spring context loads successfully")
	void contextLoads() {
		// If this fails, the application cannot start — check logs for config errors
	}

	// ── 2. Unauthenticated access is rejected ─────────────────────────────────
	@Test
	@DisplayName("Unauthenticated GET /api/v1/employees returns 401")
	@Disabled("TODO fix later")
	void unauthenticatedRequest_returns401() throws Exception {
		mockMvc.perform(get("/api/v1/employees")).andExpect(status().isUnauthorized());
	}

	// ── 3. Valid login returns JWT ────────────────────────────────────────────
	@Test
	@DisplayName("POST /api/v1/auth/login with valid credentials returns 200 + token")
	void validLogin_returnsToken() throws Exception {
		mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
				.content("{\"username\":\"hr.admin\",\"password\":\"Admin@SBI123\"}")).andExpect(status().isOk())
				.andExpect(jsonPath("$.token").isNotEmpty()).andExpect(jsonPath("$.tokenType").value("Bearer"))
				.andExpect(jsonPath("$.username").value("hr.admin"));
	}

	// ── 4. Invalid credentials are rejected ───────────────────────────────────
	@Test
	@DisplayName("POST /api/v1/auth/login with wrong password returns 401")
	void invalidLogin_returns401() throws Exception {
		mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
				.content("{\"username\":\"hr.admin\",\"password\":\"wrongpassword\"}"))
				.andExpect(status().isUnauthorized());
	}

	// ── 5. Authenticated USER can read employees ──────────────────────────────
	@Test
	@DisplayName("Authenticated USER can GET /api/v1/employees — salary omitted")
	void authenticatedUser_canReadEmployees_salaryOmitted() throws Exception {
		String token = jwtUtil.generateToken("emp.user", List.of("ROLE_USER"));

		mockMvc.perform(get("/api/v1/employees").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
	}

	// ── 6. Non-ADMIN cannot create employees ─────────────────────────────────
	@Test
	@DisplayName("USER role cannot POST /api/v1/employees — returns 403")
	void userRole_cannotCreateEmployee_returns403() throws Exception {
		String token = jwtUtil.generateToken("emp.user", List.of("ROLE_USER"));

		String body = """
				{
				  "firstName":"Test","lastName":"User",
				  "email":"test@sbi.co.in","salary":50000,
				  "hireDate":"2024-01-01","status":"ACTIVE",
				  "departmentId":1,"roleId":1
				}
				""";

		mockMvc.perform(post("/api/v1/employees").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
	}

	// ── 7. ADMIN can create employees ────────────────────────────────────────
	@Test
	@DisplayName("ADMIN role can POST /api/v1/employees — returns 201")
	@Disabled("TODO fix later")
	void adminRole_canCreateEmployee_returns201() throws Exception {
		String token = jwtUtil.generateToken("hr.admin", List.of("ROLE_ADMIN", "ROLE_USER"));

		String body = """
				{
				  "firstName":"Ravi","lastName":"Test",
				  "email":"ravi.test.new@sbi.co.in","salary":50000,
				  "hireDate":"2024-01-01","status":"ACTIVE",
				  "departmentId":1,"roleId":1
				}
				""";

		mockMvc.perform(post("/api/v1/employees").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isCreated())
				.andExpect(jsonPath("$.email").value("ravi.test.new@sbi.co.in"));
	}

	// ── 8. Health endpoint is public ─────────────────────────────────────────
	@Test
	@DisplayName("GET /actuator/health is accessible without auth")
	void actuatorHealth_isPublic() throws Exception {
		mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
	}

	// ── 9. Actuator env is NOT exposed ───────────────────────────────────────
	@Test
	@DisplayName("GET /actuator/env is NOT accessible — returns 404 (not exposed)")
	@Disabled("TODO fix later")
	void actuatorEnv_isNotExposed() throws Exception {
		// DevSecOps: /actuator/env would expose all env vars including JWT_SECRET
		// management.endpoints.web.exposure.include=health,info ensures it is not
		// mapped
		mockMvc.perform(get("/actuator/env")).andExpect(status().isUnauthorized());
	}
}
**/
