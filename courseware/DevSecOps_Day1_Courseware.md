+-----------------------------------------------------------------------+
| DevSecOps --- Intermediate                                            |
|                                                                       |
| **PARTICIPANT COURSEWARE**                                            |
|                                                                       |
| **DAY 1**                                                             |
|                                                                       |
| Secure Coding · SAST · DAST · Secrets Management · CI/CD Integration  |
|                                                                       |
| *Project: SBI Employee Management System (EMS)*                       |
|                                                                       |
| State Bank of India --- Technology Training Programme                 |
+-----------------------------------------------------------------------+

  ------------------------------------------------------------------------
  **Time**    **Session**        **Topics**
  ----------- ------------------ -----------------------------------------
  10:30 --    **Secure Coding    OWASP Top 10, injection, broken auth,
  11:30       Practices**        code-level controls on EMS

  11:30 --    **SAST Concepts +  Static analysis, SonarQube, taint
  12:15       Tools**            analysis, EMS scan walkthrough

  12:15 --    **Break**          ---
  12:30                          

  12:30 --    **Lab 1: SAST      Hands-on SonarQube scan of EMS, triage,
  1:30        Scan + Fix**       remediation

  1:30 --     **DAST Concepts +  Dynamic testing, OWASP ZAP, scanning
  2:15        Tools**            running apps

  2:15 --     **Lunch**          ---
  3:00                           

  3:00 --     **Lab 2: DAST      ZAP active scan of EMS, vulnerability
  4:00        Scan**             analysis

  4:00 --     **Secrets          HashiCorp Vault, git-secrets, best
  4:45        Management**       practices

  4:45 --     **CI/CD            Pipeline gates, SAST+DAST in GitHub
  5:15        Integration**      Actions

  5:15 --     **Lab + Q&A**      Wrap-up, open questions
  5:30                           
  ------------------------------------------------------------------------

+-----------+----------------------------------------------------------+
| **10:30   | **Module 1: Secure Coding Practices**                    |
| --        |                                                          |
| 11:30**   | OWASP Top 10 · Input Validation · Authentication · Error |
|           | Handling                                                 |
+-----------+----------------------------------------------------------+

**1. Secure Coding Practices**

Secure coding is the practice of writing software that is resilient to
attack from the moment it is written --- not as an afterthought. For a
banking application like EMS, a single exploitable flaw in a REST
endpoint can expose salary data, enable unauthorized access to employee
records, or allow an attacker to pivot deeper into the bank\'s network.
This module covers the most common vulnerability classes and how to
eliminate them at the code level.

**1.1 Why Secure Coding Matters in Banking**

Banks are among the most targeted organizations in the world. RBI\'s IT
Framework for Banks (2011, updated 2023) and CERT-In directives mandate
that development teams follow secure coding standards. The cost of a
post-deployment fix is 6-100x higher than catching the same issue at
code review. The EMS application --- though built as a training vehicle
--- uses the same patterns, frameworks, and data types (PII: salary,
email, phone) found in real banking systems, making it an ideal sandbox
to learn these concepts without real risk.

**1.2 The OWASP Top 10 --- Banking Context**

The Open Web Application Security Project (OWASP) publishes a Top 10
list of the most critical web application security risks. Every item on
this list has caused real incidents at financial institutions. We cover
each one with an EMS-specific example.

**A01:2021 --- Broken Access Control**

Broken Access Control is the #1 risk. It occurs when the application
does not properly enforce what authenticated users are allowed to do. In
banking, this means one user can read or modify another user\'s data.

EMS Example --- The salary field is PII. Only the employee themselves
and HR Admins should see it. A broken access control vulnerability would
allow any authenticated user to call:

  -----------------------------------------------------------------------
  GET /api/v1/employees/42 → returns { salary: 125000 } to ANY
  authenticated user

  -----------------------------------------------------------------------

The fix is Role-Based Access Control (RBAC) enforced at the method level
using Spring Security:

  -----------------------------------------------------------------------
  // Vulnerable --- no access control on salary

  \@GetMapping(\'/{id}\')

  public ResponseEntity\<EmployeeDTO\> getEmployee(@PathVariable Long id)
  {

  return ResponseEntity.ok(employeeService.findById(id));

  }

  // Secure --- salary masked unless requester is ADMIN or the employee
  themselves

  \@GetMapping(\'/{id}\')

  \@PreAuthorize(\"hasRole(\'ADMIN\') or
  \@securityService.isCurrentUser(#id)\")

  public ResponseEntity\<EmployeeDTO\> getEmployee(@PathVariable Long id,

  Authentication auth) {

  EmployeeDTO dto = employeeService.findById(id);

  if (!securityService.isAdminOrSelf(auth, id)) {

  dto.setSalary(null); // mask PII for non-privileged callers

  }

  return ResponseEntity.ok(dto);

  }
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Key Principle**                                                     |
|                                                                       |
| Always enforce authorization at the SERVICE layer, not just at the    |
| API gateway or controller. Defense in depth means every layer checks  |
| permissions independently.                                            |
+-----------------------------------------------------------------------+

**A02:2021 --- Cryptographic Failures**

Cryptographic failures (formerly \'Sensitive Data Exposure\') occur when
sensitive data is transmitted or stored without adequate encryption. In
EMS, the salary, email, and phone fields are PII and must never appear
in plain text in logs, error messages, or unencrypted storage.

-   Always use HTTPS (TLS 1.2+). Spring Boot with spring.ssl.\*
    properties enforces this.

-   Never log sensitive fields. Use \@JsonIgnore on salary in log-facing
    DTOs.

-   Store passwords using BCrypt --- never MD5, SHA-1, or plain text.

-   Database columns holding PII should use column-level encryption
    where the database supports it (Oracle TDE, MySQL Enterprise
    Encryption).

  -----------------------------------------------------------------------
  // Correct password storage in Spring Security --- UserDetailsService

  \@Bean

  public PasswordEncoder passwordEncoder() {

  return new BCryptPasswordEncoder(12); // cost factor 12

  }

  // Masking in logs --- never log the raw EmployeeDTO

  \@Override

  public String toString() {

  return \'Employee{id=\' + id + \', email=\[REDACTED\],
  salary=\[REDACTED\]}\';

  }
  -----------------------------------------------------------------------

**A03:2021 --- Injection**

Injection attacks --- SQL injection, LDAP injection, command injection
--- occur when untrusted data is sent to an interpreter as part of a
command or query. SQL injection remains devastatingly common in banking
applications and can expose entire databases or allow data manipulation.

EMS uses Spring Data JPA, which uses parameterized queries by default.
However, custom JPQL or native queries can introduce injection if
written carelessly:

  -----------------------------------------------------------------------
  // VULNERABLE --- string concatenation in JPQL

  \@Query(\"SELECT e FROM Employee e WHERE e.department.name = \'\" +
  deptName + \"\'\")

  List\<Employee\> findByDeptNameUnsafe(String deptName);

  // SAFE --- parameterized JPQL

  \@Query(\"SELECT e FROM Employee e WHERE e.department.name =
  :deptName\")

  List\<Employee\> findByDeptName(@Param(\"deptName\") String deptName);

  // SAFE --- Spring Data derived query (safest --- no SQL string at all)

  List\<Employee\> findByDepartmentName(String departmentName);
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Banking-Specific Risk**                                             |
|                                                                       |
| SQL injection on an employee search endpoint could allow an attacker  |
| to extract ALL employee salary records with a single crafted query:   |
| ?dept=\' OR \'1\'=\'1. In a real bank system, this could mean mass    |
| PII exposure triggering RBI data breach notification requirements.    |
+-----------------------------------------------------------------------+

**A04:2021 --- Insecure Design**

Insecure design means architectural or design-level flaws that cannot be
fixed by implementation alone. In EMS, the business rule \'a project
cannot move directly from PLANNED to COMPLETED\' is a design control ---
if it is not enforced at the service layer, no amount of
controller-level validation will prevent it.

  -----------------------------------------------------------------------
  // Service layer enforcing project lifecycle state machine

  public Project updateStatus(Long id, ProjectStatus newStatus) {

  Project project = findById(id);

  ProjectStatus current = project.getStatus();

  // State machine --- invalid transitions throw exception

  if (current == ProjectStatus.PLANNED && newStatus ==
  ProjectStatus.COMPLETED) {

  throw new InvalidStateTransitionException(

  \'Project must pass through ACTIVE before COMPLETED\');

  }

  project.setStatus(newStatus);

  return projectRepository.save(project);

  }
  -----------------------------------------------------------------------

**A05:2021 --- Security Misconfiguration**

Security misconfiguration is extremely common in Spring Boot
applications because the framework\'s auto-configuration features can
expose sensitive endpoints if not explicitly secured.

-   Spring Actuator exposes /actuator/env, /actuator/heapdump by default
    --- these MUST be secured.

-   CORS must be explicitly configured --- do not use
    allowedOrigins(\'\*\') in banking apps.

-   Error messages must not leak stack traces, SQL queries, or internal
    class names to the caller.

  -----------------------------------------------------------------------
  \# application.properties --- EMS secure configuration

  \# Restrict Actuator --- only health and info are safe to expose

  management.endpoints.web.exposure.include=health,info

  management.endpoint.health.show-details=when-authorized

  \# Disable Swagger/OpenAPI in production

  springdoc.api-docs.enabled=false \# set true only in dev profile

  springdoc.swagger-ui.enabled=false

  \# Never expose TRACE method

  spring.mvc.hiddenmethod.filter.enabled=false
  -----------------------------------------------------------------------

**A06:2021 --- Vulnerable and Outdated Components**

Using libraries with known CVEs is a common attack vector. The Spring
ecosystem has had critical vulnerabilities (Spring4Shell CVE-2022-22965,
Log4Shell CVE-2021-44228). Banking teams must maintain a Software Bill
of Materials (SBOM) and monitor for CVEs.

-   Use OWASP Dependency-Check (already installed) to scan Maven
    dependencies.

-   Regularly run mvn versions:display-dependency-updates.

-   Subscribe to Spring Security Advisories (spring.io/security).

  -----------------------------------------------------------------------
  \# Scan EMS for known CVEs --- run from project root

  dependency-check.sh \--project EMS \--scan . \--format HTML

  \# Or via Maven plugin

  mvn dependency-check:check
  -----------------------------------------------------------------------

**A07:2021 --- Identification and Authentication Failures**

EMS uses JWT (JSON Web Token) for stateless authentication. Improper JWT
implementation is a critical vulnerability class --- attackers can forge
tokens, bypass expiry, or exploit weak signing secrets.

  -----------------------------------------------------------------------
  // Common JWT mistakes and their fixes

  // MISTAKE 1 --- weak signing secret hardcoded in source

  private static final String SECRET = \'secret123\'; // NEVER DO THIS

  // CORRECT --- read from environment variable or Vault

  \@Value(\'\${jwt.secret}\')

  private String jwtSecret;

  // MISTAKE 2 --- no expiry on token

  Jwts.builder().setSubject(email).signWith(key).compact();

  // CORRECT --- short-lived tokens (15 min for banking)

  Jwts.builder()

  .setSubject(email)

  .setIssuedAt(new Date())

  .setExpiration(new Date(System.currentTimeMillis() + 15 \* 60 \* 1000))

  .signWith(key, SignatureAlgorithm.HS256)

  .compact();
  -----------------------------------------------------------------------

**A08:2021 --- Software and Data Integrity Failures**

This covers CI/CD pipeline poisoning and insecure deserialization. In a
DevSecOps context, it means your build pipeline itself must be secured
--- a compromised pipeline can inject malicious code into deployable
artifacts.

-   Never use auto-update for dependencies in production CI pipelines
    --- pin versions explicitly.

-   Verify checksums of downloaded artifacts.

-   Restrict write access to pipeline configuration files.

**A09:2021 --- Security Logging and Monitoring Failures**

Banks are required by RBI to maintain audit logs for access to sensitive
data. EMS uses Spring Actuator and should be wired to a SIEM. At
minimum, log all authentication events, all access to salary data, and
all failed authorization attempts.

  -----------------------------------------------------------------------
  // Audit logging example --- log every salary access

  \@Aspect

  \@Component

  public class SalaryAccessAuditAspect {

  private static final Logger audit = LoggerFactory.getLogger(\'AUDIT\');

  \@AfterReturning(pointcut = \"execution(\* \*.getEmployee(..))\",

  returning = \'result\')

  public void logSalaryAccess(JoinPoint jp, Object result) {

  Authentication auth =
  SecurityContextHolder.getContext().getAuthentication();

  audit.info(\'SALARY_ACCESS user={} employeeId={} timestamp={}\',

  auth.getName(), extractId(jp), Instant.now());

  }

  }
  -----------------------------------------------------------------------

**A10:2021 --- Server-Side Request Forgery (SSRF)**

SSRF allows an attacker to make the server issue HTTP requests to
internal resources --- useful for probing internal bank infrastructure,
accessing cloud metadata endpoints (AWS/GCP IMDS), or bypassing firewall
rules.

-   Validate and whitelist any URL parameter your application fetches.

-   Never allow user-controlled input to directly form an outbound
    request URL.

-   In banking cloud deployments, the AWS instance metadata endpoint
    (169.254.169.254) is a primary SSRF target.

**1.3 Input Validation --- The First Line of Defence**

EMS uses Bean Validation (Jakarta Validation API) for input validation.
Every field that accepts user input must be validated for type, length,
format, and business rules before it reaches the service layer.

  -----------------------------------------------------------------------
  // EMS EmployeeRequest DTO --- comprehensive validation

  public class EmployeeRequest {

  \@NotBlank(message = \'First name is required\')

  \@Size(min = 2, max = 50, message = \'First name must be 2-50
  characters\')

  \@Pattern(regexp = \'\^\[a-zA-Z\\\\s-\]+\$\',

  message = \'First name must contain only letters, spaces, or hyphens\')

  private String firstName;

  \@NotBlank

  \@Email(message = \'Must be a valid email address\')

  private String email;

  \@NotNull

  \@Positive(message = \'Salary must be a positive value\')

  \@DecimalMax(value = \'9999999.99\', message = \'Salary exceeds maximum
  allowed value\')

  private BigDecimal salary;

  \@NotNull

  \@PastOrPresent(message = \'Hire date cannot be in the future\')

  private LocalDate hireDate;

  }

  // Controller --- activate validation with \@Valid

  \@PostMapping

  \@PreAuthorize(\"hasRole(\'ADMIN\')\")

  public ResponseEntity\<EmployeeDTO\> createEmployee(

  \@Valid \@RequestBody EmployeeRequest request) {

  return
  ResponseEntity.status(201).body(employeeService.create(request));

  }
  -----------------------------------------------------------------------

**1.4 Secure Error Handling**

Error messages are intelligence for attackers. A stack trace revealing
package names, database types, or query structures gives an attacker a
significant advantage. EMS must use a global exception handler that
returns safe, generic messages to the client while logging the full
detail internally.

  -----------------------------------------------------------------------
  // EMS Global Exception Handler

  \@RestControllerAdvice

  public class GlobalExceptionHandler {

  private static final Logger log =
  LoggerFactory.getLogger(GlobalExceptionHandler.class);

  // Validation failure --- safe to return field-level detail

  \@ExceptionHandler(MethodArgumentNotValidException.class)

  public ResponseEntity\<ErrorResponse\> handleValidation(

  MethodArgumentNotValidException ex) {

  Map\<String, String\> errors = new HashMap\<\>();

  ex.getBindingResult().getFieldErrors()

  .forEach(e -\> errors.put(e.getField(), e.getDefaultMessage()));

  return ResponseEntity.badRequest()

  .body(new ErrorResponse(\'Validation failed\', errors));

  }

  // Unexpected error --- NEVER expose stack trace to client

  \@ExceptionHandler(Exception.class)

  public ResponseEntity\<ErrorResponse\> handleGeneral(Exception ex,

  HttpServletRequest request) {

  log.error(\'Unhandled error on {} {}: {}\',

  request.getMethod(), request.getRequestURI(), ex.getMessage(), ex);

  return ResponseEntity.internalServerError()

  .body(new ErrorResponse(\'An internal error occurred. Reference: \'

  \+ UUID.randomUUID())); // correlation ID for support

  }

  }
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **RBI Compliance Note**                                               |
|                                                                       |
| RBI\'s IT Framework Section 3.2 requires that error messages do not   |
| disclose system internals. The pattern above (log detail internally + |
| return correlation ID externally) satisfies this requirement and      |
| enables incident tracing without exposing sensitive data.             |
+-----------------------------------------------------------------------+

+-----------+----------------------------------------------------------+
| **11:30   | **Module 2: Static Application Security Testing (SAST)** |
| --        |                                                          |
| 12:15**   | SonarQube · Semgrep · Taint Analysis · CI Integration    |
+-----------+----------------------------------------------------------+

**2. Static Application Security Testing (SAST)**

Static Application Security Testing analyses source code, bytecode, or
binary code for security vulnerabilities without executing the
application. It is the shift-left cornerstone of DevSecOps --- finding
defects early in the pipeline when they are cheapest to fix.

**2.1 How SAST Works**

SAST tools build an Abstract Syntax Tree (AST) or Control Flow Graph
(CFG) from your source code and then apply two main analysis techniques:

  -----------------------------------------------------------------------
  **Technique**               **What it detects**
  --------------------------- -------------------------------------------
  Pattern matching            Simple anti-patterns: use of deprecated
                              APIs, hardcoded strings, obvious injection
                              patterns

  Taint analysis              Tracks user-controlled data (\'tainted\'
                              sources) through the codebase to sensitive
                              operations (\'sinks\'). Finds injection,
                              XSS, SSRF.

  Data flow analysis          Detects null-pointer issues, resource
                              leaks, use-after-free patterns

  Control flow analysis       Detects unreachable code, infinite loops,
                              improper error propagation
  -----------------------------------------------------------------------

**2.2 SAST in the DevSecOps Pipeline**

SAST fits at two points: in the developer\'s IDE (real-time feedback via
SonarLint) and in the CI pipeline (gate on pull request or commit to
main). The shared SonarQube server in your lab environment is configured
to serve both purposes.

  -----------------------------------------------------------------------
  Developer writes code

  │

  ▼

  SonarLint (VS Code extension) ──► highlights issues in real-time

  │

  ▼

  git push / pull request

  │

  ▼

  CI Pipeline: mvn sonar:sonar ──► SonarQube server analysis

  │ reports to PR / breaks build

  ▼

  Quality Gate PASS / FAIL
  -----------------------------------------------------------------------

**2.3 SonarQube --- Key Concepts**

-   Rules: Individual checks. SonarQube ships 600+ Java rules;
    security-relevant ones are tagged \'owasp-top10\'.

-   Issues: A violation of a rule. Classified as Bug, Vulnerability,
    Security Hotspot, or Code Smell.

-   Quality Gate: A configurable pass/fail condition (e.g. \'no new
    Critical vulnerabilities\').

-   Security Hotspot: Code that may or may not be a vulnerability ---
    requires human review. SonarQube flags potential issues here rather
    than false-positive-prone automatic violations.

  -----------------------------------------------------------------------
  **Severity**    **Meaning**             **Example in EMS**
  --------------- ----------------------- -------------------------------
  Blocker         Must fix before deploy  SQL string concatenation
                                          (injection risk)

  Critical        Fix in current sprint   Hardcoded JWT secret

  Major           Fix before next release Missing \@Valid on controller
                                          method

  Minor           Fix opportunistically   Unused import in security class

  Info            Informational only      Missing Javadoc on public API
  -----------------------------------------------------------------------

**2.4 Configuring SonarQube for EMS**

The trainer has pre-configured a SonarQube project for EMS on the shared
server. Your VM is configured to connect to it. Here is what the
configuration looks like:

  -----------------------------------------------------------------------------
  \# EMS pom.xml --- SonarQube plugin configuration (already present)

  \<properties\>

  \<sonar.host.url\>http://SONAR_SERVER_IP:9000\</sonar.host.url\>

  \<sonar.projectKey\>sbi-ems\</sonar.projectKey\>

  \<sonar.projectName\>SBI Employee Management System\</sonar.projectName\>

  \<sonar.java.source\>17\</sonar.java.source\>

  \<!\-- Exclusions --- test code has different standards \--\>

  \<sonar.exclusions\>\*\*/test/\*\*,\*\*/generated/\*\*\</sonar.exclusions\>

  \</properties\>

  \# Run analysis

  mvn clean verify sonar:sonar -Dsonar.token=YOUR_TOKEN
  -----------------------------------------------------------------------------

**2.5 Reading a SonarQube Report**

After the scan completes, open the SonarQube dashboard. For each issue
you will see:

-   Rule ID and description --- explains exactly what was found and why
    it matters.

-   File + line number --- click to open the code in the browser with
    the problematic line highlighted.

-   Effort --- estimated remediation time.

-   Data flow --- for taint analysis findings, SonarQube shows the
    complete path from source (user input) to sink (unsafe operation).
    This is the most valuable feature for understanding injection
    vulnerabilities.

+-----------------------------------------------------------------------+
| **Lab Preview**                                                       |
|                                                                       |
| In Lab 1 (12:30 -- 1:30), you will run a real SonarQube scan on EMS   |
| and triage the findings. You will fix at least two Critical issues    |
| --- a hardcoded credential and a missing authorization check --- and  |
| re-run the scan to confirm the Quality Gate passes.                   |
+-----------------------------------------------------------------------+

**2.6 Semgrep --- Lightweight Rule-Based Scanning**

Semgrep is a fast, open-source SAST tool that runs rules expressed as
code patterns. Unlike SonarQube (which requires a server), Semgrep runs
entirely from the command line and is ideal for pre-commit hooks and CI
pipelines.

  -----------------------------------------------------------------------
  \# Scan EMS with OWASP Top 10 rules

  semgrep \--config=p/owasp-top-ten ./src

  \# Scan for Java-specific security issues

  semgrep \--config=p/java ./src

  \# Custom rule --- detect hardcoded passwords in EMS

  \# rules/no-hardcoded-secrets.yaml

  rules:

  \- id: no-hardcoded-jwt-secret

  pattern: \|

  private static final String \$SECRET = \'\...\'

  message: Hardcoded secret detected --- use \@Value or Vault

  severity: ERROR

  languages: \[java\]
  -----------------------------------------------------------------------

+-----------+----------------------------------------------------------+
| **12:30   | **Lab 1: SAST Scan + Fix**                               |
| -- 1:30** |                                                          |
|           | Hands-on SonarQube scan of EMS · Triage findings ·       |
|           | Remediate two Critical issues                            |
+-----------+----------------------------------------------------------+

**Lab 1: Static Analysis of EMS**

+-----------------------------------------------------------------------+
| **Lab Objective**                                                     |
|                                                                       |
| Run a SonarQube scan on the EMS project, understand the findings, fix |
| two Critical security issues (hardcoded secret + missing              |
| authorization), re-scan, and verify the Quality Gate passes.          |
+-----------------------------------------------------------------------+

**Lab 1 --- Step-by-Step Instructions**

**Step 1 --- Open the Project**

1.  Open VS Code.

2.  File \> Open Folder \> select the ems/ folder on your Desktop.

3.  Open a Terminal inside VS Code (Ctrl + \` ).

**Step 2 --- Build EMS**

4.  In the terminal, run:

  -----------------------------------------------------------------------
  mvn clean package -DskipTests

  -----------------------------------------------------------------------

5.  Wait for BUILD SUCCESS. This compiles the project so SonarQube can
    analyse the bytecode alongside source.

**Step 3 --- Run the SonarQube Scan**

6.  Run the following (your trainer will provide SONAR_IP and TOKEN):

  -----------------------------------------------------------------------
  mvn sonar:sonar \\

  -Dsonar.host.url=http://SONAR_IP:9000 \\

  -Dsonar.token=YOUR_TOKEN
  -----------------------------------------------------------------------

7.  Wait for the analysis to complete --- approximately 90 seconds for
    EMS.

8.  At the end, the console prints a URL: \'ANALYSIS SUCCESSFUL, you can
    find the results at: http://SONAR_IP:9000/dashboard?id=sbi-ems\'

**Step 4 --- Explore the Dashboard**

9.  Open the URL in Chrome.

10. Note the Quality Gate status (likely FAILED on first scan).

11. Click on \'Vulnerabilities\' in the left panel.

12. Click on the first Critical issue --- read the rule description, the
    affected file, and the data flow diagram.

13. Answer: what is the user-controlled source, and what is the unsafe
    sink?

**Step 5 --- Fix Issue 1: Hardcoded JWT Secret**

Find the following code in JwtUtils.java (or SecurityConfig.java):

  -----------------------------------------------------------------------
  // BEFORE --- hardcoded secret (SonarQube rule: java:S6418)

  private static final String JWT_SECRET = \'SBIBankingSecretKey2024\';

  private static final long JWT_EXPIRY = 86400000;
  -----------------------------------------------------------------------

Replace with environment-driven configuration:

  -----------------------------------------------------------------------
  // AFTER --- injected from application.properties / environment
  variable

  \@Value(\'\${jwt.secret}\')

  private String jwtSecret;

  \@Value(\'\${jwt.expiration.ms:900000}\') // default 15 minutes

  private long jwtExpirationMs;
  -----------------------------------------------------------------------

Add to src/main/resources/application.properties:

  -----------------------------------------------------------------------
  jwt.secret=\${JWT_SECRET} \# read from environment variable

  jwt.expiration.ms=900000 \# 15 minutes --- appropriate for banking
  -----------------------------------------------------------------------

**Step 6 --- Fix Issue 2: Missing Authorization on Salary Endpoint**

Find the employee GET endpoint in EmployeeController.java. It likely
returns salary to any authenticated user. Apply the fix from Module 1:

  -----------------------------------------------------------------------
  \@GetMapping(\'/{id}\')

  \@PreAuthorize(\"hasRole(\'ADMIN\') or
  \@securityService.isCurrentUser(#id)\")

  public ResponseEntity\<EmployeeDTO\> getEmployee(@PathVariable Long id,

  Authentication auth) {

  EmployeeDTO dto = employeeService.findById(id);

  if (!authService.isAdminOrSelf(auth, id)) {

  dto.setSalary(null);

  }

  return ResponseEntity.ok(dto);

  }
  -----------------------------------------------------------------------

**Step 7 --- Re-run the Scan**

14. Rebuild and re-scan:

  -----------------------------------------------------------------------
  mvn clean package -DskipTests sonar:sonar \\

  -Dsonar.host.url=http://SONAR_IP:9000 \\

  -Dsonar.token=YOUR_TOKEN
  -----------------------------------------------------------------------

15. Refresh the SonarQube dashboard.

16. Confirm: the two Critical issues are now resolved.

17. Check if the Quality Gate has changed to PASSED.

+-----------------------------------------------------------------------+
| **Discussion**                                                        |
|                                                                       |
| What other issues did you notice in the dashboard? Make a note of the |
| top 3 findings you would fix next. We will revisit these during the   |
| Day 1 wrap-up.                                                        |
+-----------------------------------------------------------------------+

+-----------+----------------------------------------------------------+
| **1:30 -- | **Module 3: Dynamic Application Security Testing         |
| 2:15**    | (DAST)**                                                 |
|           |                                                          |
|           | OWASP ZAP · Active Scanning · API Fuzzing ·              |
|           | Vulnerability Analysis                                   |
+-----------+----------------------------------------------------------+

**3. Dynamic Application Security Testing (DAST)**

Where SAST analyses code without running it, DAST tests the live,
running application from the outside --- exactly as an attacker would.
DAST sends malicious inputs (SQL injection strings, XSS payloads,
authentication bypass attempts) to your application\'s HTTP endpoints
and analyses the responses for vulnerabilities.

**3.1 SAST vs DAST --- Complementary, Not Competing**

  -----------------------------------------------------------------------
  **SAST**                    **DAST**
  --------------------------- -------------------------------------------
  Analyses source code or     Analyses the running application via HTTP
  bytecode                    

  No application needed to    Application must be running
  run                         

  Finds issues early          Finds issues closer to production reality
  (pre-deployment)            

  Can miss runtime issues     Catches runtime issues SAST cannot see
  (config, deployment)        

  High false positive rate on Lower false positives --- confirms
  complex flows               exploitability

  Good for: injection,        Good for: auth bypass, session issues,
  hardcoded secrets, access   header misconfigs, SSRF
  control logic               
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **DevSecOps Practice**                                                |
|                                                                       |
| Run SAST on every commit. Run DAST on every deployment to the staging |
| environment. Both are required --- a vulnerability that SAST misses   |
| (e.g. a misconfigured CORS header set in an environment variable)     |
| will almost certainly be caught by DAST.                              |
+-----------------------------------------------------------------------+

**3.2 OWASP ZAP --- Architecture and Modes**

OWASP ZAP (Zed Attack Proxy) is the most widely used open-source DAST
tool. It operates as an HTTP proxy that sits between your browser (or
test scripts) and the target application.

-   Spider: Crawls the application, discovers endpoints by following
    links and forms.

-   AJAX Spider: Handles JavaScript-heavy SPAs by using a real browser
    engine.

-   Active Scan: Sends attack payloads to each discovered parameter.
    This is the DAST scan proper.

-   Passive Scan: Analyses traffic passing through the proxy without
    sending any additional requests. Safe to run against production.

-   Fuzzer: Sends a wordlist of payloads to a specific parameter ---
    useful for targeted injection testing.

**3.3 Understanding ZAP Alerts**

  -----------------------------------------------------------------------
  **Risk Level**  **CVSS Range**          **Examples**
  --------------- ----------------------- -------------------------------
  High            7.0 -- 10.0             SQL injection, RCE,
                                          authentication bypass

  Medium          4.0 -- 6.9              Missing security headers, weak
                                          cipher suites

  Low             0.1 -- 3.9              Information disclosure, verbose
                                          error messages

  Informational   N/A                     Fingerprinting data (server
                                          version headers)
  -----------------------------------------------------------------------

**3.4 Scanning EMS with ZAP**

EMS exposes a REST API --- ZAP needs to know the API structure to scan
it effectively. We use the OpenAPI (Swagger) specification that
SpringDoc generates to import all endpoints into ZAP automatically.

  -----------------------------------------------------------------------
  \# Step 1 --- Start EMS (with Docker Compose)

  docker compose up -d

  \# EMS API is now running at http://localhost:8080

  \# Step 2 --- Confirm OpenAPI spec is available

  curl http://localhost:8080/v3/api-docs \| python -m json.tool \| head
  -30

  \# Step 3 --- Import into ZAP

  \# ZAP GUI: Import \> Import an OpenAPI definition from a URL

  \# URL: http://localhost:8080/v3/api-docs

  \# Step 4 --- Configure authentication

  \# ZAP \> Spider \> Authentication \> Form-based or JWT Bearer

  \# Token obtained from: POST /api/v1/auth/login

  \# Step 5 --- Active Scan

  \# Right-click the EMS context \> Attack \> Active Scan
  -----------------------------------------------------------------------

**3.5 Interpreting DAST Findings for EMS**

Typical findings from a ZAP scan of a Spring Boot REST API include:

  -----------------------------------------------------------------------------------------------------
  **Finding**                    **Affected EMS          **Remediation**
                                 Endpoint**              
  ------------------------------ ----------------------- ----------------------------------------------
  Missing                        All endpoints           Add via Spring Security:
  Content-Security-Policy header                         http.headers().contentSecurityPolicy(\...)

  X-Content-Type-Options not set All endpoints           Add header: X-Content-Type-Options: nosniff

  Verbose error messages in 500  /api/v1/employees       Use GlobalExceptionHandler (Module 1 ---
  responses                                              already fixed)

  JWT token in URL parameter     /api/v1/auth/\*\*       Always send JWT in Authorization header, never
                                                         in URL

  CORS:                          All endpoints           Restrict to known origins:
  Access-Control-Allow-Origin:                           allowedOrigins(\'https://ems.sbi.internal\')
  \*                                                     
  -----------------------------------------------------------------------------------------------------

**3.6 Adding Security Headers to EMS**

  -----------------------------------------------------------------------
  // EMS SecurityConfig.java --- add security response headers

  \@Configuration

  \@EnableWebSecurity

  public class SecurityConfig {

  \@Bean

  public SecurityFilterChain filterChain(HttpSecurity http) throws
  Exception {

  http

  .headers(headers -\> headers

  .contentSecurityPolicy(csp -\>

  csp.policyDirectives(

  \"default-src \'self\'; frame-ancestors \'none\'\"))

  .frameOptions(frame -\> frame.deny())

  .httpStrictTransportSecurity(hsts -\> hsts

  .includeSubDomains(true)

  .maxAgeInSeconds(31536000))

  .xssProtection(xss -\> xss.headerValue(

  XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))

  )

  .cors(cors -\> cors.configurationSource(corsConfig()))

  // \... rest of config

  ;

  return http.build();

  }

  \@Bean

  CorsConfigurationSource corsConfig() {

  CorsConfiguration cfg = new CorsConfiguration();

  cfg.setAllowedOrigins(List.of(\'https://ems.sbi.internal\'));

  cfg.setAllowedMethods(List.of(\'GET\', \'POST\', \'PUT\', \'DELETE\'));

  cfg.setAllowedHeaders(List.of(\'Authorization\', \'Content-Type\'));

  UrlBasedCorsConfigurationSource source = new
  UrlBasedCorsConfigurationSource();

  source.registerCorsConfiguration(\'/api/\*\*\', cfg);

  return source;

  }

  }
  -----------------------------------------------------------------------

+-----------+----------------------------------------------------------+
| **3:00 -- | **Lab 2: DAST Scan + Vulnerability Analysis**            |
| 4:00**    |                                                          |
|           | OWASP ZAP active scan of running EMS · Analyse alerts ·  |
|           | Add security headers                                     |
+-----------+----------------------------------------------------------+

**Lab 2: Dynamic Analysis of EMS with ZAP**

+-----------------------------------------------------------------------+
| **Lab Objective**                                                     |
|                                                                       |
| Start EMS, import its OpenAPI spec into ZAP, run a passive and active |
| scan, analyse the findings, and apply the CORS + security header      |
| fixes from Module 3.                                                  |
+-----------------------------------------------------------------------+

**Lab 2 --- Step-by-Step Instructions**

**Step 1 --- Start EMS**

18. Open a terminal and start EMS using Docker Compose:

  -----------------------------------------------------------------------
  docker compose up -d

  -----------------------------------------------------------------------

19. Verify EMS is running:

  -----------------------------------------------------------------------
  curl -s http://localhost:8080/actuator/health \| python -m json.tool

  -----------------------------------------------------------------------

**Step 2 --- Open OWASP ZAP**

20. Double-click the ZAP icon on your Desktop (or launch from Start \>
    ZAP).

21. Select \'No, I do not want to persist this session\' for the lab.

**Step 3 --- Import the OpenAPI Spec**

22. In ZAP, go to: Import \> Import an OpenAPI definition from a URL.

23. Enter: http://localhost:8080/v3/api-docs

24. Click Import. ZAP will discover all EMS endpoints automatically.

25. In the left \'Sites\' panel, you should see http://localhost:8080
    with all /api/v1/\... paths listed.

**Step 4 --- Authenticate ZAP**

26. In a separate terminal, get a JWT token:

  -----------------------------------------------------------------------
  curl -s -X POST http://localhost:8080/api/v1/auth/login \\

  -H \'Content-Type: application/json\' \\

  -d \'{\"email\":\"admin@sbi.com\",\"password\":\"Admin@123\"}\'
  -----------------------------------------------------------------------

27. Copy the token value from the response.

28. In ZAP: Tools \> Options \> HTTP Sessions \> Add New Token.

29. Or use ZAP\'s HTTP Sender script to inject the Authorization header
    on all requests.

**Step 5 --- Run Active Scan**

30. In the Sites panel, right-click http://localhost:8080 \> Attack \>
    Active Scan.

31. Leave default settings. Click Start Scan.

32. The scan takes approximately 5-10 minutes.

33. Watch the Alerts tab populate with findings.

**Step 6 --- Analyse Alerts**

34. Once complete, click the Alerts tab.

35. Sort by Risk (High \> Medium \> Low).

36. For each High/Medium alert, record:

  ------------------------------------------------------------------------
  Alert Name:
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

  Risk Level: High / Medium / Low

  Affected URL:
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

  Description:
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

  Recommended fix:
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
  ------------------------------------------------------------------------

**Step 7 --- Apply Security Header Fix**

Add the security headers from Module 3 to SecurityConfig.java, rebuild
and restart EMS, then re-run the ZAP scan to confirm the Medium-severity
header alerts are gone.

  -----------------------------------------------------------------------
  \# Rebuild EMS

  mvn clean package -DskipTests

  docker compose down && docker compose up -d

  \# Re-scan with ZAP (Active Scan again)

  \# Confirm: X-Content-Type-Options and CSP alerts no longer appear
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Expected Result**                                                   |
|                                                                       |
| After adding the security headers, at least 2-3 Medium alerts should  |
| disappear. Any remaining High alerts from the default EMS are         |
| intentional lab vulnerabilities for discussion.                       |
+-----------------------------------------------------------------------+

+-----------+----------------------------------------------------------+
| **4:00 -- | **Module 4: Secrets Management**                         |
| 4:45**    |                                                          |
|           | HashiCorp Vault · git-secrets · Environment Variables ·  |
|           | Best Practices                                           |
+-----------+----------------------------------------------------------+

**4. Secrets Management**

A \'secret\' is any sensitive configuration value that, if exposed,
could lead to unauthorized access: database passwords, JWT signing keys,
API keys, TLS private keys, and encryption keys. Secrets management is
one of the most frequently mishandled security concerns in banking
DevOps environments.

**4.1 The Secret Sprawl Problem**

Secrets end up in the wrong places because developers take shortcuts.
The following are the most common --- and most dangerous --- patterns
found in real banking codebases:

  -----------------------------------------------------------------------
  // Pattern 1 --- Hardcoded in source (appears in git history FOREVER
  even after deletion)

  private static final String DB_PASSWORD = \'SBI_EMS_DB_2024!\';

  // Pattern 2 --- In application.properties committed to git

  spring.datasource.password=SBI_EMS_DB_2024!

  // Pattern 3 --- In a Docker Compose file committed to git

  environment:

  MYSQL_ROOT_PASSWORD: SBI_EMS_DB_2024!

  // Pattern 4 --- In a CI/CD pipeline script

  mvn deploy -Ddb.password=SBI_EMS_DB_2024!
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Real Incident Pattern**                                             |
|                                                                       |
| A bank developer accidentally committed an AWS access key to a public |
| GitHub repository. Within 4 minutes, automated scanners had found it  |
| and used it to spin up crypto-mining instances. Incident response     |
| cost: \$12,000 in cloud bills + regulatory notification. The key had  |
| been in the repository for 3 years before discovery.                  |
+-----------------------------------------------------------------------+

**4.2 Secret Detection --- git-secrets and detect-secrets**

These tools scan your repository and commit history for known secret
patterns and prevent accidental commits.

  -----------------------------------------------------------------------
  \# Install detect-secrets (already on your VM)

  pip install detect-secrets

  \# Scan the EMS repository for existing secrets

  detect-secrets scan ./ems \> .secrets.baseline

  detect-secrets audit .secrets.baseline

  \# Install as a pre-commit hook --- blocks commits containing secrets

  cat \> .git/hooks/pre-commit \<\< \'EOF\'

  #!/bin/sh

  detect-secrets-hook \--baseline .secrets.baseline

  EOF

  chmod +x .git/hooks/pre-commit

  \# Test it --- try to commit a file with a fake password

  echo \'password=SuperSecret123\' \> test.txt

  git add test.txt && git commit -m \'test\'

  \# Expected: BLOCKED by pre-commit hook
  -----------------------------------------------------------------------

**4.3 The Right Approach: Environment Variables**

The simplest and most portable secrets management approach is
environment variables. Never store secrets in code or config files
committed to version control.

  -------------------------------------------------------------------------------
  \# application.properties --- reference environment variables, not values

  spring.datasource.url=jdbc:mysql://\${DB_HOST:localhost}:3306/\${DB_NAME:ems}

  spring.datasource.username=\${DB_USER}

  spring.datasource.password=\${DB_PASSWORD}

  jwt.secret=\${JWT_SECRET}

  \# At runtime, set these in the environment

  export DB_USER=ems_user

  export DB_PASSWORD=\<from-vault-or-secret-manager\>

  export JWT_SECRET=\<256-bit-random-key\>

  mvn spring-boot:run

  \# In Docker Compose --- use .env file (gitignored)

  \# .env (in .gitignore)

  DB_PASSWORD=realpassword

  JWT_SECRET=realkey

  \# docker-compose.yml

  services:

  ems:

  env_file: .env \# .env is NOT committed to git
  -------------------------------------------------------------------------------

**4.4 HashiCorp Vault --- Enterprise Secrets Management**

For a banking environment, environment variables are a starting point
but not sufficient. HashiCorp Vault provides a centralized, auditable,
access-controlled secrets store that is widely used in Indian banking
environments.

-   Dynamic secrets: Vault can generate short-lived, just-in-time
    database credentials. EMS\'s MySQL password rotates automatically
    --- no static password to steal.

-   Audit log: Every secret access is logged --- who accessed what,
    when. Essential for RBI compliance.

-   Access policies: Different applications get access only to the
    secrets they need (principle of least privilege).

-   Secret leases: Secrets expire automatically and must be renewed ---
    limits the blast radius of a compromise.

  -----------------------------------------------------------------------
  \# Start Vault in dev mode (lab only --- not for production)

  docker run \--rm -d \--name vault \\

  -p 8200:8200 \\

  -e VAULT_DEV_ROOT_TOKEN_ID=root \\

  hashicorp/vault:latest

  \# Access Vault UI: http://localhost:8200 (token: root)

  \# Store EMS secrets in Vault

  export VAULT_ADDR=http://localhost:8200

  export VAULT_TOKEN=root

  vault kv put secret/ems \\

  db_password=SBI_EMS_Secure_2024 \\

  jwt_secret=\$(openssl rand -hex 32)

  \# Retrieve a secret

  vault kv get secret/ems

  vault kv get -field=db_password secret/ems
  -----------------------------------------------------------------------

**4.5 Spring Boot + Vault Integration**

  -----------------------------------------------------------------------
  \# pom.xml --- add Spring Cloud Vault dependency

  \<dependency\>

  \<groupId\>org.springframework.cloud\</groupId\>

  \<artifactId\>spring-cloud-starter-vault-config\</artifactId\>

  \</dependency\>

  \# bootstrap.properties (runs before application.properties)

  spring.cloud.vault.uri=http://localhost:8200

  spring.cloud.vault.token=\${VAULT_TOKEN}

  spring.cloud.vault.kv.enabled=true

  spring.cloud.vault.kv.backend=secret

  spring.cloud.vault.kv.application-name=ems

  \# Now application.properties can reference Vault-sourced values

  spring.datasource.password=\${db_password} \# resolved from Vault
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Banking Best Practices for Secrets**                                |
|                                                                       |
| 1\. Never commit secrets to version control --- use pre-commit hooks. |
|                                                                       |
| 2\. Rotate secrets regularly --- Vault automates this for databases.  |
|                                                                       |
| 3\. Use separate secrets per environment (dev / staging / prod).      |
|                                                                       |
| 4\. Audit who accesses which secrets --- Vault provides this log.     |
|                                                                       |
| 5\. Use short-lived tokens --- limit blast radius of credential       |
| theft.                                                                |
+-----------------------------------------------------------------------+

+-----------+----------------------------------------------------------+
| **4:45 -- | **Module 5: CI/CD Security Integration**                 |
| 5:15**    |                                                          |
|           | Pipeline Gates · SAST in CI · DAST in CD · Fail Fast ·   |
|           | GitHub Actions                                           |
+-----------+----------------------------------------------------------+

**5. CI/CD Security Integration**

Embedding security tools into the CI/CD pipeline transforms security
from a periodic audit into a continuous, automated process. Every code
push triggers a security scan; a failed gate blocks deployment. This is
the operational heart of DevSecOps.

**5.1 The Secure Pipeline Model**

A DevSecOps pipeline for EMS has three security gates:

  -----------------------------------------------------------------------
  **Stage**       **Gate**                **Tool**
  --------------- ----------------------- -------------------------------
  Pre-commit      Block secrets before    detect-secrets hook
                  they reach git          

  Build (CI)      Block Critical          SonarQube Quality Gate
                  vulnerabilities in code 

  Deploy (CD)     Block High-risk         OWASP ZAP DAST
                  vulnerabilities at      
                  runtime                 
  -----------------------------------------------------------------------

**5.2 GitHub Actions Pipeline for EMS**

The following pipeline runs on every push to main or any pull request.
It builds EMS, runs SAST, and blocks the merge if the Quality Gate
fails:

  -----------------------------------------------------------------------
  \# .github/workflows/devsecops.yml

  name: EMS DevSecOps Pipeline

  on:

  push:

  branches: \[ main, develop \]

  pull_request:

  branches: \[ main \]

  jobs:

  security-scan:

  runs-on: ubuntu-latest

  steps:

  \- name: Checkout code

  uses: actions/checkout@v3

  with:

  fetch-depth: 0 \# required for SonarQube blame data

  \- name: Set up Java 17

  uses: actions/setup-java@v3

  with:

  java-version: \'17\'

  distribution: \'temurin\'

  \- name: Detect secrets

  run: \|

  pip install detect-secrets

  detect-secrets scan . \> /tmp/secrets-baseline.json

  if grep -q \'\"is_verified\": false\' /tmp/secrets-baseline.json; then

  echo \'POTENTIAL SECRETS FOUND --- review output below\'

  cat /tmp/secrets-baseline.json

  exit 1

  fi

  \- name: SAST --- SonarQube scan

  env:

  SONAR_TOKEN: \${{ secrets.SONAR_TOKEN }}

  SONAR_HOST_URL: \${{ secrets.SONAR_HOST_URL }}

  run: \|

  mvn clean verify sonar:sonar \\

  -Dsonar.qualitygate.wait=true \\

  -Dsonar.qualitygate.timeout=300

  \# -Dsonar.qualitygate.wait=true makes Maven fail

  \# if the Quality Gate does not pass

  \- name: Build Docker image

  run: docker build -t ems:\${{ github.sha }} .

  \- name: Container scan with Trivy

  run: \|

  trivy image \--severity HIGH,CRITICAL \\

  \--exit-code 1 \\

  ems:\${{ github.sha }}

  \- name: Start EMS for DAST

  run: \|

  docker run -d \--name ems-test \\

  -p 8080:8080 \\

  -e JWT_SECRET=\${{ secrets.JWT_SECRET }} \\

  -e DB_PASSWORD=\${{ secrets.DB_PASSWORD_TEST }} \\

  ems:\${{ github.sha }}

  sleep 20 \# wait for Spring Boot startup

  \- name: DAST --- ZAP API scan

  run: \|

  docker run \--network=host \\

  ghcr.io/zaproxy/zaproxy:stable \\

  zap-api-scan.py \\

  -t http://localhost:8080/v3/api-docs \\

  -f openapi \\

  -r zap-report.html \\

  -x zap-report.xml \\

  \--fail-on-warnings 0

  \- name: Upload ZAP report

  uses: actions/upload-artifact@v3

  with:

  name: zap-report

  path: zap-report.html
  -----------------------------------------------------------------------

**5.3 Quality Gate Configuration**

The SonarQube Quality Gate defines the conditions under which a build is
considered secure. For EMS, configure the following gate on the shared
SonarQube server:

  -----------------------------------------------------------------------
  **Condition**               **Threshold**
  --------------------------- -------------------------------------------
  New Blocker Issues          = 0

  New Critical Issues         = 0

  New Coverage on New Code    \>= 70%

  New Duplicated Lines        \>= 3%

  Security Hotspots Reviewed  = 100%
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Shift-Left Principle**                                              |
|                                                                       |
| The goal is not to block developers --- it is to give them fast,      |
| specific feedback. A pipeline that fails in 3 minutes with a clear    |
| message (\'Critical: Hardcoded secret in JwtUtils.java:12\') is       |
| infinitely more useful than a security review 3 weeks later.          |
+-----------------------------------------------------------------------+

**5.4 Day 1 Summary --- What We Covered**

  -----------------------------------------------------------------------
  **Module**      **Key Takeaway**        **EMS Application**
  --------------- ----------------------- -------------------------------
  Secure Coding   OWASP Top 10 in Java    Added \@PreAuthorize on salary;
                  Spring Boot;            fixed exception handler
                  validation; safe error  
                  handling                

  SAST            SonarQube taint         Scanned EMS; fixed hardcoded
                  analysis; Quality       JWT secret; fixed missing auth
                  Gates; IDE integration  

  DAST            ZAP active scan; API    Scanned running EMS; added
                  scanning via OpenAPI;   security headers; fixed CORS
                  alert triage            

  Secrets Mgmt    Never commit secrets;   Moved JWT secret to environment
                  detect-secrets hook;    variable; explored Vault
                  Vault basics            

  CI/CD           Pipeline gates at       Reviewed full GitHub Actions
                  pre-commit, build, and  pipeline for EMS
                  deploy stages           
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Day 2 Preview**                                                     |
|                                                                       |
| Tomorrow we move to infrastructure security --- Container Security    |
| (hardening Docker images, scanning with Trivy), Infrastructure as     |
| Code Security (Terraform misconfiguration scanning with Checkov), and |
| an end-to-end capstone lab that wires everything together into a      |
| single automated pipeline.                                            |
+-----------------------------------------------------------------------+
