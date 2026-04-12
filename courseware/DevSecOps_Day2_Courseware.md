+-----------------------------------------------------------------------+
| DevSecOps --- Intermediate                                            |
|                                                                       |
| **PARTICIPANT COURSEWARE**                                            |
|                                                                       |
| **DAY 2**                                                             |
|                                                                       |
| Container Security · IaC Security · Integrated DevSecOps Pipeline ·   |
| Banking Case Studies                                                  |
|                                                                       |
| *Project: SBI Employee Management System (EMS)*                       |
|                                                                       |
| State Bank of India --- Technology Training Programme                 |
+-----------------------------------------------------------------------+

  ------------------------------------------------------------------------
  **Time**    **Session**        **Topics**
  ----------- ------------------ -----------------------------------------
  10:30 --    **Container        Docker hardening, image scanning, runtime
  11:30       Security**         security, Kubernetes basics

  11:30 --    **Lab 3: Container Trivy scan of EMS image, Dockerfile fix,
  12:15       Scan**             hardened image rebuild

  12:15 --    **Break**          ---
  12:30                          

  12:30 --    **IaC Security**   Terraform security, misconfig patterns,
  1:30                           Checkov policy scanning

  1:30 --     **Lab 4: IaC       Checkov scan of EMS Terraform, fix
  2:15        Scan**             misconfigs, policy-as-code

  2:15 --     **Lunch**          ---
  3:00                           

  3:00 --     **Integrated       End-to-end pipeline; all gates combined;
  4:00        DevSecOps          shift-left metrics
              Pipeline**         

  4:00 --     **Comprehensive    Full pipeline run: code → SAST →
  5:00        Capstone Lab**     container scan → IaC → DAST

  5:00 --     **Case Studies +   Real banking security incidents and
  5:30        Q&A**              lessons learned
  ------------------------------------------------------------------------

+-----------+----------------------------------------------------------+
| **10:30   | **Module 6: Container Security**                         |
| --        |                                                          |
| 11:30**   | Docker Hardening · Image Scanning · Trivy · Runtime      |
|           | Security · Kubernetes RBAC                               |
+-----------+----------------------------------------------------------+

**6. Container Security**

Containers have become the standard deployment unit for modern banking
applications. The EMS application is packaged as a Docker container.
While containers provide consistency and portability, they also
introduce a new attack surface that requires dedicated security controls
at every layer: the image, the runtime, and the orchestration platform.

**6.1 The Container Attack Surface**

Security risks in containers exist at four distinct layers. An attacker
who gains access at any layer can potentially escalate to the others:

  -----------------------------------------------------------------------
  **Layer**       **Risk**                    **EMS Example**
  --------------- --------------------------- ---------------------------
  Base image      Outdated OS packages with   openjdk:17-jdk includes
                  known CVEs; running as root 150+ OS packages, many with
                                              CVEs

  Application     Maven/Spring libraries with Spring Boot 3.x
  dependencies    known vulnerabilities       dependencies scanned by
                                              Trivy

  Container       Excessive Linux             EMS container needs no
  runtime         capabilities; privileged    capabilities --- drop all
                  mode; host namespace access by default

  Orchestration   Overly permissive RBAC;     EMS pod should run with a
  (Kubernetes)    exposed API server; default restricted ServiceAccount
                  service accounts            
  -----------------------------------------------------------------------

**6.2 Writing a Secure Dockerfile for EMS**

The default Dockerfile many developers write for a Spring Boot
application is insecure in multiple ways. Here is the before and after
for EMS:

**Insecure Dockerfile (Common Mistakes)**

  -----------------------------------------------------------------------
  \# INSECURE --- do not use this

  FROM openjdk:17-jdk \# full JDK --- 600MB+ with compilers, tools

  WORKDIR /app

  COPY target/\*.jar app.jar

  EXPOSE 8080

  ENTRYPOINT \[\'java\', \'-jar\', \'app.jar\'\]

  \# Problems:

  \# 1. Running as root (uid 0)

  \# 2. Full JDK included --- massive attack surface

  \# 3. Single layer --- no layer caching, slow rebuilds

  \# 4. No health check defined

  \# 5. No resource limits at image level
  -----------------------------------------------------------------------

**Hardened Dockerfile for EMS (Best Practice)**

  -----------------------------------------------------------------------
  \# Stage 1 --- Build (Maven + JDK --- only used during build)

  FROM eclipse-temurin:17-jdk-alpine AS build

  WORKDIR /workspace

  COPY pom.xml .

  COPY src ./src

  \# Download dependencies in a separate layer (cached)

  RUN mvn dependency:go-offline -q

  \# Build the application

  RUN mvn clean package -DskipTests

  \# Stage 2 --- Runtime (JRE only --- much smaller attack surface)

  FROM eclipse-temurin:17-jre-alpine

  \# Create non-root user --- NEVER run as root

  RUN addgroup -S emsgroup && adduser -S emsuser -G emsgroup

  WORKDIR /app

  \# Copy only the compiled jar --- not source, not build tools

  COPY \--from=build /workspace/target/ems-\*.jar app.jar

  \# Set correct ownership

  RUN chown emsuser:emsgroup app.jar

  \# Switch to non-root user

  USER emsuser

  \# Expose only the application port

  EXPOSE 8080

  \# Health check --- Kubernetes uses this to determine readiness

  HEALTHCHECK \--interval=30s \--timeout=10s \--start-period=60s
  \--retries=3 \\

  CMD wget -qO- http://localhost:8080/actuator/health \|\| exit 1

  \# JVM tuning for containers --- prevents JVM from over-allocating
  memory

  ENTRYPOINT \[\'java\',

  \'-XX:+UseContainerSupport\',

  \'-XX:MaxRAMPercentage=75.0\',

  \'-Djava.security.egd=file:/dev/./urandom\',

  \'-jar\', \'app.jar\'\]
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Why Non-Root Matters**                                              |
|                                                                       |
| If an attacker exploits a vulnerability in EMS (e.g., a path          |
| traversal bug), running as root gives them root on the host --- they  |
| can read /etc/shadow, modify the host filesystem, or escape the       |
| container. Running as a non-root user (uid 1000+) limits the blast    |
| radius to the container\'s own files.                                 |
+-----------------------------------------------------------------------+

**6.3 Multi-Stage Builds and Image Minimization**

The multi-stage Dockerfile above builds EMS in a full JDK environment
but packages only the JRE and the compiled JAR into the final image.
This reduces image size and attack surface dramatically:

  ---------------------------------------------------------------------------
  **Image**                       **Size Comparison**
  ------------------------------- -------------------------------------------
  openjdk:17-jdk (base)           \~600 MB, full JDK tools, compilers,
                                  debuggers

  eclipse-temurin:17-jre-alpine   \~160 MB, JRE only, Alpine Linux
  (base)                          

  EMS single-stage build          \~680 MB (base + source + Maven cache)

  EMS multi-stage build           \~210 MB (JRE + JAR only)

  Distroless (advanced)           \~130 MB --- no shell, no package manager
                                  at all
  ---------------------------------------------------------------------------

**6.4 Trivy --- Container Vulnerability Scanning**

Trivy is a comprehensive security scanner for containers. It scans OS
packages, language-specific packages (Maven/pip/npm), and IaC files for
known CVEs and misconfigurations.

  -----------------------------------------------------------------------
  \# Basic scan --- scan the EMS Docker image

  trivy image ems:latest

  \# Scan with severity filter --- only HIGH and CRITICAL

  trivy image \--severity HIGH,CRITICAL ems:latest

  \# Exit code 1 if any CRITICAL found --- use in CI pipelines

  trivy image \--severity CRITICAL \--exit-code 1 ems:latest

  \# Generate SARIF report for integration with GitHub Security tab

  trivy image \--format sarif \--output trivy-results.sarif ems:latest

  \# Scan the Dockerfile itself for misconfigurations

  trivy config ./Dockerfile

  \# Scan the filesystem (Maven project) for dependency CVEs

  trivy fs \--security-checks vuln ./ems
  -----------------------------------------------------------------------

**6.5 Understanding Trivy Output**

Trivy output groups findings by component type. For EMS you will see:

-   OS packages (alpine): Findings from the Alpine Linux base image
    packages.

-   Java (pom.xml): Findings from Spring Boot and its transitive Maven
    dependencies.

-   Secrets: Any accidentally included credential files or environment
    files.

  -----------------------------------------------------------------------
  \# Sample Trivy output format

  ems:latest (alpine 3.18.4)

  ================================

  Total: 2 (HIGH: 1, CRITICAL: 1)

  Library Vulnerability Severity Installed Fixed Title

  \-\-\-\-\-\-\-\-\-- \-\-\-\-\-\-\-\-\-\-\-\-\-- \-\-\-\-\-\-\-\--
  \-\-\-\-\-\-\-\-\-- \-\-\-\-\-\-\-\-- \-\-\--

  libssl3 CVE-2023-5678 CRITICAL 3.1.3-r0 3.1.4-r0 OpenSSL heap overflow

  musl CVE-2023-1234 HIGH 1.2.4-r0 1.2.4-r1 musl libc buffer overflow

  Java (pom.xml)

  ================================

  Total: 1 (HIGH: 1)

  Library Vulnerability Severity Version Fixed Title

  \-\-\-\-\-\-\-\-\-\-\-\-- \-\-\-\-\-\-\-\-\-\-\-\-\-- \-\-\-\-\-\-\-\--
  \-\-\-\-\-\-\-- \-\-\-\-\-\-\-- \-\-\--

  spring-web CVE-2024-xxxx HIGH 6.0.12 6.1.2 Spring MVC path traversal
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Trivy in CI/CD**                                                    |
|                                                                       |
| In the Day 1 CI/CD pipeline, Trivy runs after the Docker build and    |
| before deployment. \'\--exit-code 1\' causes the pipeline to fail on  |
| any CRITICAL finding. This ensures no critically vulnerable container |
| image is ever deployed to any environment.                            |
+-----------------------------------------------------------------------+

**6.6 Docker Runtime Security**

Even with a hardened image, the container must be started with security
constraints. These are typically set in docker-compose.yml or Kubernetes
pod specs:

  -----------------------------------------------------------------------
  \# docker-compose.yml --- EMS with runtime security constraints

  services:

  ems:

  image: ems:latest

  ports:

  \- \'8080:8080\'

  environment:

  \- JWT_SECRET=\${JWT_SECRET}

  \- DB_PASSWORD=\${DB_PASSWORD}

  \# Security constraints

  security_opt:

  \- no-new-privileges:true \# prevents privilege escalation

  read_only: true \# root filesystem is read-only

  tmpfs:

  \- /tmp \# writable temp space if needed

  cap_drop:

  \- ALL \# drop ALL Linux capabilities

  cap_add: \[\] \# add NONE back

  mem_limit: 512m \# memory limit

  cpus: \'1.0\' \# CPU limit

  user: \'1000:1000\' \# run as non-root

  healthcheck:

  test: \[\'CMD\', \'wget\', \'-qO-\',
  \'http://localhost:8080/actuator/health\'\]

  interval: 30s

  timeout: 10s

  retries: 3
  -----------------------------------------------------------------------

+-----------+----------------------------------------------------------+
| **11:30   | **Lab 3: Container Security Scan**                       |
| --        |                                                          |
| 12:15**   | Build EMS image · Trivy scan · Fix Dockerfile · Rebuild  |
|           | · Re-scan                                                |
+-----------+----------------------------------------------------------+

**Lab 3: Container Scan and Dockerfile Hardening**

+-----------------------------------------------------------------------+
| **Lab Objective**                                                     |
|                                                                       |
| Build the insecure EMS Docker image, scan it with Trivy to identify   |
| vulnerabilities, apply Dockerfile hardening (multi-stage build +      |
| non-root user), rebuild, and re-scan to confirm vulnerability count   |
| drops.                                                                |
+-----------------------------------------------------------------------+

**Lab 3 --- Step-by-Step Instructions**

**Step 1 --- Build the Insecure EMS Image**

1.  In the terminal, navigate to the ems/ project folder.

2.  The insecure Dockerfile is at ems/Dockerfile.insecure. Build it:

  -----------------------------------------------------------------------
  docker build -f Dockerfile.insecure -t ems:insecure .

  -----------------------------------------------------------------------

**Step 2 --- Scan the Insecure Image with Trivy**

3.  Run Trivy against the insecure image:

  -----------------------------------------------------------------------
  trivy image \--severity HIGH,CRITICAL ems:insecure

  -----------------------------------------------------------------------

4.  Note the total number of HIGH and CRITICAL findings. Write it here:
    \_\_\_\_\_\_\_

5.  Identify the top 3 libraries with the most Critical findings.

**Step 3 --- Inspect the Dockerfile**

6.  Open Dockerfile.insecure in VS Code. List all the security problems
    you can spot:

  ----------------------------------------------------------------------------------------------------
  1\.
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

  2\.
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

  3\.
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

  4\.
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
  ----------------------------------------------------------------------------------------------------

**Step 4 --- Apply the Hardened Dockerfile**

7.  The hardened Dockerfile is at ems/Dockerfile.secure (pre-created for
    you based on Module 6).

8.  Review it in VS Code. Confirm: multi-stage build, non-root user,
    JRE-only runtime, HEALTHCHECK.

9.  Build the hardened image:

  -----------------------------------------------------------------------
  docker build -f Dockerfile.secure -t ems:secure .

  -----------------------------------------------------------------------

**Step 5 --- Re-scan the Hardened Image**

10. Scan the hardened image:

  -----------------------------------------------------------------------
  trivy image \--severity HIGH,CRITICAL ems:secure

  -----------------------------------------------------------------------

11. Record the new total: \_\_\_\_\_\_\_ (should be significantly lower)

12. Compare image sizes:

  -----------------------------------------------------------------------
  docker images \| grep ems

  -----------------------------------------------------------------------

**Step 6 --- Scan the Dockerfile for Misconfigs**

13. Run Trivy\'s config scan on the hardened Dockerfile:

  -----------------------------------------------------------------------
  trivy config ./Dockerfile.secure

  -----------------------------------------------------------------------

14. Are there any remaining misconfigurations flagged? Note them.

+-----------------------------------------------------------------------+
| **Discussion**                                                        |
|                                                                       |
| Why did the vulnerability count drop? It is not because we \'fixed\'  |
| CVEs --- it is because we eliminated hundreds of packages (full JDK,  |
| Alpine extras) that are not needed at runtime. Reducing attack        |
| surface is as important as patching.                                  |
+-----------------------------------------------------------------------+

+-----------+----------------------------------------------------------+
| **12:30   | **Module 7: Infrastructure as Code Security**            |
| -- 1:30** |                                                          |
|           | Terraform Misconfigurations · Checkov · Policy-as-Code · |
|           | Drift Detection                                          |
+-----------+----------------------------------------------------------+

**7. Infrastructure as Code Security**

Infrastructure as Code (IaC) means defining servers, networks,
databases, and security controls in code files rather than through
manual console clicks. For banking environments deploying on cloud
(AWS/Azure/GCP) or private cloud, IaC is the primary way infrastructure
is provisioned. A misconfigured Terraform file can create an open S3
bucket, a publicly accessible database, or a VM with no firewall --- at
the speed of automation.

**7.1 Why IaC Security is Critical in Banking**

The Capital One breach of 2019 exposed 100 million customer records.
Root cause: a misconfigured AWS Web Application Firewall created through
manual console configuration (not IaC --- which is itself an argument
for IaC). Had IaC been used with policy scanning, the misconfiguration
would have been caught before deployment. Key IaC security principles:

-   Immutable infrastructure: never modify running infrastructure
    manually --- all changes through IaC.

-   Every IaC change goes through version control and code review ---
    just like application code.

-   Policy scanning (Checkov) runs on every IaC change before it is
    applied.

-   Drift detection: detect when actual infrastructure diverges from the
    IaC definition.

**7.2 Common IaC Misconfigurations**

The following misconfigurations are the most commonly found in Terraform
configurations for banking applications. EMS deploys to infrastructure
that includes an RDS MySQL database, an ECS/Kubernetes cluster, and a
load balancer. All of these can be misconfigured.

**Misconfiguration 1: Database Publicly Accessible**

  -----------------------------------------------------------------------
  \# INSECURE --- RDS instance accessible from the internet

  resource \'aws_db_instance\' \'ems_mysql\' {

  engine = \'mysql\'

  instance_class = \'db.t3.medium\'

  username = \'admin\'

  password = \'SBI_EMS_DB_2024!\' \# hardcoded!

  publicly_accessible = true \# CRITICAL MISCONFIGURATION

  skip_final_snapshot = true

  }

  \# SECURE --- database only accessible from within the VPC

  resource \'aws_db_instance\' \'ems_mysql\' {

  engine = \'mysql\'

  instance_class = \'db.t3.medium\'

  username = \'admin\'

  password = var.db_password \# from Vault/variable

  publicly_accessible = false \# not internet-accessible

  db_subnet_group_name = aws_db_subnet_group.private.name

  vpc_security_group_ids = \[aws_security_group.rds_sg.id\]

  storage_encrypted = true \# encrypt at rest

  deletion_protection = true \# prevent accidental deletion

  skip_final_snapshot = false \# take snapshot on deletion

  }
  -----------------------------------------------------------------------

**Misconfiguration 2: S3 Bucket Publicly Accessible**

  -----------------------------------------------------------------------
  \# INSECURE --- public S3 bucket (common misconfiguration)

  resource \'aws_s3_bucket\' \'ems_reports\' {

  bucket = \'sbi-ems-reports\'

  }

  resource \'aws_s3_bucket_acl\' \'ems_reports_acl\' {

  bucket = aws_s3_bucket.ems_reports.id

  acl = \'public-read\' \# CRITICAL --- all employee reports visible to
  internet

  }

  \# SECURE

  resource \'aws_s3_bucket_public_access_block\' \'ems_reports\' {

  bucket = aws_s3_bucket.ems_reports.id

  block_public_acls = true

  block_public_policy = true

  ignore_public_acls = true

  restrict_public_buckets = true

  }

  resource \'aws_s3_bucket_server_side_encryption_configuration\'
  \'ems_enc\' {

  bucket = aws_s3_bucket.ems_reports.id

  rule {

  apply_server_side_encryption_by_default {

  sse_algorithm = \'aws:kms\'

  }

  }

  }
  -----------------------------------------------------------------------

**Misconfiguration 3: Security Group --- All Traffic Allowed**

  -----------------------------------------------------------------------
  \# INSECURE --- security group allows ALL inbound traffic

  resource \'aws_security_group\' \'ems_sg\' {

  ingress {

  from_port = 0

  to_port = 65535

  protocol = \'-1\'

  cidr_blocks = \[\'0.0.0.0/0\'\] \# allows all traffic from internet

  }

  }

  \# SECURE --- allow only port 443 from internet; port 8080 from load
  balancer only

  resource \'aws_security_group\' \'ems_sg\' {

  ingress {

  description = \'HTTPS from internet\'

  from_port = 443

  to_port = 443

  protocol = \'tcp\'

  cidr_blocks = \[\'0.0.0.0/0\'\]

  }

  ingress {

  description = \'App port from load balancer only\'

  from_port = 8080

  to_port = 8080

  protocol = \'tcp\'

  security_groups = \[aws_security_group.alb_sg.id\] \# NOT from internet

  }

  egress {

  from_port = 0

  to_port = 0

  protocol = \'-1\'

  cidr_blocks = \[\'0.0.0.0/0\'\]

  }

  }
  -----------------------------------------------------------------------

**7.3 Checkov --- Policy Scanning for IaC**

Checkov is an open-source static analysis tool for Terraform,
CloudFormation, Kubernetes manifests, and Dockerfiles. It runs over
1,000 built-in security policies aligned with CIS benchmarks, HIPAA,
PCI-DSS, and SOC 2.

  -----------------------------------------------------------------------
  \# Install Checkov (already on your VM)

  pip install checkov

  \# Scan the EMS Terraform directory

  checkov -d ./terraform/ems

  \# Scan a specific file

  checkov -f ./terraform/ems/main.tf

  \# Scan and output JUnit XML for CI pipeline integration

  checkov -d ./terraform/ems \--output junitxml \> checkov-results.xml

  \# Show only FAILED checks

  checkov -d ./terraform/ems \--compact

  \# Scan against specific compliance framework

  checkov -d ./terraform/ems \--framework terraform \--check CKV_AWS\_\*

  \# Skip a specific check with justification (documented suppression)

  \# Add to resource block in Terraform:

  \# #checkov:skip=CKV_AWS_145:KMS encryption not available in training
  account
  -----------------------------------------------------------------------

**7.4 Understanding Checkov Output**

  -----------------------------------------------------------------------
  Passed checks: 34, Failed checks: 6, Skipped checks: 0

  Check: CKV_AWS_17: \'Ensure all data stored in the RDS instance is not
  publicly accessible\'

  FAILED for resource: aws_db_instance.ems_mysql

  File: /terraform/ems/main.tf:12-28

  Guide: https://docs.bridgecrew.io/docs/general-ensure-\...

  Code:

  12 \| resource \'aws_db_instance\' \'ems_mysql\' {

  \...

  22 \| publicly_accessible = true \<\-- this line causes the failure

  \...

  28 \| }
  -----------------------------------------------------------------------

**7.5 Policy-as-Code with Checkov Custom Policies**

Checkov allows you to write custom policies for organisation-specific
rules. For SBI\'s EMS deployment, a custom policy might enforce that all
RDS instances must use Multi-AZ (for HA required by RBI\'s BCM
guidelines):

  -----------------------------------------------------------------------
  \# custom_policies/CKV_SBI_001.py

  from checkov.common.models.enums import CheckResult, CheckCategories

  from checkov.terraform.checks.resource.base_resource_check import
  BaseResourceCheck

  class DBMultiAZCheck(BaseResourceCheck):

  def \_\_init\_\_(self):

  name = \'Ensure RDS instance uses Multi-AZ (RBI BCM requirement)\'

  id = \'CKV_SBI_001\'

  categories = \[CheckCategories.BACKUP_AND_RECOVERY\]

  supported_resources = \[\'aws_db_instance\'\]

  super().\_\_init\_\_(name=name, id=id,

  categories=categories,

  supported_resources=supported_resources)

  def scan_resource_conf(self, conf):

  multi_az = conf.get(\'multi_az\', \[False\])\[0\]

  if multi_az:

  return CheckResult.PASSED

  return CheckResult.FAILED

  check = DBMultiAZCheck()

  \# Run with custom policy

  checkov -d ./terraform/ems \--external-checks-dir ./custom_policies
  -----------------------------------------------------------------------

**7.6 Terraform Security Best Practices for EMS**

  -----------------------------------------------------------------------
  **Practice**                **Implementation**
  --------------------------- -------------------------------------------
  Use variables, not literals var.db_password, not \'password123\'

  Store state in encrypted    S3 + KMS, not local terraform.tfstate
  backend                     

  Enable versioning on state  S3 versioning for audit trail and rollback
  bucket                      

  Use least-privilege IAM     EMS task role only has access to its own
  roles                       RDS, S3, secrets

  Encrypt all data at rest    storage_encrypted=true on RDS; SSE-KMS on
                              S3

  Enable VPC flow logs        Capture all network traffic for audit

  Tag all resources           team=devops, environment=prod, project=ems,
                              owner=sbi-team
  -----------------------------------------------------------------------

+-----------+----------------------------------------------------------+
| **1:30 -- | **Lab 4: IaC Security Scan**                             |
| 2:15**    |                                                          |
|           | Checkov scan of EMS Terraform · Fix misconfigurations ·  |
|           | Custom policy                                            |
+-----------+----------------------------------------------------------+

**Lab 4: IaC Security with Checkov**

+-----------------------------------------------------------------------+
| **Lab Objective**                                                     |
|                                                                       |
| Run Checkov against the EMS Terraform configuration, identify and fix |
| the three critical misconfigurations (public DB, open security group, |
| unencrypted storage), and write a simple custom SBI policy.           |
+-----------------------------------------------------------------------+

**Lab 4 --- Step-by-Step Instructions**

**Step 1 --- Explore the EMS Terraform**

15. Navigate to the terraform/ems/ folder in VS Code.

16. Open main.tf. Identify the aws_db_instance, aws_security_group, and
    aws_s3_bucket resources.

17. Without running any tool --- can you spot the misconfigurations by
    reading the code?

**Step 2 --- Run Checkov Scan**

18. In the terminal:

  -----------------------------------------------------------------------
  cd terraform/ems

  checkov -d . \--compact
  -----------------------------------------------------------------------

19. Note the number of FAILED checks: \_\_\_\_\_\_\_

20. For each FAILED check, copy the Check ID and description:

  ------------------------------------------------------------------------
  Failed Check 1:
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

  Failed Check 2:
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

  Failed Check 3:
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

  Failed Check 4:
  \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
  ------------------------------------------------------------------------

**Step 3 --- Fix the Misconfigurations**

21. Fix each misconfiguration in main.tf by applying the patterns from
    Module 7.

22. Key fixes to apply:

-   Set publicly_accessible = false on the RDS instance.

-   Add storage_encrypted = true on the RDS instance.

-   Add aws_s3_bucket_public_access_block with all four block options
    set to true.

-   Restrict the security group ingress to specific ports only.

**Step 4 --- Re-scan**

23. Run Checkov again after fixes:

  -----------------------------------------------------------------------
  checkov -d . \--compact

  -----------------------------------------------------------------------

24. New FAILED count: \_\_\_\_\_\_\_ (should be 0 or close to 0)

**Step 5 --- Write a Custom Policy**

25. Create the file custom_policies/CKV_SBI_001.py with the Multi-AZ
    check from Module 7.

26. Run Checkov with the custom policy:

  -----------------------------------------------------------------------
  checkov -d . \--external-checks-dir ../custom_policies \--compact

  -----------------------------------------------------------------------

27. Does the EMS RDS resource pass or fail your custom CKV_SBI_001
    check?

28. If it fails, add multi_az = true to the aws_db_instance resource and
    re-run.

+-----------------------------------------------------------------------+
| **Real-World Relevance**                                              |
|                                                                       |
| RBI\'s Business Continuity Management guidelines (Annex 7 of the      |
| Master Direction on IT) require that critical banking applications    |
| have multi-AZ or equivalent high availability. The custom Checkov     |
| policy you just wrote enforces this at the IaC level ---              |
| automatically, on every deployment.                                   |
+-----------------------------------------------------------------------+

+-----------+----------------------------------------------------------+
| **3:00 -- | **Module 8: Integrated DevSecOps Pipeline**              |
| 4:00**    |                                                          |
|           | End-to-End · All Gates · Metrics · Shift-Left Maturity   |
|           | Model                                                    |
+-----------+----------------------------------------------------------+

**8. The Integrated DevSecOps Pipeline**

The goal of DevSecOps is not a collection of individual security tools
--- it is a continuous, automated security process woven into every
stage of software delivery. This module brings together everything from
Day 1 and Day 2 into a single, coherent pipeline for EMS.

**8.1 The EMS Complete Security Pipeline**

Every change to EMS goes through the following security gates
automatically:

  -----------------------------------------------------------------------
  **Stage**       **Tool / Control**          **Pass Condition**
  --------------- --------------------------- ---------------------------
  1\. Pre-commit  detect-secrets hook         No secrets in staged files

  2\. Commit (CI  SonarQube SAST              Quality Gate passes (0
  trigger)                                    Critical/Blocker)

  3\. Build       Maven verify                All unit tests pass
                                              (including security tests)

  4\. Container   Trivy image scan            0 CRITICAL CVEs in image
  build                                       

  5\. IaC change  Checkov scan                0 FAILED checks (or
                                              suppressed with
                                              justification)

  6\. Staging     OWASP ZAP DAST              0 High-risk alerts
  deploy                                      

  7\. Production  Manual approval             Security team sign-off
  deploy                                      
  -----------------------------------------------------------------------

**8.2 Complete Pipeline YAML --- EMS**

The following GitHub Actions workflow integrates all security stages.
This is a production-grade pipeline you can adapt for your organisation:

  -----------------------------------------------------------------------
  \# .github/workflows/devsecops-full.yml

  name: EMS Full DevSecOps Pipeline

  on:

  push:

  branches: \[main, develop\]

  pull_request:

  branches: \[main\]

  env:

  IMAGE_NAME: sbi-ems

  IMAGE_TAG: \${{ github.sha }}

  jobs:

  \# ── STAGE 1: SAST ────────────────────────────────────────────

  sast:

  name: SAST --- Code Analysis

  runs-on: ubuntu-latest

  steps:

  \- uses: actions/checkout@v3

  with: { fetch-depth: 0 }

  \- uses: actions/setup-java@v3

  with: { java-version: \'17\', distribution: \'temurin\' }

  \- name: Detect secrets

  run: \|

  pip install detect-secrets

  detect-secrets scan \--all-files .

  \- name: Semgrep scan

  run: \|

  pip install semgrep

  semgrep \--config=p/owasp-top-ten \--error ./src

  \- name: SonarQube --- Quality Gate

  env:

  SONAR_TOKEN: \${{ secrets.SONAR_TOKEN }}

  SONAR_HOST_URL: \${{ secrets.SONAR_HOST_URL }}

  run: \|

  mvn clean verify sonar:sonar \\

  -Dsonar.qualitygate.wait=true

  \# ── STAGE 2: IaC SCAN ────────────────────────────────────────

  iac-scan:

  name: IaC --- Checkov Scan

  runs-on: ubuntu-latest

  steps:

  \- uses: actions/checkout@v3

  \- name: Checkov IaC scan

  run: \|

  pip install checkov

  checkov -d terraform/ems \\

  \--external-checks-dir custom_policies \\

  \--output junitxml \> checkov-results.xml

  \- name: Publish Checkov results

  uses: actions/upload-artifact@v3

  with: { name: checkov-report, path: checkov-results.xml }

  \# ── STAGE 3: BUILD + CONTAINER SCAN ─────────────────────────

  build-and-scan:

  name: Build + Container Scan

  needs: \[sast, iac-scan\]

  runs-on: ubuntu-latest

  steps:

  \- uses: actions/checkout@v3

  \- uses: actions/setup-java@v3

  with: { java-version: \'17\', distribution: \'temurin\' }

  \- name: Build JAR

  run: mvn clean package -DskipTests

  \- name: Build Docker image

  run: \|

  docker build -f Dockerfile.secure \\

  -t \$IMAGE_NAME:\$IMAGE_TAG .

  \- name: Trivy --- container scan

  run: \|

  trivy image \\

  \--severity HIGH,CRITICAL \\

  \--exit-code 1 \\

  \--format sarif \\

  \--output trivy-results.sarif \\

  \$IMAGE_NAME:\$IMAGE_TAG

  \- name: Push to registry (only on main)

  if: github.ref == \'refs/heads/main\'

  run: \|

  docker tag \$IMAGE_NAME:\$IMAGE_TAG \\

  registry.sbi.internal/\$IMAGE_NAME:\$IMAGE_TAG

  docker push registry.sbi.internal/\$IMAGE_NAME:\$IMAGE_TAG

  \# ── STAGE 4: DAST ────────────────────────────────────────────

  dast:

  name: DAST --- ZAP API Scan

  needs: build-and-scan

  runs-on: ubuntu-latest

  if: github.ref == \'refs/heads/main\'

  steps:

  \- uses: actions/checkout@v3

  \- name: Start EMS (staging)

  run: \|

  docker run -d \--name ems-staging \\

  -p 8080:8080 \\

  -e JWT_SECRET=\${{ secrets.JWT_SECRET }} \\

  -e SPRING_PROFILES_ACTIVE=staging \\

  registry.sbi.internal/\$IMAGE_NAME:\$IMAGE_TAG

  sleep 30

  \- name: ZAP API Scan

  run: \|

  docker run \--network=host \\

  ghcr.io/zaproxy/zaproxy:stable \\

  zap-api-scan.py \\

  -t http://localhost:8080/v3/api-docs \\

  -f openapi -r zap-report.html \\

  -l WARN

  \- name: Upload ZAP report

  uses: actions/upload-artifact@v3

  with: { name: zap-dast-report, path: zap-report.html }
  -----------------------------------------------------------------------

**8.3 DevSecOps Maturity Model**

Not every organisation starts at full pipeline automation. The maturity
model below shows a realistic progression for a PSU bank:

  -----------------------------------------------------------------------
  **Level**       **Characteristics**         **EMS Target**
  --------------- --------------------------- ---------------------------
  Level 1 --- Ad  Manual security reviews; no Starting point for most
  hoc             tooling in pipeline         legacy banking apps

  Level 2 ---     SAST tool in place;         SonarQube integrated;
  Defined         developers aware of         Quality Gate enforced
                  findings                    

  Level 3 ---     SAST + DAST automated;      Days 1+2 lab state --- all
  Consistent      secrets management active   tools in CI/CD

  Level 4 ---     Security metrics tracked;   MTTR for security findings
  Quantified      SLAs on remediation time    tracked in Jira

  Level 5 ---     Threat modelling; chaos     Target state for banking
  Optimizing      engineering; red team       security programmes
  -----------------------------------------------------------------------

**8.4 Security Metrics That Matter**

Metrics enable evidence-based security decisions. For the EMS DevSecOps
programme, track these:

  -----------------------------------------------------------------------
  **Metric**                  **What it measures**
  --------------------------- -------------------------------------------
  Mean Time to Remediate      How quickly critical vulnerabilities are
  (MTTR) --- Critical         fixed after discovery

  Vulnerability escape rate   \% of vulnerabilities found in production
                              vs caught in pipeline

  Quality Gate pass rate      \% of builds passing security gate ---
                              signals developer adoption

  New vs total technical debt Are we paying down security debt or
                              accumulating it?

  Container base image age    Days since base image was last updated ---
                              older = more CVEs

  Secrets detected pre-commit Count of secrets caught by hooks (lower is
                              better over time)
  -----------------------------------------------------------------------

+-----------+----------------------------------------------------------+
| **4:00 -- | **Capstone Lab: Full DevSecOps Pipeline Run**            |
| 5:00**    |                                                          |
|           | Code change → SAST → Container Scan → IaC Scan → DAST →  |
|           | Verify all gates                                         |
+-----------+----------------------------------------------------------+

**Capstone Lab: End-to-End DevSecOps on EMS**

+-----------------------------------------------------------------------+
| **Lab Objective**                                                     |
|                                                                       |
| Simulate a real developer workflow: make a code change to EMS that    |
| introduces a security vulnerability, watch the pipeline catch it, fix |
| it, and push again to watch all gates pass. This exercise ties        |
| together every tool from both days.                                   |
+-----------------------------------------------------------------------+

**Capstone --- Scenario**

The EMS development team has received a new requirement: add a
department search endpoint that accepts a department name as a query
parameter. A developer has implemented it using string concatenation
(introducing SQL injection). Your job is to:

-   Run the full security pipeline against this change.

-   Identify the vulnerability using SAST.

-   Confirm it is exploitable using DAST.

-   Fix the code.

-   Rebuild the Docker image and rescan with Trivy.

-   Confirm all gates pass.

**Capstone --- Step-by-Step**

**Step 1 --- Introduce the Vulnerability**

29. Open EmployeeController.java.

30. Add the following (intentionally vulnerable) search endpoint:

  -----------------------------------------------------------------------
  // NEW ENDPOINT --- vulnerable to SQL injection

  \@GetMapping(\'/search\')

  public ResponseEntity\<?\> searchByDept(@RequestParam String dept) {

  // VULNERABLE --- uses EntityManager with string concatenation

  List\<Employee\> result = em.createQuery(

  \'SELECT e FROM Employee e WHERE e.department.name = \\\'\' + dept +
  \'\\\'\',

  Employee.class).getResultList();

  return ResponseEntity.ok(result);

  }
  -----------------------------------------------------------------------

31. Save and commit:

  -----------------------------------------------------------------------
  git add . && git commit -m \'feat: add department search endpoint\'

  -----------------------------------------------------------------------

**Step 2 --- Run SAST**

32. Re-run the SonarQube scan:

  -----------------------------------------------------------------------
  mvn clean package -DskipTests sonar:sonar \\

  -Dsonar.host.url=http://SONAR_IP:9000 \\

  -Dsonar.token=YOUR_TOKEN
  -----------------------------------------------------------------------

33. Open the SonarQube dashboard. Find the new Critical issue on the
    search endpoint.

34. Read the taint analysis --- where does the user input enter? Where
    is the unsafe query built?

**Step 3 --- Confirm with DAST (ZAP)**

35. Start EMS: docker compose up -d

36. In ZAP, Spider and then Active Scan the running EMS.

37. Check for SQL injection alerts on /api/v1/employees/search.

38. Use ZAP\'s Fuzzer to manually confirm --- right-click the search
    request \> Fuzz \> add payload: \' OR \'1\'=\'1

**Step 4 --- Fix the Vulnerability**

39. Replace the vulnerable query with a parameterized Spring Data
    derived query:

  --------------------------------------------------------------------------
  // FIXED --- using Spring Data repository method (safe)

  \@GetMapping(\'/search\')

  public ResponseEntity\<?\> searchByDept(

  \@RequestParam \@NotBlank \@Size(max=100) String dept) {

  List\<Employee\> result = employeeRepository.findByDepartmentName(dept);

  return
  ResponseEntity.ok(result.stream().map(mapper::toDto).collect(toList()));

  }
  --------------------------------------------------------------------------

40. Commit the fix and re-run the SAST scan to confirm it passes.

**Step 5 --- Rebuild Container and Re-scan**

41. Rebuild:

  -----------------------------------------------------------------------
  mvn clean package -DskipTests

  docker build -f Dockerfile.secure -t ems:capstone .

  trivy image \--severity HIGH,CRITICAL \--exit-code 1 ems:capstone
  -----------------------------------------------------------------------

42. Confirm Trivy passes.

**Step 6 --- Run IaC Scan**

43. Confirm your Terraform fixes from Lab 4 still pass:

  -----------------------------------------------------------------------
  checkov -d terraform/ems \--compact

  -----------------------------------------------------------------------

44. Confirm: 0 FAILED checks.

**Step 7 --- Final DAST Verification**

45. Restart EMS with the fixed image: docker compose up -d

46. Re-run ZAP Active Scan.

47. Confirm: the SQL injection alert on /search is gone.

+-----------------------------------------------------------------------+
| **Congratulations**                                                   |
|                                                                       |
| You have completed a full DevSecOps cycle: introduced a               |
| vulnerability, caught it with SAST (before it ran), confirmed it with |
| DAST (when it ran), fixed it at the code level, verified the fix      |
| across container and IaC layers, and confirmed clean DAST results.    |
| This is the DevSecOps workflow.                                       |
+-----------------------------------------------------------------------+

+-----------+----------------------------------------------------------+
| **5:00 -- | **Case Studies: Banking Security Incidents + Q&A**       |
| 5:30**    |                                                          |
|           | Real Incidents · Lessons Learned · RBI Compliance        |
|           | Mapping                                                  |
+-----------+----------------------------------------------------------+

**9. Banking Security Case Studies**

The most effective way to internalise DevSecOps is to see what happens
when it is absent. The following incidents are real events at financial
institutions that could have been prevented by the tools and practices
covered in this training.

**Case Study 1 --- SWIFT Banking Fraud (Bangladesh Bank, 2016)**

-   What happened: Attackers gained access to the Bangladesh Bank\'s
    SWIFT terminal, modified legitimate transaction requests, and
    transferred \$81 million to fraudulent accounts in the Philippines.

-   Root DevSecOps cause: Malware on SWIFT terminals (no
    container/endpoint security); hardcoded credentials in legacy
    systems (no secrets management); no anomaly detection on outbound
    transactions (no monitoring/logging).

-   Which tools from this training would have helped:

  -----------------------------------------------------------------------
  \- Secrets management (Vault): rotating SWIFT credentials automatically

  \- Container security: isolating SWIFT terminal software

  \- SAST: detecting hardcoded credentials in SWIFT integration code

  \- Monitoring: anomaly detection on transaction amounts/patterns
  -----------------------------------------------------------------------

**Case Study 2 --- Spring4Shell at a Bank (2022)**

-   What happened: CVE-2022-22965 allowed Remote Code Execution on any
    Java Spring MVC application running on JDK 9+ and deployed on Apache
    Tomcat. Banks using Spring Boot internally were vulnerable for
    weeks.

-   Root DevSecOps cause: No container scanning (Trivy would have
    flagged the CVE within 24 hours of disclosure); no automated
    dependency checking.

-   EMS relevance: EMS uses Spring Boot 3.x. Had this been a Spring Boot
    3.x CVE, a Trivy scan would show it immediately.

  -----------------------------------------------------------------------
  \# How Trivy would have caught Spring4Shell

  trivy image ems:spring4shell-era

  \# Output:

  \# CVE-2022-22965 CRITICAL spring-webmvc 5.3.17 Fixed: 5.3.18

  \# Remote Code Execution via data binding

  \# CVSS: 9.8

  \# \--exit-code 1 would have blocked deployment automatically
  -----------------------------------------------------------------------

**Case Study 3 --- Exposed S3 Bucket at an NBFC (India, 2023)**

-   What happened: An NBFC\'s cloud team created an S3 bucket for
    customer KYC documents and accidentally set it to public-read during
    testing. The configuration was never reverted before the bucket was
    used in production.

-   Data exposed: 2.3 lakh customer KYC documents including Aadhaar
    numbers, PAN cards, and bank statements.

-   Root DevSecOps cause: IaC not used (manual console configuration);
    no IaC scanning.

-   How Checkov would have prevented it:

  -----------------------------------------------------------------------
  \# If IaC had been used and Checkov had run:

  \# Check: CKV_AWS_53: \'Ensure S3 bucket has block public ACLS
  enabled\'

  \# FAILED for resource: aws_s3_bucket.kyc_documents

  \#

  \# Pipeline would have blocked deployment before the bucket went live.
  -----------------------------------------------------------------------

**RBI Compliance Mapping**

The tools and practices in this training directly address requirements
from RBI\'s Master Direction on Information Technology Governance, Risk,
Controls, and Assurance Practices (2023):

  ------------------------------------------------------------------------
  **RBI            **Section**                 **DevSecOps Control**
  Requirement**                                
  ---------------- --------------------------- ---------------------------
  Secure Software  6.3                         SAST (SonarQube), DAST
  Development                                  (ZAP), peer code review
  Lifecycle                                    

  Vulnerability    6.4                         Trivy CVE scanning, OWASP
  management                                   Dependency-Check, SCA

  Secrets and      6.5                         HashiCorp Vault,
  credential                                   detect-secrets, no
  management                                   hardcoded secrets

  Audit logging    7.2                         Spring AOP audit aspect,
  for sensitive                                structured logging, SIEM
  data access                                  integration

  Change           8.1                         CI/CD pipeline gates,
  management with                              security sign-off before
  security review                              production

  Business         Annex 7                     Custom Checkov policy
  continuity                                   (CKV_SBI_001)
  (Multi-AZ)                                   

  Infrastructure   6.6                         Checkov CIS benchmark
  security                                     checks, IaC-enforced
  baseline                                     configuration
  ------------------------------------------------------------------------

**Key Takeaways --- Both Days**

  -----------------------------------------------------------------------
  **Day**         **Module**                  **The One Thing to
                                              Remember**
  --------------- --------------------------- ---------------------------
  Day 1           Secure Coding               Write security in from line
                                              1 --- \@PreAuthorize,
                                              \@Valid, BCrypt, safe error
                                              handling

  Day 1           SAST                        SonarQube finds what you
                                              cannot see --- run it on
                                              every commit; fix Critical
                                              before merging

  Day 1           DAST                        The running app is the
                                              ground truth --- ZAP finds
                                              what SAST cannot (headers,
                                              runtime config)

  Day 1           Secrets                     A secret in git is a secret
                                              forever --- use
                                              detect-secrets hooks and
                                              Vault

  Day 1           CI/CD                       Automate the gates --- a
                                              gate only you manually run
                                              is a gate that gets skipped

  Day 2           Containers                  Non-root + minimal base
                                              image + Trivy scan = 90% of
                                              container security

  Day 2           IaC                         Every infra change through
                                              Terraform; every Terraform
                                              through Checkov

  Day 2           Pipeline                    DevSecOps is a culture
                                              before it is a toolchain
                                              --- fast feedback, shared
                                              ownership
  -----------------------------------------------------------------------

+-----------------------------------------------------------------------+
| **Next Steps for Your Team**                                          |
|                                                                       |
| 1\. Set up SonarQube in your internal CI/CD (Jenkins/GitLab/GitHub    |
| Actions) this week.                                                   |
|                                                                       |
| 2\. Add detect-secrets pre-commit hooks to all active repositories.   |
|                                                                       |
| 3\. Add Trivy to your container build pipeline --- even if exit-code  |
| 0 initially.                                                          |
|                                                                       |
| 4\. Run Checkov on your existing Terraform --- treat it as a security |
| audit.                                                                |
|                                                                       |
| 5\. Schedule a quarterly DAST scan on all externally-facing           |
| applications.                                                         |
|                                                                       |
| 6\. Present the RBI compliance mapping to your CISO --- this          |
| programme addresses real regulatory requirements.                     |
+-----------------------------------------------------------------------+
