# IBM Employee Management System (EMS)

## 📌 Project Overview
This project is a **Spring Boot REST API-based Employee Management System (EMS)**.

The goal is to help trainees apply all major Spring Boot concepts including:
- Spring Boot REST APIs
- Spring Data JPA
- Entity Relationships
- Validation
- H2 Database
- Swagger (OpenAPI)

---

## 🧱 Tech Stack
- Java 17
- Spring Boot 3.x
- Spring Data JPA
- H2 Database (In-Memory)
- Spring Validation
- Swagger UI (OpenAPI)

---

## 📦 Domain Model

### 1. Employee
Represents an employee in the organization.

**Attributes:**
- id (Long)
- name (String)
- email (String)
- salary (Double)

---

### 2. Department
Represents a department.

**Attributes:**
- id (Long)
- name (String)

---

### 3. Role
Represents employee role.

**Attributes:**
- id (Long)
- name (String)

---

### 4. Project
Represents a project.

**Attributes:**
- id (Long)
- name (String)
- description (String)

---

## 🔗 Relationships

- Employee → Department (Many-to-One)
- Employee → Role (Many-to-One)
- Employee ↔ Project (Many-to-Many)

---

## 📁 Suggested Package Structure

```
com.sbi.ems
 ├── controller
 ├── service
 ├── repository
 ├── entity
 ├── dto
 ├── exception
 └── config
```

---

## 🧾 Entity Classes (Sample)

### Employee.java
```java
@Entity
public class Employee {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String email;

    private Double salary;

    @ManyToOne
    private Department department;

    @ManyToOne
    private Role role;

    @ManyToMany
    private List<Project> projects;
}
```

---

### Department.java
```java
@Entity
public class Department {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
}
```

---

### Role.java
```java
@Entity
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
}
```

---

### Project.java
```java
@Entity
public class Project {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String description;
}
```

---

## 🗄️ Repository Layer
Create interfaces extending JpaRepository:

- EmployeeRepository
- DepartmentRepository
- RoleRepository
- ProjectRepository

---

## ⚙️ Service Layer
- Business logic implementation
- CRUD operations
- Relationship handling

---

## 🌐 Controller Layer (REST APIs)

### Employee APIs
- GET /employees
- GET /employees/{id}
- POST /employees
- PUT /employees/{id}
- DELETE /employees/{id}

Similarly create APIs for:
- Departments
- Roles
- Projects

---

## 🧪 Validation
Use annotations like:
- @NotNull
- @Email
- @Size

---

## 📊 H2 Database
Access H2 console:
```
http://localhost:8080/h2-console
```

---

## 📘 Swagger UI
```
http://localhost:8080/swagger-ui.html
```

---

## 🎯 Learning Objectives

Trainees will learn:
- REST API design
- Entity relationships (OneToMany, ManyToMany)
- JPA repositories
- Exception handling
- DTO mapping
- Validation
- API documentation

---

## 🚀 Enhancements (Optional)
- DTO Layer
- Global Exception Handling
- Pagination & Sorting
- Search APIs
- Authentication (Spring Security)

---

## ✅ Instructions for Trainees
1. Read this document carefully
2. Create project using Spring Initializr
3. Implement entities and relationships
4. Build repositories and services
5. Expose REST APIs
6. Test using Postman / Swagger

---

Happy Coding! 🎉
