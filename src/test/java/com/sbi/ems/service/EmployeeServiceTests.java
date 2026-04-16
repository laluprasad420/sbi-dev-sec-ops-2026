/**
package com.sbi.ems.service;

import com.sbi.ems.dto.employee.EmployeeRequest;
import com.sbi.ems.exception.ConflictException;
import com.sbi.ems.model.Department;
import com.sbi.ems.model.Employee;
import com.sbi.ems.model.Role;
import com.sbi.ems.repository.DepartmentRepository;
import com.sbi.ems.repository.EmployeeRepository;
import com.sbi.ems.repository.RoleRepository;
import com.sbi.ems.service.impl.EmployeeServiceImpl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
public class EmployeeServiceTests {

    @Mock
    private EmployeeRepository employeeRepository;

    @Mock
    private DepartmentRepository departmentRepository;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private EmployeeServiceImpl employeeService;

    private EmployeeRequest request;
    private Department dept;
    private Role role;

    @BeforeEach
    void setup() {
        request = new EmployeeRequest();
        request.setFirstName("John");
        request.setLastName("Doe");
        request.setEmail("john.doe@sbi.co.in");
        request.setSalary(new BigDecimal("50000.0"));
        request.setHireDate(LocalDate.now());
        request.setStatus(Employee.EmployeeStatus.ACTIVE);
        request.setDepartmentId(1L);
        request.setRoleId(1L);

        dept = new Department();
        dept.setId(1L);

        role = new Role();
        role.setId(1L);
    }

    // ✅ 1. Happy path
    @Test
    void shouldCreateEmployeeSuccessfully() {

        when(employeeRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.empty());

        when(departmentRepository.findById(1L))
                .thenReturn(Optional.of(dept));

        when(roleRepository.findById(1L))
                .thenReturn(Optional.of(role));

        when(employeeRepository.save(any(Employee.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        var response = employeeService.createEmployee(request);

        assertNotNull(response);
        assertEquals("john.doe@sbi.co.in", response.getEmail());

        verify(employeeRepository).save(any(Employee.class));
    }

    // ❌ 2. Duplicate email → ConflictException
    @Test
    void shouldThrowException_whenEmailAlreadyExists() {

        when(employeeRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.of(new Employee()));

        assertThrows(ConflictException.class,
                () -> employeeService.createEmployee(request));

        verify(employeeRepository, never()).save(any());
    }

    // ❌ 3. Department not found
    @Test
    void shouldThrowException_whenDepartmentNotFound() {

        when(employeeRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.empty());

        when(departmentRepository.findById(1L))
                .thenReturn(Optional.empty());

        assertThrows(RuntimeException.class,
                () -> employeeService.createEmployee(request));
    }

    // ❌ 4. Role not found
    @Test
    void shouldThrowException_whenRoleNotFound() {

        when(employeeRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.empty());

        when(departmentRepository.findById(1L))
                .thenReturn(Optional.of(dept));

        when(roleRepository.findById(1L))
                .thenReturn(Optional.empty());

        assertThrows(RuntimeException.class,
                () -> employeeService.createEmployee(request));
    }
}
**/

