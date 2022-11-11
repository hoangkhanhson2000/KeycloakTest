package com.example.keycloaktest.controller;

import com.example.keycloaktest.entity.Employee;
import com.example.keycloaktest.service.EmployeeService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.RolesAllowed;
import java.util.List;

@RestController
@RequestMapping("/employee")
@Slf4j
public class EmployeeController {

    private final EmployeeService service;

    public EmployeeController(EmployeeService service) {
        this.service = service;
    }

    //this method can be accessed by user whose role is user
    @GetMapping("/{employeeId}")
    @RolesAllowed("user")
    public ResponseEntity<Employee> getEmployee(@PathVariable int employeeId) {
        log.info("{}", SecurityContextHolder.getContext().getAuthentication());;
        return ResponseEntity.ok(service.getEmployee(employeeId));
    }

    //this method can be accessed by user whose role is admin
    @GetMapping()
    @RolesAllowed("admin")
    public ResponseEntity<List<Employee>> findALlEmployees() {
        log.info("{}", SecurityContextHolder.getContext().getAuthentication());;
        return ResponseEntity.ok(service.getAllEmployees());
    }



}
