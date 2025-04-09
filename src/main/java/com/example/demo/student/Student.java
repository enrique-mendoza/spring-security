package com.example.demo.student;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Student {

    private final Integer studentId;

    private final String studentName;
}

