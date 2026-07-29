#Code Quality & Security Linker

-A robust, custom-built static code analyzer in Java that scans source code files to detect security vulnerabilities, poor 
coding practices, performance bottlenecks, and style violations


## Features

- Hardcoded password detection

- SQL injection pattern detection

- Empty catch block detection

- System.out.println detection

## Technologies
-java
-Regex
-File Handling

## How to Run

```bash

javac AdvancedLinter.java

java AdvancedLinter Test.java 


## Sample Input
String password = "admin123";

String query = "SELECT * FROM users WHERE name = '" + userName + "'";

System.out.println("debug");

catch(Exception e) {}



## Sample Output
======================================================
 Advanced Code Quality & Security Linter
 Target: Test.java
======================================================

--- Scan Results ---
Files scanned: 1
Issues found: 5

[CRITICAL] [SECURITY] [SEC001] Test.java:1 -> Hardcoded password detected.
    Code: String password = "admin123";
    Fix : Move secrets to environment variables or a secure vault.
------------------------------------------------------
[ERROR] [SECURITY] [SEC003] Test.java:2 -> Possible SQL Injection risk due to string concatenation.
    Code: String query = "SELECT * FROM users WHERE name = '" + userName + "'";
    Fix : Use PreparedStatement with parameter binding.
------------------------------------------------------
[INFO] [QUALITY] [QUA002] Test.java:3 -> System.out.println used.
    Code: System.out.println("debug");
    Fix : Use a logging framework for production code.
------------------------------------------------------
[WARNING] [QUALITY] [QUA001] Test.java:4 -> Empty catch block found.
    Code: catch(Exception e) {}
    Fix : Log the exception or handle it properly.
------------------------------------------------------
[WARNING] [QUALITY] [QUA009] Test.java:4 -> Generic catch(Exception) detected.
    Code: catch(Exception e) {}
    Fix : Catch specific exception types wherever possible.
------------------------------------------------------

