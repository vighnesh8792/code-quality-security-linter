# code-quality-security-linter
🛡️ Code Quality & Security Linter (Java)
A robust, custom-built static code analyzer in Java that scans source code files to detect security vulnerabilities, poor coding practices, performance bottlenecks, and style violations.

✨ Features
Security Checks: Detects hardcoded passwords, exposed API keys, SQL injection risks, and weak hashing algorithms (e.g., MD5/SHA-1).

Code Quality & Style: Identifies empty catch blocks, generic exceptions, leftover System.out.println statements, and wildcard imports.

Performance Analysis: Flags multiple nested loops and excessive string concatenations.

Detailed Reporting: Generates a categorized, line-by-line issue report with specific suggestions for fixes (Categorized by CRITICAL, ERROR, WARNING, INFO).

🛠️ Technologies Used
Java (Core): File I/O Streams, Collections Framework, Enums

Regular Expressions (Regex): Advanced pattern matching for syntax and security flaw detection

🚀 How to Run
Compile the linter:

Bash


javac AdvancedLinter.java
Run the scan on a target file (or directory):

Bash


java AdvancedLinter Test.java
