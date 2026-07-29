import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AdvancedLinter {

    enum Severity {
        INFO, WARNING, ERROR, CRITICAL
    }

    enum Category {
        SECURITY, QUALITY, STYLE, PERFORMANCE
    }

    static class Issue {
        String file;
        int line;
        String ruleId;
        Severity severity;
        Category category;
        String message;
        String suggestion;
        String codeSnippet;

        Issue(String file, int line, String ruleId, Severity severity, Category category,
              String message, String suggestion, String codeSnippet) {
            this.file = file;
            this.line = line;
            this.ruleId = ruleId;
            this.severity = severity;
            this.category = category;
            this.message = message;
            this.suggestion = suggestion;
            this.codeSnippet = codeSnippet;
        }

        @Override
        public String toString() {
            return "[" + severity + "] [" + category + "] [" + ruleId + "] " +
                    file + ":" + line + " -> " + message + "\n" +
                    "    Code: " + codeSnippet.trim() + "\n" +
                    "    Fix : " + suggestion;
        }
    }

    static class Rule {
        String id;
        Severity severity;
        Category category;
        Pattern pattern;
        String message;
        String suggestion;

        Rule(String id, Severity severity, Category category, String regex,
             String message, String suggestion) {
            this.id = id;
            this.severity = severity;
            this.category = category;
            this.pattern = Pattern.compile(regex);
            this.message = message;
            this.suggestion = suggestion;
        }

        boolean matches(String line) {
            Matcher matcher = pattern.matcher(line);
            return matcher.find();
        }
    }

    private static final List<Rule> LINE_RULES = new ArrayList<>();
    private static final Set<String> SUPPORTED_EXTENSIONS = new HashSet<>(
            Arrays.asList(".java", ".txt", ".properties", ".xml", ".sql")
    );

    static {
        // ---------------- SECURITY RULES ----------------
        LINE_RULES.add(new Rule(
                "SEC001",
                Severity.CRITICAL,
                Category.SECURITY,
                "(?i)\\b(String|var)\\s+(password|passwd|pwd)\\s*=\\s*\"[^\"]+\"",
                "Hardcoded password detected.",
                "Move secrets to environment variables or a secure vault."
        ));

        LINE_RULES.add(new Rule(
                "SEC002",
                Severity.CRITICAL,
                Category.SECURITY,
                "(?i)(api[_-]?key|secret|token)\\s*=\\s*\"[A-Za-z0-9_\\-=:/.]{8,}\"",
                "Hardcoded API key / token detected.",
                "Store API keys securely outside source code."
        ));

        LINE_RULES.add(new Rule(
                "SEC003",
                Severity.ERROR,
                Category.SECURITY,
                "(?i)select\\s+.+\\+|insert\\s+.+\\+|update\\s+.+\\+|delete\\s+.+\\+",
                "Possible SQL Injection risk due to string concatenation.",
                "Use PreparedStatement with parameter binding."
        ));

        LINE_RULES.add(new Rule(
                "SEC004",
                Severity.ERROR,
                Category.SECURITY,
                "(?i)Statement\\s+\\w+\\s*=\\s*conn\\.createStatement\\(",
                "Use of Statement detected; may encourage unsafe dynamic SQL.",
                "Prefer PreparedStatement for database queries."
        ));

        LINE_RULES.add(new Rule(
                "SEC005",
                Severity.ERROR,
                Category.SECURITY,
                "(?i)Runtime\\.getRuntime\\(\\)\\.exec\\(",
                "Command execution detected.",
                "Validate input strictly or avoid shell execution entirely."
        ));

        LINE_RULES.add(new Rule(
                "SEC006",
                Severity.WARNING,
                Category.SECURITY,
                "(?i)new\\s+ObjectInputStream\\(",
                "Java deserialization usage detected.",
                "Avoid unsafe deserialization or validate trusted classes only."
        ));

        LINE_RULES.add(new Rule(
                "SEC007",
                Severity.WARNING,
                Category.SECURITY,
                "(?i)MessageDigest\\.getInstance\\(\"(MD5|SHA-?1)\"\\)",
                "Weak hash algorithm detected.",
                "Use SHA-256 or stronger algorithms when appropriate."
        ));

        LINE_RULES.add(new Rule(
                "SEC008",
                Severity.WARNING,
                Category.SECURITY,
                "(?i)http://",
                "Insecure HTTP URL detected.",
                "Use HTTPS unless plain HTTP is explicitly required."
        ));

        LINE_RULES.add(new Rule(
                "SEC009",
                Severity.WARNING,
                Category.SECURITY,
                "(?i)new\\s+Random\\(",
                "Random used in potentially security-sensitive code.",
                "Use SecureRandom where unpredictability matters."
        ));

        LINE_RULES.add(new Rule(
                "SEC010",
                Severity.WARNING,
                Category.SECURITY,
                "(?i)printStackTrace\\(",
                "Stack trace printing detected.",
                "Use structured logging instead of printStackTrace()."
        ));

        LINE_RULES.add(new Rule(
                "SEC011",
                Severity.ERROR,
                Category.SECURITY,
                "(\\.\\./|\\.\\.\\\\)",
                "Possible path traversal pattern detected.",
                "Normalize and validate file paths before access."
        ));

        LINE_RULES.add(new Rule(
                "SEC012",
                Severity.WARNING,
                Category.SECURITY,
                "(?i)setAccessible\\(true\\)",
                "Reflection access override detected.",
                "Avoid bypassing access controls unless absolutely necessary."
        ));

        // ---------------- QUALITY RULES ----------------
        LINE_RULES.add(new Rule(
                "QUA001",
                Severity.WARNING,
                Category.QUALITY,
                "catch\\s*\\([^)]*\\)\\s*\\{\\s*\\}",
                "Empty catch block found.",
                "Log the exception or handle it properly."
        ));

        LINE_RULES.add(new Rule(
                "QUA002",
                Severity.INFO,
                Category.QUALITY,
                "System\\.out\\.println\\(",
                "System.out.println used.",
                "Use a logging framework for production code."
        ));

        LINE_RULES.add(new Rule(
                "QUA003",
                Severity.INFO,
                Category.QUALITY,
                "System\\.err\\.println\\(",
                "System.err.println used.",
                "Use a logger instead of console error printing."
        ));

        LINE_RULES.add(new Rule(
                "QUA004",
                Severity.WARNING,
                Category.QUALITY,
                "\\bTODO\\b|\\bFIXME\\b",
                "TODO/FIXME comment found.",
                "Track pending work in issue management or resolve before release."
        ));

        LINE_RULES.add(new Rule(
                "QUA005",
                Severity.WARNING,
                Category.QUALITY,
                "\\bif\\s*\\([^)]*\\)\\s*\\{\\s*\\}",
                "Empty if block found.",
                "Remove dead code or implement the intended logic."
        ));

        LINE_RULES.add(new Rule(
                "QUA006",
                Severity.WARNING,
                Category.QUALITY,
                "\\b(while|for)\\s*\\([^)]*\\)\\s*\\{\\s*\\}",
                "Empty loop block found.",
                "Remove the loop or add the required logic."
        ));

        LINE_RULES.add(new Rule(
                "QUA007",
                Severity.WARNING,
                Category.QUALITY,
                "\\bThread\\.sleep\\(",
                "Thread.sleep used directly.",
                "Avoid arbitrary sleeps; use synchronization or scheduled mechanisms."
        ));

        LINE_RULES.add(new Rule(
                "QUA008",
                Severity.WARNING,
                Category.QUALITY,
                "\\bthrows\\s+Exception\\b",
                "Generic exception declared.",
                "Throw more specific exception types."
        ));

        LINE_RULES.add(new Rule(
                "QUA009",
                Severity.WARNING,
                Category.QUALITY,
                "\\bcatch\\s*\\(\\s*Exception\\s+\\w+\\s*\\)",
                "Generic catch(Exception) detected.",
                "Catch specific exception types wherever possible."
        ));

        LINE_RULES.add(new Rule(
                "QUA010",
                Severity.INFO,
                Category.QUALITY,
                "\\breturn\\s+null\\s*;",
                "return null detected.",
                "Consider Optional, exception handling, or safer return contracts."
        ));

        // ---------------- STYLE RULES ----------------
        LINE_RULES.add(new Rule(
                "STY001",
                Severity.INFO,
                Category.STYLE,
                "^.{121,}$",
                "Line exceeds 120 characters.",
                "Break long lines for readability."
        ));

        LINE_RULES.add(new Rule(
                "STY002",
                Severity.WARNING,
                Category.STYLE,
                "\\b([a-zA-Z_][a-zA-Z0-9_]*)\\s*==\\s*\"[^\"]*\"|\"[^\"]*\"\\s*==\\s*([a-zA-Z_][a-zA-Z0-9_]*)",
                "Possible String comparison using == detected.",
                "Use .equals() for String content comparison."
        ));

        LINE_RULES.add(new Rule(
                "STY003",
                Severity.INFO,
                Category.STYLE,
                "\\bclass\\s+[a-z][A-Za-z0-9]*\\b",
                "Class name may violate PascalCase naming convention.",
                "Use PascalCase for class names."
        ));

        LINE_RULES.add(new Rule(
                "STY004",
                Severity.INFO,
                Category.STYLE,
                "\\b(int|double|float|long)\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*\\d{2,}\\s*;",
                "Possible magic number detected.",
                "Replace repeated numeric literals with named constants."
        ));

        LINE_RULES.add(new Rule(
                "STY005",
                Severity.INFO,
                Category.STYLE,
                "\\s+$",
                "Trailing whitespace detected.",
                "Remove trailing spaces."
        ));

        // ---------------- PERFORMANCE RULES ----------------
        LINE_RULES.add(new Rule(
                "PER001",
                Severity.WARNING,
                Category.PERFORMANCE,
                "\\+\\s*\"[^\"]*\"\\s*\\+|\"[^\"]*\"\\s*\\+\\s*[a-zA-Z_]",
                "Possible repeated string concatenation detected.",
                "Consider StringBuilder inside loops or repeated concatenations."
        ));

        LINE_RULES.add(new Rule(
                "PER002",
                Severity.INFO,
                Category.PERFORMANCE,
                "\\bString\\.matches\\(",
                "String.matches() can recompile regex repeatedly.",
                "Reuse compiled Pattern objects for repeated matching."
        ));

        LINE_RULES.add(new Rule(
                "PER003",
                Severity.INFO,
                Category.PERFORMANCE,
                "\\bnew\\s+ArrayList<.*>\\(\\)\\s*;?",
                "Collection initialization found.",
                "Check whether initial capacity can be set for large collections."
        ));
    }

    public static void main(String[] args) {
        String targetPath = args.length > 0 ? args[0] : ".";
        boolean recursive = true;

        System.out.println("======================================================");
        System.out.println(" Advanced Code Quality & Security Linter");
        System.out.println(" Target: " + targetPath);
        System.out.println("======================================================");

        List<Path> filesToScan = collectFiles(targetPath, recursive);

        if (filesToScan.isEmpty()) {
            System.out.println("No supported files found.");
            return;
        }

        List<Issue> allIssues = new ArrayList<>();

        for (Path file : filesToScan) {
            List<Issue> issues = scanFile(file);
            allIssues.addAll(issues);
        }

        printReport(allIssues, filesToScan.size());
    }

    private static List<Path> collectFiles(String targetPath, boolean recursive) {
        List<Path> files = new ArrayList<>();
        Path start = Paths.get(targetPath);

        if (!Files.exists(start)) {
            System.out.println("Path does not exist: " + targetPath);
            return files;
        }

        try {
            if (Files.isRegularFile(start)) {
                if (isSupported(start)) {
                    files.add(start);
                }
                return files;
            }

            Stream<Path> stream = recursive ? Files.walk(start) : Files.list(start);

            files = stream
                    .filter(Files::isRegularFile)
                    .filter(AdvancedLinter::isSupported)
                    .collect(Collectors.toList());

        } catch (IOException e) {
            System.out.println("Error collecting files: " + e.getMessage());
        }

        return files;
    }

    private static boolean isSupported(Path file) {
        String name = file.getFileName().toString().toLowerCase();
        for (String ext : SUPPORTED_EXTENSIONS) {
            if (name.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private static List<Issue> scanFile(Path filePath) {
        List<Issue> issues = new ArrayList<>();
        List<String> lines;

        try {
            lines = Files.readAllLines(filePath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.out.println("Could not read file: " + filePath + " -> " + e.getMessage());
            return issues;
        }

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            int lineNumber = i + 1;

            if (shouldIgnoreLine(line)) {
                continue;
            }

            for (Rule rule : LINE_RULES) {
                if (isRuleIgnored(line, rule.id)) {
                    continue;
                }

                if (rule.matches(line)) {
                    issues.add(new Issue(
                            filePath.toString(),
                            lineNumber,
                            rule.id,
                            rule.severity,
                            rule.category,
                            rule.message,
                            rule.suggestion,
                            line
                    ));
                }
            }

            runCustomHeuristics(filePath, lines, i, issues);
        }

        return issues;
    }

    private static void runCustomHeuristics(Path filePath, List<String> lines, int index, List<Issue> issues) {
        String line = lines.get(index);
        int lineNumber = index + 1;

        checkNestedLoops(filePath, lines, index, issues);
        checkLongMethodHeuristic(filePath, lines, index, issues);
        checkPublicMutableField(filePath, line, lineNumber, issues);
        checkCommentedCode(filePath, line, lineNumber, issues);
        checkWildcardImport(filePath, line, lineNumber, issues);
    }

    private static void checkNestedLoops(Path filePath, List<String> lines, int index, List<Issue> issues) {
        String line = lines.get(index);
        if (line.contains("for") || line.contains("while")) {
            int lookAhead = Math.min(index + 12, lines.size());
            int nestedCount = 0;
            for (int j = index + 1; j < lookAhead; j++) {
                String next = lines.get(j);
                if (next.contains("for") || next.contains("while")) {
                    nestedCount++;
                }
            }
            if (nestedCount >= 2) {
                issues.add(new Issue(
                        filePath.toString(),
                        index + 1,
                        "PER004",
                        Severity.WARNING,
                        Category.PERFORMANCE,
                        "Multiple nested loops suspected nearby.",
                        "Review time complexity; refactor if unnecessary nesting exists.",
                        line
                ));
            }
        }
    }

    private static void checkLongMethodHeuristic(Path filePath, List<String> lines, int index, List<Issue> issues) {
        String line = lines.get(index);
        if (line.matches(".*\\b(public|private|protected)\\b.*\\(.*\\)\\s*\\{\\s*")) {
            int braceDepth = 0;
            int methodLength = 0;
            boolean started = false;

            for (int j = index; j < lines.size(); j++) {
                String current = lines.get(j);
                for (char c : current.toCharArray()) {
                    if (c == '{') {
                        braceDepth++;
                        started = true;
                    } else if (c == '}') {
                        braceDepth--;
                    }
                }

                if (started) {
                    methodLength++;
                }

                if (started && braceDepth == 0) {
                    break;
                }
            }

            if (methodLength > 40) {
                issues.add(new Issue(
                        filePath.toString(),
                        index + 1,
                        "QUA011",
                        Severity.INFO,
                        Category.QUALITY,
                        "Method appears longer than 40 lines.",
                        "Break large methods into smaller focused methods.",
                        line
                ));
            }
        }
    }

    private static void checkPublicMutableField(Path filePath, String line, int lineNumber, List<Issue> issues) {
        if (line.matches(".*\\bpublic\\s+(?!static\\s+final)(int|String|double|float|long|boolean|List<.*>|Map<.*>)\\s+\\w+\\s*;.*")) {
            issues.add(new Issue(
                    filePath.toString(),
                    lineNumber,
                    "QUA012",
                    Severity.WARNING,
                    Category.QUALITY,
                    "Public mutable field detected.",
                    "Prefer private fields with controlled accessors.",
                    line
            ));
        }
    }

    private static void checkCommentedCode(Path filePath, String line, int lineNumber, List<Issue> issues) {
        String trimmed = line.trim();
        if (trimmed.startsWith("//") &&
                (trimmed.contains("if(") || trimmed.contains("if (") ||
                 trimmed.contains("for(") || trimmed.contains("for (") ||
                 trimmed.contains("System.out.println") || trimmed.contains(";"))) {
            issues.add(new Issue(
                    filePath.toString(),
                    lineNumber,
                    "STY006",
                    Severity.INFO,
                    Category.STYLE,
                    "Possible commented-out code detected.",
                    "Remove dead code to keep the source file clean.",
                    line
            ));
        }
    }

    private static void checkWildcardImport(Path filePath, String line, int lineNumber, List<Issue> issues) {
        if (line.matches("^import\\s+[a-zA-Z0-9_.]+\\.\\*\\s*;")) {
            issues.add(new Issue(
                    filePath.toString(), 
                    lineNumber, 
                    "STY007", 
                    Severity.INFO, 
                    Category.STYLE, 
                    "Wildcard import detected.", 
                    "Import specific classes instead.", 
                    line
            ));
        }
    }

    private static boolean shouldIgnoreLine(String line) {
        return line.trim().isEmpty() || line.trim().startsWith("// Ignore");
    }

    private static boolean isRuleIgnored(String line, String ruleId) {
        return line.contains("suppress:" + ruleId) || line.contains("@SuppressWarnings(\"" + ruleId + "\")");
    }

    private static void printReport(List<Issue> issues, int fileCount) {
        System.out.println("\n--- Scan Results ---");
        System.out.println("Files scanned: " + fileCount);
        System.out.println("Issues found: " + issues.size() + "\n");
        for (Issue issue : issues) {
            System.out.println(issue.toString());
            System.out.println("------------------------------------------------------");
        }
    }
}