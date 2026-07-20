# Cloud.md - AST CLI Java Wrapper Repository

## Project Overview

The **ast-cli-java-wrapper** is a Java SDK/wrapper library that provides a shared infrastructure and abstraction layer for the Checkmarx Application Security Testing (AST) platform. It serves as a client library for integrating AST capabilities into Java-based applications and CI/CD pipelines. The wrapper offers technology-neutral repository interfaces and a metadata model for persisting Java classes, enabling developers to interact with the AST platform programmatically.

**Repository:** https://github.com/CheckmarxDev/ast-cli-java-wrapper  
**Package:** Published as Maven dependency (com.checkmarx.ast:ast-cli-java-wrapper)

---

## Architecture

The ast-cli-java-wrapper follows a modular architecture with clear separation of concerns:

```
ast-cli-java-wrapper/
├── src/main/java/com/checkmarx/ast/
│   ├── wrapper/              # Core wrapper utilities (CxConfig, CxException, CxConstants)
│   ├── asca/                 # ASCA (Application Source Code Analysis) module
│   ├── codebashing/          # CodeBashing integration
│   ├── containersrealtime/   # Container scanning real-time results
│   ├── iacrealtime/          # IaC (Infrastructure as Code) real-time results
│   ├── kicsRealtimeResults/  # KICS (Kics Infrastructure Code Scanner) results
│   ├── ossrealtime/          # OSS (Open Source Software) real-time vulnerability scanning
│   ├── learnMore/            # Learning resources integration
│   ├── mask/                 # Secret masking functionality
│   ├── project/              # Project management interfaces
│   ├── scan/                 # Scan management
│   ├── results/              # Result handling and processing
│   ├── remediation/          # Remediation guidance
│   ├── predicate/            # Predicate-based filtering
│   └── tenant/               # Tenant management
├── src/test/java/            # Unit tests (JUnit 5)
└── src/main/resources/        # Configuration resources
```

**Design Pattern:** The wrapper uses a layered architecture with:
- **Interface Layer:** Technology-neutral interfaces for extensibility
- **Implementation Layer:** Concrete implementations for AST integration
- **Data Model Layer:** POJOs (Plain Old Java Objects) for data persistence and serialization
- **Utility Layer:** Configuration management (CxConfig), exception handling (CxException), and constants

---

## Repository Structure

```
.
├── pom.xml                    # Maven configuration and dependencies
├── README.md                  # User-facing documentation
├── Cloud.md                   # This file - development/deployment documentation
├── src/
│   ├── main/
│   │   ├── java/             # Production source code
│   │   └── resources/         # Configuration files and resources
│   └── test/
│       ├── java/             # Unit tests (JUnit 5 + Jupiter)
│       └── resources/         # Test configuration and fixtures
├── target/                    # Build output (generated during maven clean install)
└── .github/                   # GitHub Actions, workflows (if present)
```

**Key Files:**
- `pom.xml` - Defines Maven build configuration, dependencies, and JaCoCo code coverage plugin
- `src/main/java/com/checkmarx/ast/wrapper/CxConfig.java` - Core configuration class
- `src/main/java/com/checkmarx/ast/wrapper/CxException.java` - Custom exception handling
- `src/main/java/com/checkmarx/ast/wrapper/CxConstants.java` - Application constants

---

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Language** | Java | 8+ |
| **Build Tool** | Maven | 3+ |
| **JSON Processing** | Jackson | 2.21.1 |
| **JSON Serialization** | GSON | 2.12.1 |
| **Utilities** | Lombok | 1.18.32 |
| **Commons** | Apache Commons Lang3 | 3.18.0 |
| **JSON Parsing** | JSON-Simple | 1.1.1 |
| **Logging** | SLF4J | 2.0.12 |
| **Testing** | JUnit 5 (Jupiter) | 5.10.2 |
| **Code Coverage** | JaCoCo | 0.8.8 |

**Key Dependencies:**
- **Jackson** - Primary JSON serialization/deserialization framework
- **GSON** - Alternative/supplementary JSON processing
- **Lombok** - Reduces boilerplate via annotations (@Data, @Getter, @Setter, etc.)
- **SLF4J** - Logging abstraction layer with slf4j-simple binding
- **JUnit 5** - Modern testing framework with parameterized tests and extensions

---

## Development Setup

### Prerequisites

- **Java Development Kit (JDK):** Version 8 or higher
  - Download from [Oracle JDK](https://www.oracle.com/java/technologies/downloads/) or use OpenJDK
  - Verify: `java -version` and `javac -version`

- **Maven:** Version 3.6.0 or higher
  - Download from [Apache Maven](https://maven.apache.org/download.cgi)
  - Verify: `mvn -version`

- **Git:** For cloning and version control

### Local Setup Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/CheckmarxDev/ast-cli-java-wrapper.git
   cd ast-cli-java-wrapper
   ```

2. **Build the project:**
   ```bash
   mvn clean install
   ```
   - Compiles source code, runs tests, and generates JAR artifact
   - Output: `target/ast-cli-java-wrapper-[version].jar`

3. **Run tests:**
   ```bash
   mvn test
   ```

4. **Generate code coverage report:**
   ```bash
   mvn test jacoco:report
   ```
   - Coverage report available at: `target/site/jacoco/index.html`

5. **Install to local Maven repository:**
   ```bash
   mvn install
   ```

### Integration Tests Setup

To run integration tests that interact with the AST platform, set environment variables:

**Linux/macOS:**
```bash
export CX_CLIENT_ID="your_client_id"
export CX_CLIENT_SECRET="your_client_secret"
export CX_APIKEY="your_api_key"
export CX_BASE_URI="https://ast.checkmarx.net"
export CX_BASE_AUTH_URI="https://iam.checkmarx.net"
export CX_TENANT="your_tenant_name"
export PATH_TO_EXECUTABLE="/path/to/ast-cli-executable"
```

**Windows (PowerShell):**
```powershell
setx CX_CLIENT_ID "your_client_id"
setx CX_CLIENT_SECRET "your_client_secret"
setx CX_APIKEY "your_api_key"
setx CX_BASE_URI "https://ast.checkmarx.net"
setx CX_BASE_AUTH_URI "https://iam.checkmarx.net"
setx CX_TENANT "your_tenant_name"
setx PATH_TO_EXECUTABLE "path\to\ast-cli-executable"
```

### IDE Configuration

- **IntelliJ IDEA:** Import project as Maven project, mark `src/main/java` as Sources Root, `src/test/java` as Tests Root
- **Eclipse:** Use `mvn eclipse:eclipse` or import via "Existing Maven Projects"
- **VS Code:** Install "Extension Pack for Java" and "Maven for Java" extensions

---

## Coding Standards

### Code Style Guidelines

1. **Naming Conventions:**
   - Classes: PascalCase (e.g., `CxConfig`, `ScanResult`)
   - Methods/Variables: camelCase (e.g., `getScanId()`, `scanDetails`)
   - Constants: UPPER_SNAKE_CASE (e.g., `MAX_TIMEOUT`, `DEFAULT_PORT`)
   - Private fields: prefix with underscore or use Lombok annotations

2. **Lombok Annotations:**
   - Use `@Data` for POJOs (generates getters, setters, equals, hashCode, toString)
   - Use `@Getter` / `@Setter` for selective generation
   - Use `@AllArgsConstructor` / `@NoArgsConstructor` for constructors
   - Avoid verbose getter/setter implementations

3. **Jackson Annotations:**
   - Use `@JsonProperty("fieldName")` for JSON serialization mapping
   - Use `@JsonIgnore` for excluding fields from JSON
   - Use `@JsonDeserialize` / `@JsonSerialize` for custom type handling

4. **Documentation:**
   - Add JavaDoc comments for public classes and methods
   - Keep comments concise and explain the "why", not the "what"
   - Include examples in JavaDoc for complex methods

5. **Exception Handling:**
   - Extend `CxException` for domain-specific exceptions
   - Use try-catch only for exceptional conditions, not control flow
   - Log exceptions with appropriate level (error, warn, debug)

6. **Code Organization:**
   - Keep classes focused on a single responsibility
   - Group related methods and fields together
   - Use access modifiers appropriately (private by default, public only when needed)

### Code Quality Tools

- **JaCoCo Code Coverage:** Minimum coverage target is maintained via `pom.xml` configuration
  - Excluded packages (data models, generated code) specified in JaCoCo excludes
  - Run: `mvn jacoco:report` to generate coverage report

- **Maven Compiler:** Configured for Java 8 compatibility
  - Source: Java 8
  - Target: Java 8
  - Encoding: UTF-8

---

## Project Rules

1. **Branching Strategy:**
   - Main development branch: `main`
   - Feature branches: `feature/*`
   - Bug fixes: `bugfix/*`
   - Hotfixes: `hotfix/*`
   - Delete merged branches to keep repository clean

2. **Commit Standards:**
   - Write clear, descriptive commit messages
   - Reference Jira ticket IDs in commit messages (e.g., "AST-12345: Add feature description")
   - Keep commits atomic and logically grouped

3. **Pull Requests:**
   - Create PR against `main` branch
   - Include description and acceptance criteria
   - Ensure all tests pass before merging
   - Require code review from at least one team member
   - Squash commits on merge for cleaner history

4. **Version Management:**
   - Versions defined in `pom.xml` as `${ast.wrapper.version}`
   - Follow semantic versioning (MAJOR.MINOR.PATCH)
   - Update version before release
   - Tag releases in Git (e.g., `v1.0.14`)

5. **Dependency Management:**
   - Keep dependencies updated, especially security patches
   - Use Maven Dependabot or similar tools for automatic updates
   - Review dependency changes in PRs for breaking changes
   - Exclude conflicting transitive dependencies if needed

6. **Documentation:**
   - Keep README.md and Cloud.md synchronized with changes
   - Document API changes in PR descriptions
   - Update environment variables list if new ones are required

---

## Testing Strategy

### Testing Pyramid

```
         /\
        /  \  Integration Tests (Integration with AST platform)
       /____\
       /    \
      /      \ Unit Tests (JUnit 5 - ~80% of tests)
     /________\
     /        \
    /          \ Manual Testing & E2E
   /____________\
```

### Unit Testing

- **Framework:** JUnit 5 (Jupiter)
- **Location:** `src/test/java/`
- **Naming Convention:** `*Test.java` or `*Tests.java`
- **Coverage Target:** >70% for core modules
- **Execution:** `mvn test`

**Example Unit Test Structure:**
```java
@DisplayName("ScanResult Tests")
class ScanResultTest {
    @Test
    @DisplayName("Should deserialize scan result from JSON")
    void testDeserializeScanResult() {
        // Test implementation
    }
}
```

### Integration Tests

- **Environment Setup:** Requires AST platform credentials (see Development Setup)
- **Credentials:** Use environment variables for sensitive data
- **Isolation:** Test data should be isolated and cleaned up after tests
- **Skip in CI:** Can be skipped in pull request CI if platform access is limited

### Test Fixtures & Mocks

- Use JSON files in `src/test/resources/` for sample data
- Mock external dependencies where appropriate
- Use parameterized tests (`@ParameterizedTest`) for multiple scenarios

### Code Coverage

- **Tool:** JaCoCo Maven Plugin
- **Report Location:** `target/site/jacoco/index.html`
- **Excluded from Coverage:** Data models, POJOs, generated code (as specified in pom.xml)
- **Run:** `mvn test jacoco:report`

---

## Known Issues

1. **Java 8 Compatibility:** The project targets Java 8 for compatibility with older systems, which limits access to newer Java features (records, text blocks, sealed classes, etc.)

2. **Dual JSON Libraries:** Both Jackson and GSON are included as dependencies, which may lead to subtle differences in serialization behavior. Prefer Jackson for primary serialization unless GSON is specifically required.

3. **SLF4J Simple Binding:** The `slf4j-simple` binding is basic and may not be suitable for production environments. Consider switching to Logback or Log4j2 for advanced features.

4. **JaCoCo Excludes:** Large portions of the codebase are excluded from code coverage (data models, results, etc.), which may mask untested code paths. Review excludes periodically.

5. **Maven Build Performance:** Large transitive dependency trees and full coverage analysis can slow down builds. Use `mvn clean install -DskipTests` for faster builds during development.

---

## Database Schema

Not applicable - this is a client library with no persistent storage or database dependencies.

---

## External Integrations

1. **Checkmarx AST Platform:**
   - **Purpose:** Provides security scanning, remediation guidance, and vulnerability data
   - **Integration Points:** REST API calls via HTTP clients
   - **Authentication:** OAuth 2.0 via `CX_CLIENT_ID` and `CX_CLIENT_SECRET`, or API key via `CX_APIKEY`
   - **Endpoints:** Configured via `CX_BASE_URI` and `CX_BASE_AUTH_URI`

2. **Maven Central Repository:**
   - **Artifact:** com.checkmarx.ast:ast-cli-java-wrapper
   - **Distribution:** Published JAR for inclusion in other projects

3. **GitHub:**
   - **Repository:** CheckmarxDev/ast-cli-java-wrapper
   - **CI/CD:** Likely uses GitHub Actions for automated builds and tests

---

## Deployment Info

### Publishing to Maven Central

1. **Build Release:**
   ```bash
   mvn clean install
   ```

2. **Create Release Tag:**
   ```bash
   git tag -a v1.0.14 -m "Release version 1.0.14"
   git push origin v1.0.14
   ```

3. **Deploy to Maven Central (Checkmarx Process):**
   - Typically handled by CI/CD pipeline or release manager
   - Requires Sonatype credentials and GPG signing
   - Uses `mvn deploy` with Maven settings.xml configuration

### Artifact Coordinates

```xml
<dependency>
    <groupId>com.checkmarx.ast</groupId>
    <artifactId>ast-cli-java-wrapper</artifactId>
    <version>1.0.14</version>
</dependency>
```

### Versioning

- Current version: Check `pom.xml` for `<ast.wrapper.version>` property
- Increment version before release
- Use semantic versioning (MAJOR.MINOR.PATCH)

---

## Performance Considerations

1. **Serialization:** Jackson is the primary JSON serialization engine and is optimized for performance. Ensure large result sets are streamed rather than loaded entirely in memory.

2. **HTTP Client Configuration:** Consider connection pooling and timeout configurations when making requests to the AST platform.

3. **Memory Usage:** For large scan results (KICS, OSS, containers), implement pagination or streaming to avoid OutOfMemoryError.

4. **Compilation:** Java 8 target ensures compatibility but limits optimization opportunities available in newer Java versions.

5. **Build Optimization:** Use `mvn clean install -T 1C` for parallel build threads to speed up compilation.

---

## API/Endpoints/Interfaces

### Core Interfaces

**CxConfig** - Configuration management
- `getClientId()` - OAuth client identifier
- `getClientSecret()` - OAuth client secret
- `getApiKey()` - API key for authentication
- `getBaseUri()` - AST platform base URL
- `getBaseAuthUri()` - Identity/authentication service URL
- `getTenant()` - Tenant identifier

**CxException** - Custom exception for domain errors
- Extends RuntimeException
- Used for all AST-specific error conditions

### Module-Specific Interfaces

- **Scan Module:** Scan creation, retrieval, status management
- **Results Module:** Result parsing, filtering, and analysis
- **ASCA Module:** Application source code analysis results
- **OSS Module:** Open source software vulnerability data
- **KICS Module:** Infrastructure as code scanning results
- **Remediation Module:** Remediation guidance and solutions
- **CodeBashing Module:** Security training integration
- **Containers Module:** Container image scanning results

---

## Security & Access

### Authentication

1. **OAuth 2.0:**
   - Client ID: `CX_CLIENT_ID`
   - Client Secret: `CX_CLIENT_SECRET`
   - Token endpoint: `CX_BASE_AUTH_URI`
   - Recommended for service-to-service integration

2. **API Key:**
   - API Key: `CX_APIKEY`
   - Recommended for personal use and testing
   - Less secure than OAuth, use with caution in production

### Authorization

- **Tenant-Based:** Access controlled at tenant level via `CX_TENANT`
- **Scope-Based:** Different operations may require different permissions in AST platform
- **Role-Based:** User roles in AST platform determine available operations

### Secrets Management

- **Never commit credentials** to version control
- Use environment variables for local development
- Use CI/CD secrets managers for automated deployments
- Rotate API keys and client secrets regularly
- Audit access logs for suspicious activity

### Data Protection

- Use HTTPS for all API communication
- Jackson's default serialization is safe from injection attacks
- Validate all external input before processing
- Sanitize output if displaying user data
- Review JaCoCo excludes to ensure security code is tested

---

## Logging

### Logging Framework

- **Framework:** SLF4J with slf4j-simple binding
- **Configuration:** Can be customized via `simplelogger.properties` in classpath
- **Production Use:** Consider upgrading to Logback or Log4j2 for advanced features

### Logger Usage

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class MyClass {
    private static final Logger log = LoggerFactory.getLogger(MyClass.class);
    
    public void myMethod() {
        log.info("Operation started");
        log.debug("Debug information");
        log.warn("Warning message");
        log.error("Error occurred", exception);
    }
}
```

### Log Levels

- **DEBUG:** Detailed information for debugging
- **INFO:** General informational messages
- **WARN:** Warning messages for potentially problematic situations
- **ERROR:** Error messages for failures

### Sensitive Data

- Never log credentials, API keys, or secrets
- Mask sensitive information in logs (user IDs, tokens, etc.)
- Use `log.debug()` for development-only logging
- Review logs regularly for security issues

---

## Debugging Steps

### Local Debugging

1. **Enable Debug Logging:**
   ```bash
   mvn test -Dorg.slf4j.simpleLogger.defaultLogLevel=debug
   ```

2. **IDE Debugging:**
   - Set breakpoints in IDE
   - Run tests in debug mode: Right-click test → "Debug"
   - Use IntelliJ Debugger or Eclipse Debug perspective

3. **Maven Debug Output:**
   ```bash
   mvn -X clean install  # Very verbose output
   mvn -e test           # Print stack traces
   ```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Test failures | Missing environment variables | Set CX_* environment variables for integration tests |
| Build failures | Java version mismatch | Ensure JDK 8+ is installed and JAVA_HOME is set |
| Dependency conflicts | Transitive dependency issues | Check pom.xml for exclusions or use `mvn dependency:tree` |
| OOM errors | Large scan results | Increase heap size: `export MAVEN_OPTS="-Xmx2g"` |
| Slow builds | Parallel testing disabled | Use `mvn clean install -T 1C` for parallel builds |

### Useful Maven Commands

```bash
mvn dependency:tree              # Show dependency hierarchy
mvn help:describe-mojo -Dplugin=org.apache.maven.plugins:maven-compiler-plugin  # Plugin help
mvn clean install -o             # Offline build (use cached dependencies)
mvn test -Dtest=ScanResultTest   # Run specific test
mvn test -Dtest=*Integration     # Run tests matching pattern
```

### Profiling & Analysis

```bash
# Generate detailed build report
mvn clean install -Dmaven.compiler.verbose=true

# Check for deprecated API usage
mvn compile -Werror:sunapi

# Analyze code with SpotBugs (if configured)
mvn spotbugs:check
```

---

## Contributing

- Follow coding standards outlined above
- Write unit tests for new functionality
- Ensure all tests pass: `mvn clean install`
- Update documentation for API changes
- Create pull request with clear description
- Respond to code review feedback
- Maintain backward compatibility where possible

---

## Support & Contact

**Team:** Checkmarx - AST Integrations Team  
**Project Link:** https://github.com/CheckmarxDev/ast-cli-java-wrapper  
**Issues:** GitHub Issues for bug reports and feature requests

---

**Last Updated:** April 20, 2026  
**Status:** In Active Development
