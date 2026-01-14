package com.checkmarx.ast.wrapper;

import com.checkmarx.ast.asca.ScanResult;
import com.checkmarx.ast.codebashing.CodeBashing;
import com.checkmarx.ast.kicsRealtimeResults.KicsRealtimeResults;
import com.checkmarx.ast.learnMore.LearnMore;
import com.checkmarx.ast.mask.MaskResult;
import com.checkmarx.ast.ossrealtime.OssRealtimeResults;
import com.checkmarx.ast.secretsrealtime.SecretsRealtimeResults;

import com.checkmarx.ast.iacrealtime.IacRealtimeResults;
import com.checkmarx.ast.containersrealtime.ContainersRealtimeResults;
import com.checkmarx.ast.predicate.CustomState;
import com.checkmarx.ast.predicate.Predicate;
import com.checkmarx.ast.project.Project;
import com.checkmarx.ast.remediation.KicsRemediation;
import com.checkmarx.ast.results.ReportFormat;
import com.checkmarx.ast.results.Results;
import com.checkmarx.ast.results.ResultsSummary;
import com.checkmarx.ast.results.result.Node;
import com.checkmarx.ast.scan.Scan;
import com.checkmarx.ast.tenant.TenantSetting;
import com.checkmarx.ast.utils.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.util.*;

import static com.checkmarx.ast.wrapper.Execution.*;

public class CxWrapper {

    private static final CollectionType BRANCHES_TYPE = TypeFactory.defaultInstance()
            .constructCollectionType(List.class, String.class);
    private static final String OS_LINUX = "linux";
    private static final String OS_WINDOWS = "windows";
    private static final String OS_MAC = "mac";

    @NonNull
    private final CxConfig cxConfig;
    @NonNull
    private final Logger logger;
    @NonNull
    private final String executable;

    public CxWrapper(CxConfig cxConfig) throws IOException {
        this(cxConfig, LoggerFactory.getLogger(CxWrapper.class));
    }

    public CxWrapper(@NonNull CxConfig cxConfig, @NonNull Logger logger) throws IOException {
        this.cxConfig = cxConfig;
        this.logger = logger;
        this.executable = StringUtils.isBlank(this.cxConfig.getPathToExecutable())
                ? Execution.getTempBinary(logger)
                : this.cxConfig.getPathToExecutable();
        this.logger.info("Executable path: {} ", executable);
    }

    public String authValidate() throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'auth validate' command using the CLI.");

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_AUTH);
        arguments.add(CxConstants.SUB_CMD_VALIDATE);

        return Execution.executeCommand(withConfigArguments(arguments), logger, line -> line);
    }

    public Scan scanShow(@NonNull UUID scanId) throws IOException, InterruptedException, CxException {
        this.logger.info("Retrieving the details for scan id: {}", scanId);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_SCAN);
        arguments.add(CxConstants.SUB_CMD_SHOW);
        arguments.add(CxConstants.SCAN_ID);
        arguments.add(scanId.toString());
        arguments.addAll(jsonArguments());

        return Execution.executeCommand(withConfigArguments(arguments), logger, Scan::fromLine);
    }

    public List<Scan> scanList() throws IOException, InterruptedException, CxException {
        return scanList("");
    }

    public List<Scan> scanList(String filter) throws IOException, InterruptedException, CxException {
        this.logger.info("Fetching the scan list using the filter: {}", filter);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_SCAN);
        arguments.add(CxConstants.SUB_CMD_LIST);
        arguments.addAll(jsonArguments());
        arguments.addAll(filterArguments(filter));

        return Execution.executeCommand(withConfigArguments(arguments), logger, Scan::listFromLine);
    }

    public Scan scanCreate(@NonNull Map<String, String> params) throws IOException, InterruptedException, CxException {
        return scanCreate(params, "");
    }

    public Scan scanCreate(@NonNull Map<String, String> params, String additionalParameters)
            throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'scan create' command using the CLI.");

        List<String> arguments = buildScanCreateArguments(params, additionalParameters);

        return Execution.executeCommand(arguments, logger, Scan::fromLine);
    }

    public List<String> buildScanCreateArguments(@NonNull Map<String, String> params, String additionalParameters) {
        return withConfigArguments(buildScanCreateArgumentsArray(params, additionalParameters));
    }

    private List<String> buildScanCreateArgumentsArray(@NonNull Map<String, String> params, String additionalParameters) {
        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_SCAN);
        arguments.add(CxConstants.SUB_CMD_CREATE);
        arguments.add(CxConstants.SCAN_INFO_FORMAT);
        arguments.add(CxConstants.FORMAT_JSON);

        for (Map.Entry<String, String> param : params.entrySet()) {
            arguments.add(param.getKey());
            arguments.add(param.getValue());
        }

        arguments.addAll(CxConfig.parseAdditionalParameters(additionalParameters));
        return arguments;
    }

    public void scanCancel(String scanId)
            throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'scan cancel' command using the CLI.");

        List<String> arguments = buildScanCancelArguments(UUID.fromString(scanId));

        Execution.executeCommand(arguments, logger, line -> null);
    }

    public List<String> buildScanCancelArguments(@NonNull UUID scanId) {
        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_SCAN);
        arguments.add(CxConstants.SUB_CMD_CANCEL);
        arguments.add(CxConstants.SCAN_ID);
        arguments.add(scanId.toString());

        return withConfigArguments(arguments);
    }

    public List<Predicate> triageShow(@NonNull UUID projectId, String similarityId, String scanType) throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'triage show' command using the CLI.");
        this.logger.info("Fetching the list of predicates for projectId {} , similarityId {} and scan-type {}.", projectId, similarityId, scanType);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_TRIAGE);
        arguments.add(CxConstants.SUB_CMD_SHOW);
        arguments.add(CxConstants.PROJECT_ID);
        arguments.add(projectId.toString());
        arguments.add(CxConstants.SIMILARITY_ID);
        arguments.add(similarityId);
        arguments.add(CxConstants.SCAN_TYPE);
        arguments.add(scanType);

        arguments.addAll(jsonArguments());

        return Execution.executeCommand(withConfigArguments(arguments), logger, Predicate::listFromLine, Predicate::validator);
    }

    public List<CustomState> triageGetStates(boolean all) throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'triage get-states' command using the CLI.");

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_TRIAGE);
        arguments.add(CxConstants.SUB_CMD_GET_STATES);
        if (all) {
            arguments.add(CxConstants.ALL_STATES_FLAG);
        }

        return Execution.executeCommand(withConfigArguments(arguments), logger, CustomState::listFromLine);
    }

    public void triageUpdate(@NonNull UUID projectId, String similarityId, String scanType, String state, String comment, String severity) throws IOException, InterruptedException, CxException {
        triageUpdate(projectId, similarityId, scanType, state, comment, severity, null);
    }

    public void triageUpdate(@NonNull UUID projectId, String similarityId, String scanType, String state, String comment, String severity, String customStateId) throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'triage update' command using the CLI.");
        this.logger.info("Updating the similarityId {} with state {} with customStateId {} and severity {}.", similarityId, state, customStateId, severity);

        boolean emptyCustomStateId = customStateId == null || customStateId.isEmpty();

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_TRIAGE);
        arguments.add(CxConstants.SUB_CMD_UPDATE);
        arguments.add(CxConstants.PROJECT_ID);
        arguments.add(projectId.toString());
        arguments.add(CxConstants.SIMILARITY_ID);
        arguments.add(similarityId);
        arguments.add(CxConstants.SCAN_TYPE);
        arguments.add(scanType);
        arguments.add(CxConstants.STATE);
        arguments.add(state);
        if (!emptyCustomStateId) {
            arguments.add(CxConstants.CUSTOM_STATE_ID);
            arguments.add(customStateId);
        }
        if (!StringUtils.isBlank(comment)) {
            arguments.add(CxConstants.COMMENT);
            arguments.add(comment);
        }
        arguments.add(CxConstants.SEVERITY);
        arguments.add(severity);

        Execution.executeCommand(withConfigArguments(arguments), logger, line -> null);
    }

    public Project projectShow(@NonNull UUID projectId) throws IOException, InterruptedException, CxException {
        this.logger.info("Retrieving the details for project id: {}", projectId);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_PROJECT);
        arguments.add(CxConstants.SUB_CMD_SHOW);
        arguments.add(CxConstants.PROJECT_ID);
        arguments.add(projectId.toString());
        arguments.addAll(jsonArguments());

        return Execution.executeCommand(withConfigArguments(arguments), logger, Project::fromLine);
    }

    public List<Project> projectList() throws IOException, InterruptedException, CxException {
        return projectList("");
    }

    public List<Project> projectList(String filter) throws IOException, InterruptedException, CxException {
        this.logger.info("Fetching the project list using the filter: {}", filter);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_PROJECT);
        arguments.add(CxConstants.SUB_CMD_LIST);
        arguments.addAll(filterArguments(filter));
        arguments.addAll(jsonArguments());

        return Execution.executeCommand(withConfigArguments(arguments), logger, Project::listFromLine);
    }

    public ScanResult ScanAsca(String fileSource, boolean ascaLatestVersion, String agent) throws IOException, InterruptedException, CxException {
        this.logger.info("Fetching ASCA scanResult");

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_SCAN);
        arguments.add(CxConstants.SUB_CMD_ASCA);
        arguments.add(CxConstants.FILE_SOURCE);
        arguments.add(fileSource);
        if (ascaLatestVersion) {
            arguments.add(CxConstants.ASCA_LATEST_VERSION);
        }

        appendAgentToArguments(agent, arguments);

        return Execution.executeCommand(withConfigArguments(arguments), logger, ScanResult::fromLine,
                (args, ignored) ->
                        (args.size() >= 3 && args.get(1).equals(CxConstants.CMD_SCAN) && args.get(2).equals(CxConstants.SUB_CMD_ASCA)));
    }

    private static void appendAgentToArguments(String agent, List<String> arguments) {
        arguments.add(CxConstants.AGENT);
        if (agent != null && !agent.isEmpty()){
            arguments.add(agent);
        }
        else{
            arguments.add("CLI-Java-Wrapper");
        }
    }

    public List<String> projectBranches(@NonNull UUID projectId, String filter)
            throws CxException, IOException, InterruptedException {
        this.logger.info("Fetching the branches for project id {} using the filter: {}", projectId, filter);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_PROJECT);
        arguments.add(CxConstants.SUB_CMD_BRANCHES);
        arguments.add(CxConstants.PROJECT_ID);
        arguments.add(projectId.toString());
        arguments.addAll(filterArguments(filter));

        return Execution.executeCommand(withConfigArguments(arguments),
                logger,
                line -> JsonParser.parse(line, BRANCHES_TYPE));
    }

    public List<CodeBashing> codeBashingList(@NonNull String cweId, @NonNull String language, @NonNull String queryName) throws IOException, InterruptedException, CxException {
        this.logger.info("Fetching the codebashing link");

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_RESULT);
        arguments.add(CxConstants.SUB_CMD_CODE_BASHING);
        arguments.add(CxConstants.LANGUAGE);
        arguments.add(language);
        arguments.add(CxConstants.VULNERABILITY_TYPE);
        arguments.add(queryName);
        arguments.add(CxConstants.CWE_ID);
        arguments.add(cweId);
        arguments.addAll(jsonArguments());

        return Execution.executeCommand(withConfigArguments(arguments), logger, CodeBashing::listFromLine);
    }

    public ResultsSummary resultsSummary(@NonNull UUID scanId) throws IOException, InterruptedException, CxException {
        return new ObjectMapper()
                .readerFor(ResultsSummary.class)
                .readValue(results(scanId, ReportFormat.summaryJSON));
    }

    public Results results(@NonNull UUID scanId) throws IOException, InterruptedException, CxException {
        return new ObjectMapper()
                .readerFor(Results.class)
                .readValue(results(scanId, ReportFormat.json));
    }

    public Results results(@NonNull UUID scanId, String agent) throws IOException, InterruptedException, CxException {
        return new ObjectMapper()
                .readerFor(Results.class)
                .readValue(results(scanId, ReportFormat.json, agent));
    }

    public String results(@NonNull UUID scanId, ReportFormat reportFormat)
            throws IOException, InterruptedException, CxException {
        return results(scanId, reportFormat, null);
    }
    public String results(@NonNull UUID scanId, ReportFormat reportFormat, String agent)
            throws IOException, InterruptedException, CxException {
        this.logger.info("Retrieving the scan result for scan id {}", scanId);

        String tempDir = Files.createTempDirectory("cx").toAbsolutePath().toString();
        String fileName = Long.toString(System.nanoTime());

        List<String> arguments = buildResultsArguments(scanId, reportFormat);

        arguments.add(CxConstants.OUTPUT_NAME);
        arguments.add(fileName);
        arguments.add(CxConstants.OUTPUT_PATH);
        arguments.add(tempDir);
        if (agent != null) {
            arguments.add(CxConstants.AGENT);
            arguments.add(agent);
        }
        return Execution.executeCommand(arguments,
                logger, tempDir,
                fileName + reportFormat.getExtension());
    }

    public String scaRemediation(String packageFiles, String packages, String packageVersion) throws CxException, IOException, InterruptedException {
        List<String> arguments = new ArrayList<>();

        arguments.add(CxConstants.CMD_UTILS);
        arguments.add(CxConstants.CMD_REMEDIATION);
        arguments.add(CxConstants.SUB_CMD_REMEDIATION_SCA);
        arguments.add(CxConstants.SCA_REMEDIATION_PACKAGE_FILES);
        arguments.add(packageFiles);
        arguments.add(CxConstants.SCA_REMEDIATION_PACKAGE);
        arguments.add(packages);
        arguments.add(CxConstants.SCA_REMEDIATION_PACKAGE_VERSION);
        arguments.add(packageVersion);

        return Execution.executeCommand(withConfigArguments(arguments), logger, line -> null);
    }

    public int getResultsBfl(@NonNull UUID scanId, @NonNull String queryId, List<Node> resultNodes)
            throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'results bfl' command using the CLI.");
        this.logger.info("Fetching the best fix location for ScanId {} and QueryId {}", scanId, queryId);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_RESULT);
        arguments.add(CxConstants.RESULTS_BFL_SUB_CMD);
        arguments.add(CxConstants.SCAN_ID);
        arguments.add(scanId.toString());
        arguments.add(CxConstants.QUERY_ID);
        arguments.add(queryId);
        arguments.addAll(jsonArguments());

        List<Node> bflNodes = Execution.executeCommand(withConfigArguments(arguments), logger, Node::listFromLine);
        return getIndexOfBfLNode(bflNodes, resultNodes);

    }

    public KicsRealtimeResults kicsRealtimeScan(@NonNull String fileSources, String engine, String additionalParams)
            throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'scan kics-realtime' command using the CLI.");
        this.logger.info("Fetching the results for fileSources {} and additionalParams {}", fileSources, additionalParams);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_SCAN);
        arguments.add(CxConstants.SUB_CMD_KICS_REALTIME);
        arguments.add(CxConstants.FILE);
        arguments.add(fileSources);
        arguments.add(CxConstants.ADDITONAL_PARAMS);
        arguments.add(additionalParams);
        if (!engine.isEmpty()) {
            arguments.add(CxConstants.ENGINE);
            arguments.add(engine);
        }

        return Execution.executeCommand(withConfigArguments(arguments), logger, KicsRealtimeResults::fromLine);
    }

    public String checkEngineExist(@NonNull String engineName) throws CxException, IOException, InterruptedException {
             String osName = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
             String osType=Execution.getOperatingSystemType(osName);
                return this.checkEngine(engineName,osType);
    }

    private  String checkEngine(String engineName, String osType ) throws CxException, IOException, InterruptedException {
        List<String> arguments = new ArrayList<>();
        switch (osType){
            case OS_MAC:
                String enginePath;
                arguments.add("/bin/sh");
                arguments.add("-c");
                arguments.add("command -v " + engineName);
                try{
                    enginePath= Execution.executeCommand((arguments), logger, line->line);
                }
                catch (CxException e){
                    throw new CxException(1,"Engine "+engineName+" is not installed on the system");
                }

                if(!enginePath.startsWith("/usr/local/bin/")){
                    throw new CxException(1, engineName+ " was found at: " + enginePath + "\n" +
                            "Please create a symlink at /usr/local/bin/docker:\n\n" +
                            "sudo ln -s " + enginePath + " /usr/local/bin/"+engineName +"\n");
                }
                return enginePath;
            case OS_WINDOWS:
            case OS_LINUX:
                arguments.add(engineName);
                arguments.add("--version");
                try {
                    Execution.executeCommand(arguments, logger, line -> line);
                    return engineName; // docker is available via PATH
                } catch (CxException | IOException e) {
                    throw new CxException(
                            1,engineName+" is not installed or is not accessible from the system PATH."
                    );
                }
            default:
                throw new IllegalArgumentException("Unsupported OS: " + osType);
        }

    }

    public <T> T realtimeScan(@NonNull String subCommand, @NonNull String sourcePath, String containerTool, String ignoredFilePath, java.util.function.Function<String, T> resultParser)
            throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'scan {}' command using the CLI.", subCommand);
        this.logger.info("Source: {} IgnoredFilePath: {}", sourcePath, ignoredFilePath);
        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_SCAN);
        arguments.add(subCommand);
        arguments.add(CxConstants.SOURCE);
        arguments.add(sourcePath);
        if(StringUtils.isNotBlank(containerTool)){
            arguments.add(CxConstants.ENGINE);
            arguments.add(containerTool);
        }
        if (StringUtils.isNotBlank(ignoredFilePath)) {
            arguments.add(CxConstants.IGNORED_FILE_PATH);
            arguments.add(ignoredFilePath);
        }
        return Execution.executeCommand(withConfigArguments(arguments), logger, resultParser);
    }

    // OSS Realtime
    public OssRealtimeResults ossRealtimeScan(@NonNull String sourcePath, String ignoredFilePath)
            throws IOException, InterruptedException, CxException {
        return realtimeScan(CxConstants.SUB_CMD_OSS_REALTIME, sourcePath,"", ignoredFilePath, OssRealtimeResults::fromLine);
    }

    // IAC Realtime
    public IacRealtimeResults iacRealtimeScan(@NonNull String sourcePath,String containerTool, String ignoredFilePath)
            throws IOException, InterruptedException, CxException {
        return realtimeScan(CxConstants.SUB_CMD_IAC_REALTIME, sourcePath,containerTool, ignoredFilePath, IacRealtimeResults::fromLine);
    }


    // Secrets Realtime
    public SecretsRealtimeResults secretsRealtimeScan(@NonNull String sourcePath, String ignoredFilePath)
            throws IOException, InterruptedException, CxException {
        return realtimeScan(CxConstants.SUB_CMD_SECRETS_REALTIME, sourcePath,"", ignoredFilePath, SecretsRealtimeResults::fromLine);
    }

    // Containers Realtime
    public ContainersRealtimeResults containersRealtimeScan(@NonNull String sourcePath, String ignoredFilePath)
            throws IOException, InterruptedException, CxException {
        return realtimeScan(CxConstants.SUB_CMD_CONTAINERS_REALTIME, sourcePath, "",ignoredFilePath, ContainersRealtimeResults::fromLine);
    }

    public KicsRemediation kicsRemediate(@NonNull String resultsFile, String kicsFile, String engine,String similarityIds)
            throws IOException, InterruptedException, CxException {
        this.logger.info("Executing 'remediation kics' command using the CLI.");
        this.logger.info("Applying remediation for resultsFile {} and resultsFile {}", resultsFile, kicsFile);

        List<String> arguments = new ArrayList<>();
        arguments.add(this.executable);
        arguments.add(CxConstants.CMD_UTILS);
        arguments.add(CxConstants.CMD_REMEDIATION);
        arguments.add(CxConstants.SUB_CMD_REMEDIATION_KICS);
        arguments.add(CxConstants.KICS_REMEDIATION_RESULTS_FILE);
        arguments.add(resultsFile);
        arguments.add(CxConstants.KICS_REMEDIATION_KICS_FILE);
        arguments.add(kicsFile);
        if (!engine.isEmpty()) {
            arguments.add(CxConstants.ENGINE);
            arguments.add(engine);
        }
        if (!similarityIds.isEmpty()) {
            arguments.add(CxConstants.KICS_REMEDIATION_SIMILARITY);
            arguments.add(similarityIds);
        }

        return Execution.executeCommand(arguments, logger, KicsRemediation::fromLine);
    }

    public List<LearnMore> learnMore(String queryId) throws CxException, IOException, InterruptedException {
        List<String> arguments = new ArrayList<>();

        arguments.add(CxConstants.CMD_UTILS);
        arguments.add(CxConstants.SUB_CMD_LEARN_MORE);
        arguments.add(CxConstants.QUERY_ID);
        arguments.add(queryId);
        arguments.add(CxConstants.FORMAT);
        arguments.add(CxConstants.FORMAT_JSON);

        return Execution.executeCommand(withConfigArguments(arguments), logger, LearnMore::listFromLine);
    }

    public boolean ideScansEnabled() throws CxException, IOException, InterruptedException {
        List<TenantSetting> tenantSettings = tenantSettings();
        if (tenantSettings == null) {
            throw new CxException(1, "Unable to parse tenant settings");
        }
        return tenantSettings.stream()
                             .filter(t -> t.getKey().equals(CxConstants.IDE_SCANS_KEY))
                             .findFirst()
                             .map(t -> Boolean.parseBoolean(t.getValue()))
                             .orElse(false);
    }

    public boolean aiMcpServerEnabled() throws CxException, IOException, InterruptedException {
        List<TenantSetting> tenantSettings = tenantSettings();
        if (tenantSettings == null) {
            throw new CxException(1, "Unable to parse tenant settings");
        }
        return tenantSettings.stream()
                .filter(t -> t.getKey().equals(CxConstants.AI_MCP_SERVER_KEY))
                .findFirst()
                .map(t -> Boolean.parseBoolean(t.getValue()))
                .orElse(false);
    }

    public List<TenantSetting> tenantSettings() throws CxException, IOException, InterruptedException {
        List<String> arguments = jsonArguments();

        arguments.add(CxConstants.CMD_UTILS);
        arguments.add(CxConstants.SUB_CMD_TENANT);

        return Execution.executeCommand(withConfigArguments(arguments), logger, TenantSetting::listFromLine);
    }

    public MaskResult maskSecrets(@NonNull String filePath) throws CxException, IOException, InterruptedException {
        List<String> arguments = new ArrayList<>();

        arguments.add(CxConstants.CMD_UTILS);
        arguments.add(CxConstants.SUB_CMD_MASK);
        arguments.add(CxConstants.RESULT_FILE);
        arguments.add(filePath);

        return Execution.executeCommand(withConfigArguments(arguments), logger, MaskResult::fromLine);
    }

    /**
     * Executes telemetry AI command to collect telemetry data for user interactions related to AI features.
     *
     * @param aiProvider AI provider name (e.g., "Copilot")
     * @param agent Agent name (e.g., "Jetbrains")
     * @param eventType Event type (e.g., "click")
     * @param subType Event subtype (e.g., "ast-results.viewPackageDetails")
     * @param engine Engine type (e.g., "secrets")
     * @param problemSeverity Severity level (e.g., "high")
     * @param scanType Type of scan
     * @param status Status information
     * @param totalCount Number count
     * @return Command output as string
     * @throws IOException if I/O error occurs
     * @throws InterruptedException if command execution is interrupted
     * @throws CxException if CLI command fails
     */
    public String telemetryAIEvent(String aiProvider, String agent, String eventType, String subType,
                                  String engine, String problemSeverity, String scanType, String status,
                                  Integer totalCount) throws IOException, InterruptedException, CxException {
        this.logger.info("Executing telemetry AI event with provider: {}, type: {}, subType: {}",
                         aiProvider, eventType, subType);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_TELEMETRY);
        arguments.add(CxConstants.SUB_CMD_TELEMETRY_AI);
        arguments.add(CxConstants.AI_PROVIDER);
        arguments.add(aiProvider);
        arguments.add(CxConstants.AGENT);
        arguments.add(agent);
        arguments.add(CxConstants.TYPE);
        arguments.add(eventType);
        arguments.add(CxConstants.SUB_TYPE);
        arguments.add(subType);
        arguments.add(CxConstants.ENGINE);
        arguments.add(engine);
        arguments.add(CxConstants.PROBLEM_SEVERITY);
        arguments.add(problemSeverity);
        arguments.add(CxConstants.SCAN_TYPE_FLAG);
        arguments.add(scanType);
        arguments.add(CxConstants.STATUS);
        arguments.add(status);
        arguments.add(CxConstants.TOTAL_COUNT);
        arguments.add(totalCount.toString());

        return Execution.executeCommand(withConfigArguments(arguments), logger, line -> line);
    }

    private int getIndexOfBfLNode(List<Node> bflNodes, List<Node> resultNodes) {

        int bflNodeNotFound = -1;
        for (Node bflNode : bflNodes) {
            for (Node resultNode : resultNodes) {
                if (bflNode.equals(resultNode)) {
                    return resultNodes.indexOf(resultNode);
                }
            }
        }
        return bflNodeNotFound;
    }

    public List<String> buildResultsArguments(@NonNull UUID scanId, ReportFormat reportFormat) {
        return withConfigArguments(buildResultsArgumentsArray(scanId, reportFormat));
    }

    private List<String> buildResultsArgumentsArray(UUID scanId, ReportFormat reportFormat) {
        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_RESULT);
        arguments.add(CxConstants.SUB_CMD_SHOW);
        arguments.add(CxConstants.SCAN_ID);
        arguments.add(scanId.toString());
        arguments.add(CxConstants.REPORT_FORMAT);
        arguments.add(reportFormat.toString());

        return arguments;
    }

    private List<String> withConfigArguments(List<String> commands) {
        List<String> arguments = new ArrayList<>();

        arguments.add(this.executable);
        arguments.addAll(commands);
        arguments.addAll(this.cxConfig.toArguments());

        return arguments;
    }

    private List<String> jsonArguments() {
        List<String> arguments = new ArrayList<>();

        arguments.add(CxConstants.FORMAT);
        arguments.add(CxConstants.FORMAT_JSON);

        return arguments;
    }

    private List<String> filterArguments(String filter) {
        List<String> arguments = new ArrayList<>();

        if (StringUtils.isNotBlank(filter)) {
            arguments.add(CxConstants.FILTER);
            arguments.add(filter);
        }

        return arguments;
    }
}
