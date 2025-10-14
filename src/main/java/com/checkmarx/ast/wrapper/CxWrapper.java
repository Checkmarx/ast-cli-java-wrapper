package com.checkmarx.ast.wrapper;

import com.checkmarx.ast.asca.ScanResult;
import com.checkmarx.ast.codebashing.CodeBashing;
import com.checkmarx.ast.engines.Engines;
import com.checkmarx.ast.kicsRealtimeResults.KicsRealtimeResults;
import com.checkmarx.ast.learnMore.LearnMore;
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
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class CxWrapper {

    private static final CollectionType BRANCHES_TYPE = TypeFactory.defaultInstance()
            .constructCollectionType(List.class, String.class);

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
        if (engine.length() > 0) {
            arguments.add(CxConstants.ENGINE);
            arguments.add(engine);
        }

        return Execution.executeCommand(withConfigArguments(arguments), logger, KicsRealtimeResults::fromLine);
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
        if (engine.length() > 0) {
            arguments.add(CxConstants.ENGINE);
            arguments.add(engine);
        }
        if (similarityIds.length() > 0) {
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

    public List<TenantSetting> tenantSettings() throws CxException, IOException, InterruptedException {
        List<String> arguments = jsonArguments();

        arguments.add(CxConstants.CMD_UTILS);
        arguments.add(CxConstants.SUB_CMD_TENANT);

        return Execution.executeCommand(withConfigArguments(arguments), logger, TenantSetting::listFromLine);
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

    private List<String> jsonArguments2() {
        List<String> arguments = new ArrayList<>();

        arguments.add(CxConstants.OUTPUT_FORMAT);
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

    private List<String> engineFilterArguments(String filter) {
        List<String> arguments = new ArrayList<>();

        if (StringUtils.isNotBlank(filter)) {
            arguments.add(CxConstants.ENGINE_NAME_FILTER);
            arguments.add(filter);
        }

        return arguments;
    }

    public Engines listApi(String filter) throws IOException, InterruptedException, CxException {
        this.logger.info("Fetching the api list using the filter: {}", filter);

        List<String> arguments = new ArrayList<>();
        arguments.add(CxConstants.CMD_ENGINES);
        arguments.add(CxConstants.SUB_CMD_LIST_API);
        arguments.addAll(engineFilterArguments(filter));
        arguments.addAll(jsonArguments2());

        return Execution.executeCommand(withConfigArguments(arguments), logger, Engines::fromLine);
    }
}