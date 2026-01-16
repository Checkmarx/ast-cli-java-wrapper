package com.checkmarx.ast.wrapper;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Data
@Builder
public class CxConfig {

    private static final Pattern pattern = Pattern.compile("([^\"]\\S*|\".+?\")\\s*");
    private String agentName;    //JETBRAINS 
    private String baseUri;
    private String baseAuthUri;
    private String tenant;
    private String clientId;
    private String clientSecret;
    private String apiKey;
    private String pathToExecutable;
    @Setter(AccessLevel.NONE)
    private List<String> additionalParameters;

    public void setAdditionalParameters(String additionalParameters) {
        this.additionalParameters = parseAdditionalParameters(additionalParameters);
    }

    List<String> toArguments() {
        List<String> commands = new ArrayList<>();

        if (StringUtils.isNotBlank(getClientId()) && StringUtils.isNotBlank(getApiKey())) {
            /*
             * Added dynamic client-id support for refresh_token grant flow
             */
            commands.add(CxConstants.CLIENT_ID);
            commands.add(getClientId());
            commands.add(CxConstants.API_KEY);
            commands.add(getApiKey());
        } else if (StringUtils.isNotBlank(getApiKey())) {
            commands.add(CxConstants.API_KEY);
            commands.add(getApiKey());
        } else if (StringUtils.isNotBlank(getClientId()) && StringUtils.isNotBlank(getClientSecret())) {
            commands.add(CxConstants.CLIENT_ID);
            commands.add(getClientId());
            commands.add(CxConstants.CLIENT_SECRET);
            commands.add(getClientSecret());
        }

        if (StringUtils.isNotBlank(getTenant())) {
            commands.add(CxConstants.TENANT);
            commands.add(getTenant());
        }

        if (StringUtils.isNotBlank(getBaseUri())) {
            commands.add(CxConstants.BASE_URI);
            commands.add(getBaseUri());
        }

        if (StringUtils.isNotBlank(getBaseAuthUri())) {
            commands.add(CxConstants.BASE_AUTH_URI);
            commands.add(getBaseAuthUri());
        }
        if (getAgentName() != null && !getAgentName().isEmpty()) {
            commands.add("--agent");
            commands.add(getAgentName()); 
        }        
        if (getAdditionalParameters() != null)
            commands.addAll(getAdditionalParameters());

        return commands;
    }


    @SuppressWarnings("ALL")
    public static class CxConfigBuilder {

        public CxConfigBuilder additionalParameters(String additionalParameters) {
            this.additionalParameters = parseAdditionalParameters(additionalParameters);
            return this;
        }
    }

    static List<String> parseAdditionalParameters(String additionalParameters) {
        List<String> additionalParametersList = new ArrayList<>();
        if (StringUtils.isNotBlank(additionalParameters)) {
            Matcher m = pattern.matcher(additionalParameters);
            while (m.find()) {
                additionalParametersList.add(m.group(1).replaceAll("\"", ""));
            }
        }
        return additionalParametersList;
    }
}
