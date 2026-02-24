package com.checkmarx.ast.wrapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CommandRequest {

    private final String command;
    private final List<String> arguments;
    private final Map<String, String> flags;

    public CommandRequest(String command) {
        this.command = command;
        this.arguments = new ArrayList<>();
        this.flags = new HashMap<>();
    }

    public CommandRequest addArg(String arg) {
        this.arguments.add(arg);
        return this;
    }

    public CommandRequest addFlag(String key, String value) {
        this.flags.put(key, value);
        return this;
    }

    public String getCommand() {
        return command;
    }

    public List<String> getArguments() {
        return arguments;
    }

    public Map<String, String> getFlags() {
        return flags;
    }
}
