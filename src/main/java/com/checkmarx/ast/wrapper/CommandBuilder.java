package com.checkmarx.ast.wrapper;

import java.util.ArrayList;
import java.util.List;

public class CommandBuilder {

    public List<String> build(CommandRequest req) {
        List<String> cmd = new ArrayList<>();

        cmd.add("mycli");                    // CLI binary name
        cmd.add(req.getCommand());          // e.g. "scan"

        cmd.addAll(req.getArguments());     // e.g. ["--path=/src"]

        req.getFlags().forEach((k, v) -> {
            cmd.add(k);
            if (v != null) cmd.add(v);
        });

        cmd.add("--json");                  // enforce machine output

        return cmd;
    }
}
