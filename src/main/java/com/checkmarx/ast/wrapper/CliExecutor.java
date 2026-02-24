package com.checkmarx.ast.wrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public class CliExecutor {

    public CommandResponse execute(CommandRequest req) {

        try {
            List<String> cmd = new CommandBuilder().build(req);

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);

            Process process = pb.start();
            String output = readProcessOutputAsString(process);

            int exitCode = process.waitFor();

            return new OutputParser().parse(output, exitCode);

        } catch (Exception e) {
            return new CommandResponse(
                    1,
                    false,
                    "",
                    null,
                    e.getMessage()
            );
        }

    }

    /**
     * Reads the output of the given process as a String.
     *
     * @param process The process whose output is to be read.
     * @return The process output as a String.
     * @throws IOException If an I/O error occurs while reading the process output.
     */
    private String readProcessOutputAsString(Process process) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = process.getInputStream().read(buffer)) != -1) {
            baos.write(buffer, 0, length);
        }
        return baos.toString("UTF-8");
    }

}
