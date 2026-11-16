package burp.playbook;

import burp.Settings;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Loads the specialized agent playbooks: the bundled set shipped inside the jar
 * (src/main/resources/playbooks/*.md) plus, optionally, user-editable .md files
 * from an external directory that override/extend the bundled ones by id.
 *
 * A fat jar has no listable directory, so the bundled set is an explicit manifest.
 * Loaded once per site scan (a snapshot), so editing files mid-scan is harmless.
 *
 * @author Zahid Eroglu
 */
public class PlaybookLibrary {

    /** Bundled playbook ids (must match resource file stems under /playbooks/). */
    private static final String[] BUNDLED = {
            "access-control-idor",
            "business-logic",
            "auth-jwt",
            "bola-multisession",
            "multistep-chain",
            "mass-assignment"
    };

    private final LinkedHashMap<String, Playbook> byId = new LinkedHashMap<>();

    public static PlaybookLibrary load(Settings settings, PrintWriter stderr) {
        PlaybookLibrary lib = new PlaybookLibrary();

        // 1) Bundled (classpath)
        for (String stem : BUNDLED) {
            try (InputStream is = PlaybookLibrary.class.getResourceAsStream("/playbooks/" + stem + ".md")) {
                if (is != null) {
                    Playbook p = Playbook.parse(stem, readAll(is));
                    lib.byId.put(p.id, p);
                } else if (stderr != null) {
                    stderr.println("[Playbook] bundled resource missing: /playbooks/" + stem + ".md");
                }
            } catch (Exception e) {
                if (stderr != null) stderr.println("[Playbook] bundled " + stem + ": " + e.getMessage());
            }
        }

        // 2) External overrides (opt-in)
        if (settings != null && settings.isAgentLoadExternalPlaybooks()) {
            try {
                File dir = new File(settings.getAgentPlaybookDir());
                if (dir.isDirectory()) {
                    File[] files = dir.listFiles((d, n) -> n.toLowerCase().endsWith(".md"));
                    if (files != null) {
                        for (File f : files) {
                            try {
                                String raw = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
                                String stem = f.getName().replaceAll("(?i)\\.md$", "");
                                Playbook p = Playbook.parse(stem, raw);
                                lib.byId.put(p.id, p); // override or add by id
                            } catch (Exception e) {
                                if (stderr != null) stderr.println("[Playbook] external " + f.getName() + ": " + e.getMessage());
                            }
                        }
                    }
                } else if (stderr != null) {
                    stderr.println("[Playbook] external dir not found: " + dir.getAbsolutePath());
                }
            } catch (Exception e) {
                if (stderr != null) stderr.println("[Playbook] external dir error: " + e.getMessage());
            }
        }
        return lib;
    }

    public List<Playbook> all() {
        return new ArrayList<>(byId.values());
    }

    public Playbook byId(String id) {
        return byId.get(id);
    }

    public boolean isEmpty() {
        return byId.isEmpty();
    }

    public int size() {
        return byId.size();
    }

    private static String readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) >= 0) {
            bos.write(buf, 0, n);
        }
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }
}
