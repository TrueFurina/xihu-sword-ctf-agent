// Batch-export decompiled C for every function in the current program.
//
// Why this exists: REA's `decompile --procedure <one>` pays a full Ghidra/JVM
// cold start (~40s) per function. That makes "decompile 20 functions" cost 13+
// minutes. analyzeHeadless can import + analyze + run this script once and emit
// every function in a single JVM lifetime, so the 40s is paid once, not N times.
//
// Usage (from analyzeHeadless):
//   -postScript ExportAllDecompiled.java <outFile> [maxFuncs] [nameSubstring]
//
// Args:
//   outFile        absolute path for the combined C output
//   maxFuncs      0 or omitted = no cap; otherwise stop after N functions
//   nameSubstring only export functions whose name contains this (case-insensitive)
//
// Output layout is deliberately greppable:
//   // ==== FUNC <entryVA> <name> size=<bytes> ====
//   <C body>

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportAllDecompiled extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: need outFile argument");
            return;
        }
        String outPath = args[0];
        int maxFuncs = 0;
        if (args.length >= 2) {
            try {
                maxFuncs = Integer.parseInt(args[1].trim());
            } catch (NumberFormatException e) {
                maxFuncs = 0;
            }
        }
        String filter = args.length >= 3 ? args[2].trim().toLowerCase() : "";
        // "*" is the explicit "no filter" placeholder: passing a truly empty
        // string through cmd.exe can collapse the argument and shift maxFuncs.
        if (filter.equals("*")) {
            filter = "";
        }
        // Multi-word OR filter (2026-10-21): the LLM naturally passes
        // "add_char_to_map,serialize_and_output,main,list_len" (comma-joined
        // names copied from the elf-lane hint). Plain substring matching on
        // the whole string matches nothing -> zero candidates -> the full
        // ~90s Ghidra analysis is burned for an empty result. Split on
        // comma/whitespace and treat the parts as OR terms.
        String[] filterTerms = filter.isEmpty() ? new String[0]
                : filter.split("[,\\s;|]+");

        DecompInterface ifc = new DecompInterface();
        // "decompile" is the normal style; "normalize" is faster but loses types.
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            println("ERROR: DecompInterface.openProgram failed: " + ifc.getLastMessage());
            return;
        }

        int seen = 0;
        int emitted = 0;
        int failed = 0;
        int skipped = 0;
        long t0 = System.currentTimeMillis();

        PrintWriter pw = new PrintWriter(new File(outPath), "UTF-8");
        try {
            pw.println("// program: " + currentProgram.getName());
            pw.println("// lang: " + currentProgram.getLanguageID());
            pw.println("// imageBase: " + currentProgram.getImageBase());

            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }
                Function f = it.next();

                // Thunks and externals carry no real body; exporting them just
                // adds noise that pushes real function bodies out of grep range.
                if (f.isThunk() || f.isExternal()) {
                    skipped++;
                    continue;
                }
                if (filterTerms.length > 0) {
                    String fname = f.getName().toLowerCase();
                    boolean any = false;
                    for (String term : filterTerms) {
                        if (!term.isEmpty() && fname.contains(term)) {
                            any = true;
                            break;
                        }
                    }
                    if (!any) {
                        skipped++;
                        continue;
                    }
                }

                seen++;
                DecompileResults res = ifc.decompileFunction(f, 60, monitor);
                if (res == null || !res.decompileCompleted()) {
                    failed++;
                    pw.println("// ==== FUNC " + f.getEntryPoint() + " " + f.getName()
                            + " FAILED: "
                            + (res == null ? "null result" : res.getErrorMessage()) + " ====");
                    continue;
                }
                pw.println("// ==== FUNC " + f.getEntryPoint() + " " + f.getName()
                        + " size=" + f.getBody().getNumAddresses() + " ====");
                pw.println(res.getDecompiledFunction().getC());
                emitted++;

                if (maxFuncs > 0 && emitted >= maxFuncs) {
                    break;
                }
            }
        } finally {
            pw.flush();
            pw.close();
            ifc.dispose();
        }

        long ms = System.currentTimeMillis() - t0;
        println("EXPORT_DONE out=" + outPath
                + " emitted=" + emitted
                + " failed=" + failed
                + " skipped=" + skipped
                + " candidates=" + seen
                + " elapsed_ms=" + ms);
    }
}
