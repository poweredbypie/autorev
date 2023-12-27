import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;

public class Util {
    public static ConstantPropagationAnalyzer getConstantAnalyzer(Program program) {
        // Thanks to astrelsky 
        // https://github.com/astrelsky/ghidra_scripts/blob/ac3caaf7762f59a72bfeef8e24cbc8d1eda00657/PrintfSigOverrider.java#L292-L317
        var manager = AutoAnalysisManager.getAnalysisManager(program);
        var analyzers = ClassSearcher.getInstances(ConstantPropagationAnalyzer.class);
        for (ConstantPropagationAnalyzer analyzer : analyzers) {
            if (analyzer.canAnalyze(program)) {
                return (ConstantPropagationAnalyzer) manager.getAnalyzer(analyzer.getName());
            }
        }
        return null;
    }
}
