import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.Map;

public class FunctionStats {
    private ArrayList<PcodeOpAST> pcodeOpCallSites ;
    private Map<Varnode, Varnode> copyMap;

    public FunctionStats(ArrayList<PcodeOpAST> pcodeOpCallSites, Map<Varnode, Varnode> copyMap) {
        this.pcodeOpCallSites = pcodeOpCallSites;
        this.copyMap = copyMap;
    }

    public ArrayList<PcodeOpAST> getPcodeOpCallSites() {
        return pcodeOpCallSites;
    }

    public Map<Varnode, Varnode> getCopyMap() {
        return copyMap;
    }
}
