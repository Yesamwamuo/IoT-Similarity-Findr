import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.database.code.*;
import ghidra.program.database.ProgramDB;

import java.util.*;


import java.io.FileNotFoundException;
import java.io.PrintWriter;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;


public class ExtractFunction extends GhidraScript {
    private DecompInterface decomplib;

    /*public void addToJson(String callingFunction, String call) {
        JSONArray calls = jo.get(callingFunction);
        if(calls != null) {
            calls.add(call);
        }
    } */
    public HighFunction decompileFunction(Function f) {
        HighFunction hfunction = null;
        try {
            DecompileResults dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), getMonitor());
            hfunction = dRes.getHighFunction();
        } catch (Exception exc) {
            printf("EXCEPTION IN DECOMPILATION!\n");
            exc.printStackTrace();
        }
        return hfunction;
    }

    public JSONArray analyzeFunctionCallSite(Function callingFunction, PcodeOpAST callPCOp, Map<Varnode, Varnode> copyMap)
            throws InvalidInputException, NotYetImplementedException, NotFoundException, Exception {
        JSONArray arr = new JSONArray();

        if (callPCOp.getOpcode() != PcodeOp.CALL) {
            throw new InvalidInputException("PCodeOp that is not CALL passed in to function expecting CALL only");
        }
        Varnode calledFunc = callPCOp.getInput(0);
        if (calledFunc == null || !calledFunc.isAddress()) {
            println("call, but not address!");
            return arr;
        }
        Address pa = callPCOp.getSeqnum().getTarget();
        int numParams = callPCOp.getNumInputs();

        String calledFunctionName = getFunctionAt(calledFunc.getAddress()).getName();
        arr.add(calledFunctionName);

//        printf("\nCall @ 0x%x [%s] to 0x%x [%s] (%d pcodeops)\n",
//            pa.getOffset(),
//            callingFunction.getName(),
//            calledFunc.getAddress().getOffset(),
//            calledFunctionName,
//            numParams);

        for (int i = 1; i < numParams; i++) {
            Varnode varParam = callPCOp.getInput(i);
            if (varParam == null) {
                continue;
            }
            if (varParam.isConstant()) {
                long value = varParam.getOffset();
                arr.add(String.valueOf(value));
            } else { // else if (varParam.isUnique())?
                arr.add(getValue(copyMap.get(varParam)));
            }
        }
        return arr;
    }


    public String getValue(Varnode vn) {

        if (vn != null) {
            Address offset = vn.getAddress(); // getoffset
            try {
                Address ram_addr = getAddressFactory().getAddress(String.format("ram:%x", offset.getOffset()));
                byte[] null_byte = new byte[0];
                Data stuff = getCurrentProgram().getListing().getDefinedDataAt(ram_addr);
                if (stuff != null)
                    return StringDataInstance.getStringDataInstance(stuff).getStringValue();
            } catch (Exception ex) {//MemoryAccessException ex){
                println(ex.getMessage());
                return "param";
            }
        }

        return "param";
    }


    public FunctionStats getFunctionCallSitePCodeOps(Function f) {
        ArrayList<PcodeOpAST> pcodeOpCallSites = new ArrayList<PcodeOpAST>();
        Map<Varnode, Varnode> copyMap = new HashMap<>();
        HighFunction hfunction = decompileFunction(f);
        if (hfunction == null) {
            printf("ERROR: Failed to decompile function!\n");
            return null;
        }
        Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();
        //iterate over all p-code ops in the function
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();
            if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {
                //current p-code op is a CALL
                //get the address CALL-ed
                Varnode calledVarnode = pcodeOpAST.getInput(0);
                if (calledVarnode == null || !calledVarnode.isAddress()) {
                    printf("ERROR: call, but not to address!");
                    continue;
                }
                println(pcodeOpAST.toString());
                pcodeOpCallSites.add(pcodeOpAST);
            } else if (pcodeOpAST.getOpcode() == PcodeOp.COPY) {

                copyMap.put(pcodeOpAST.getOutput(), pcodeOpAST.getInput(0));

            }
        }

        return new FunctionStats(pcodeOpCallSites, copyMap);
    }

    private DecompInterface setUpDecompiler(Program program) {
        DecompInterface decompInterface = new DecompInterface();
        DecompileOptions options;
        options = new DecompileOptions();
        PluginTool tool = state.getTool();
        if (tool != null) {
            OptionsService service = tool.getService(OptionsService.class);
            if (service != null) {
                ToolOptions opt = service.getOptions("Decompiler");
                options.grabFromToolAndProgram(null, opt, program);
            }
        }
        decompInterface.setOptions(options);
        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");
        return decompInterface;
    }

    public void run() throws Exception {
        decomplib = setUpDecompiler(currentProgram);
        if (!decomplib.openProgram(currentProgram)) {
            printf("Decompiler error: %s\n", decomplib.getLastMessage());
            return;
        }
        JSONObject jo = new JSONObject();
        Memory memory = currentProgram.getMemory();
        FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
        for (Function function : functionManager) {
            JSONArray arr = new JSONArray();
            FunctionStats funcStat = getFunctionCallSitePCodeOps(function);
            ArrayList<PcodeOpAST> callSites = funcStat.getPcodeOpCallSites();
            if (callSites != null) {
                println(function.getName() + " Called " + callSites.size() + " fuctions");
            }
            for (PcodeOpAST callSite : callSites) {
                arr.add(analyzeFunctionCallSite(function, callSite, funcStat.getCopyMap()));
            }
            jo.put(function.getName(), arr);
        }
        PrintWriter pw = new PrintWriter("device_functions.json");
        pw.write(jo.toJSONString());

        pw.flush();
        pw.close();
    }
}