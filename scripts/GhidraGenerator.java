import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.annotations.SerializedName;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

enum PlatformProvider {
    Windows(new Builder().setProcessor("x86")
            .setABISignature("QueryPerformanceCounter")
            .setPureVirtual("_purecall")
            .setVtableSymbol("vftable")
            .setReadOnlySection(".rdata")),
    AndroidArm32(new Builder().setProcessor("ARM")
            .setABISignature("__android_log_print")
            .setPureVirtual("__cxa_pure_virtual")
            .setVtableSymbol("vtable")
            .setReadOnlySection(".rodata"));

    // This is kind of unnecessary but it's kind of unreadable otherwise
    private static class Builder {
        String processor;
        String abiSignature;
        String pureVirtual;
        String vtableSymbol;
        String readOnlySection;

        public Builder setProcessor(String processor) {
            this.processor = processor;
            return this;
        }

        public Builder setABISignature(String abiSignature) {
            this.abiSignature = abiSignature;
            return this;
        }

        public Builder setPureVirtual(String pureVirtual) {
            this.pureVirtual = pureVirtual;
            return this;
        }

        public Builder setVtableSymbol(String vtableSymbol) {
            this.vtableSymbol = vtableSymbol;
            return this;
        }

        public Builder setReadOnlySection(String readOnlySection) {
            this.readOnlySection = readOnlySection;
            return this;
        }
    };

    private String processor;
    private String abiSignature;
    private String pureVirtual;
    private String vtableSymbol;
    private String readOnlySection;

    PlatformProvider(Builder builder) {
        this.processor = builder.processor;
        this.abiSignature = builder.abiSignature;
        this.pureVirtual = builder.pureVirtual;
        this.vtableSymbol = builder.vtableSymbol;
        this.readOnlySection = builder.readOnlySection;
    }

    // Make sure the program matches our current platform
    private void validate(Program program) throws IllegalArgumentException {
        // Not validating program's processor ID because this should be handled already
        var syms = program.getSymbolTable();
        if (!syms.getSymbols(this.abiSignature).hasNext()) {
            throw new IllegalArgumentException(
                "Program does not contain ABI signature for platform (%s)"
                        .formatted(this.abiSignature));
        }
        if (!syms.getSymbols(this.pureVirtual).hasNext()) {
            throw new IllegalArgumentException(
                "Program does not contain pure virtual symbol for platform (%s)"
                        .formatted(this.pureVirtual));
        }
        if (program.getMemory().getBlock(this.readOnlySection) == null) {
            throw new IllegalArgumentException(
                "Program does not contain read only section for platform (%s)"
                        .formatted(this.readOnlySection));
        }
    }

    // Actual providers
    public SymbolIterator getVirtualTables(Program program) {
        return program.getSymbolTable().getSymbols(this.vtableSymbol);
    }

    public MemoryBlock getReadonlyBlock(Memory memory) {
        return memory.getBlock(this.readOnlySection);
    }

    private static PlatformProvider valueFromProcessor(String processor)
            throws IllegalArgumentException {
        var values = PlatformProvider.class.getEnumConstants();
        for (var value : values) {
            if (value.processor.contains(processor)) {
                return value;
            }
        }

        throw new IllegalArgumentException(
            "No platform matches processor provided (%s)".formatted(processor));
    }

    public static PlatformProvider valueOf(Program program) throws IllegalArgumentException {
        var pointerSize = program.getDefaultPointerSize();
        if (pointerSize != 4) {
            throw new IllegalArgumentException(
                "None of the platform providers support pointer size %s".formatted(pointerSize));
        }

        var langDesc = program.getLanguage().getLanguageDescription();
        // Get platform from processor name
        var platform = valueFromProcessor(langDesc.getProcessor().toString());
        platform.validate(program);

        return platform;
    }
}

class DestDump {
    enum Type {
        Known,
        Unknown
    }

    public Type type;
    long call;

    private DestDump(Type type, long call) {
        this.type = type;
        this.call = call;
    }

    static DestDump unknown() {
        return new DestDump(Type.Unknown, 0);
    }

    static DestDump known(Address addr) {
        return new DestDump(Type.Known, addr.getOffset());
    }
}

// To force serialization to match serde_json's default
class DestDumpSerializer implements JsonSerializer<DestDump> {
    private String shortName(DestDump value) {
        return String.valueOf(value.type.name().charAt(0));
    }

    @Override
    public JsonElement serialize(DestDump value, Type type, JsonSerializationContext context) {
        switch (value.type) {
            // serde_json encodes a variant type with a map of enum name to value
            case Known:
                var outer = new JsonObject();
                outer.add(shortName(value), new JsonPrimitive(value.call));
                return outer;
            // serde_json uses a string tag for monostate enum types
            default:
                return new JsonPrimitive(shortName(value));
        }
    }
}

class BranchDump {
    enum Type {
        Return,
        Neutral,
        Equality,
        Inequality
    }

    public Type type;
    public List<DestDump> dests;

    private BranchDump(Type type, DestDump... dests) {
        this.type = type;
        this.dests = List.of(dests);
    }

    public static BranchDump inequality(DestDump first, DestDump second) {
        return new BranchDump(Type.Inequality, first, second);
    }

    public static BranchDump equality(DestDump first, DestDump second) {
        return new BranchDump(Type.Equality, first, second);
    }

    public static BranchDump neutral(DestDump dest) {
        return new BranchDump(Type.Neutral, dest);
    }

    public static BranchDump returns() {
        return new BranchDump(Type.Return);
    }

    private static DestDump fallthruFor(Instruction inst) throws IllegalArgumentException {
        var fallthru = inst.getFallThrough();
        if (fallthru == null) {
            // Just get the instruction following this one
            var next = inst.getNext();
            if (next == null) {
                throw new IllegalArgumentException(
                    "No fallthrough or proceeding instruction %s at offset %s"
                            .formatted(inst, inst.getAddress()));
            }
            else {
                return DestDump.known(next.getAddress());
            }
        }
        else {
            return DestDump.known(fallthru);
        }
    }

    private static DestDump jumpFor(Instruction inst) throws IllegalArgumentException {
        var flows = inst.getFlows();
        if (flows == null || flows.length < 1) {
            // Dunno where it's going to
            return DestDump.unknown();
        }
        else {
            return DestDump.known(flows[0]);
        }
    }

    public static BranchDump branchForInst(Instruction inst) throws IllegalArgumentException {
        var flow = inst.getFlowType();

        // Process instructions with no fallthrough
        if (flow.isTerminal() && !flow.isCall()) {
            return BranchDump.returns();
        }
        else if (flow.isJump() || flow.isCall()) {
            var jump = jumpFor(inst);
            if (flow.isUnConditional()) {
                return BranchDump.neutral(jump);
            }
            else {
                // Conditional so find fallthrough
                // TODO: Inequality enum is not used at all
                return BranchDump.equality(jump, fallthruFor(inst));
            }
        }
        else {
            // Probably not a branch instruction so just fallthrough
            return BranchDump.neutral(fallthruFor(inst));
        }
    }

    public static BranchDump branchForBlock(Program program, CodeBlock block)
            throws IllegalArgumentException {
        var end = block.getMaxAddress();
        var inst = program.getListing().getInstructionContaining(end);
        if (inst == null) {
            throw new IllegalArgumentException("No instruction at end of codeblock");
        }

        return BranchDump.branchForInst(inst);
    }
}

class BranchDumpSerializer implements JsonSerializer<BranchDump> {
    private String shortName(BranchDump value) {
        return String.valueOf(value.type.name().charAt(0));
    }

    private JsonElement getOuterElement(BranchDump value, JsonElement inner) {
        var outer = new JsonObject();
        outer.add(shortName(value), inner);
        return outer;
    }

    @Override
    public JsonElement serialize(BranchDump value, Type type, JsonSerializationContext context) {
        switch (value.type) {
            case Neutral:
                // Only one destination (if I didn't fuck up the init code) so just serialize the first
                return this.getOuterElement(value, context.serialize(value.dests.get(0)));
            case Equality, Inequality:
                // Tuple variants are encoded as an array
                return this.getOuterElement(value, context.serialize(value.dests));
            // serde_json uses a string tag for monostate enum types
            default:
                return new JsonPrimitive(shortName(value));
        }
    }
}

class AddressDump {
    @SerializedName("A")
    public long address;
    @SerializedName("B")
    public long blockAddr;
    @SerializedName("F")
    public long functionAddr;

    private static long offsetFor(Address address) {
        return address != null ? address.getOffset() : 0;
    }

    public AddressDump(Address address, Address blockAddr, Address functionAddr) {
        this.address = offsetFor(address);
        this.blockAddr = offsetFor(blockAddr);
        this.functionAddr = offsetFor(functionAddr);
    }
}

class StringDump {
    @SerializedName("S")
    public String string;
    @SerializedName("X")
    public List<AddressDump> xrefs;

    public StringDump(String string, List<AddressDump> xrefs) {
        this.string = string;
        this.xrefs = xrefs;
    }
}

class BlockDump {
    @SerializedName("A")
    public AddressDump address;
    @SerializedName("C")
    public List<DestDump> calls;
    @SerializedName("B")
    public BranchDump branch;
    @SerializedName("S")
    public List<String> strings;

    public BlockDump(AddressDump address, List<DestDump> calls, BranchDump branch,
            List<String> strings) {
        this.address = address;
        this.calls = calls;
        this.branch = branch;
        this.strings = strings;
    }
}

class FunctionDump {
    @SerializedName("N")
    public String name;
    @SerializedName("A")
    public AddressDump address;
    @SerializedName("B")
    public List<BlockDump> blocks;
    @SerializedName("X")
    public List<AddressDump> xrefs;

    public FunctionDump(String name, AddressDump address, List<BlockDump> blocks,
            List<AddressDump> xrefs) {
        this.name = name;
        this.address = address;
        this.blocks = blocks;
        this.xrefs = xrefs;
    }
}

class VtableDump {
    @SerializedName("N")
    public String name;
    @SerializedName("A")
    public long address;
    @SerializedName("F")
    public List<Long> functions;

    private VtableDump(String name, long address, List<Long> functions) {
        this.name = name;
        this.address = address;
        this.functions = functions;
    }

    public static List<Long> functionsFromAddress(Address address, SymbolTable syms, Memory memory)
            throws IllegalArgumentException, MemoryAccessException {
        // Pointer to RTTI
        var ptrSize = address.getPointerSize();
        var offset = memory.getInt(address);
        if (offset > 0) {
            throw new IllegalArgumentException("Offset from base of class is negative");
        }

        var rtti = address.getNewAddress(memory.getInt(address.add(1 * ptrSize)));
        var rttiSym = syms.getPrimarySymbol(rtti);
        if (rttiSym == null) {
            throw new IllegalArgumentException("No RTTI symbol for vtable symbol passed");
        }

        // vtable starts 2 down
        var funcs = new ArrayList<Long>();
        var execBlock = memory.getExecuteSet();
        var funcIter = address.add(2 * ptrSize);
        while (true) {
            var addr = address.getNewAddress(memory.getInt(funcIter));
            if (!execBlock.contains(addr)) {
                // Non executable pointer so we stop
                break;
            }
            var func = memory.getProgram().getFunctionManager().getFunctionContaining(addr);
            if (func != null) {
                // Use the function's start address
                addr = func.getEntryPoint();
            }
            funcs.add(addr.getOffset());
            funcIter = funcIter.add(1 * ptrSize);
        }
        return funcs;
    }

    public static VtableDump vtableForSymbol(Symbol symbol, TaskMonitor monitor)
            throws IllegalArgumentException, MemoryAccessException, CancelledException {
        var program = symbol.getProgram();
        var memory = program.getMemory();
        var syms = program.getSymbolTable();
        var addr = symbol.getAddress();
        var ptrSize = addr.getPointerSize();

        var rtti =
            syms.getPrimarySymbol(addr.getNewAddress(memory.getInt(addr.add(1 * ptrSize))));
        if (rtti == null) {
            throw new IllegalArgumentException("No RTTI object for vtable passed");
        }
        var className = rtti.getParentNamespace().getName(true);

        var funcs = new ArrayList<Long>();
        try {
            while (true) {
                if (monitor.isCancelled()) {
                    // Break early if the task monitor is cancelled
                    break;
                }
                var funcsPart = functionsFromAddress(addr, syms, memory);
                funcs.addAll(funcsPart);
                // Move on to the next one
                addr = addr.add((funcsPart.size() + 2) * ptrSize);
            }
        }
        catch (Exception e) {
            // Reached the end of the vtables we can process
        }
        return new VtableDump(className, addr.getOffset(), funcs);
    }
}

class Dump {
    @SerializedName("F")
    public Map<Long, FunctionDump> funcs;
    @SerializedName("V")
    public Map<String, VtableDump> vtables;
    @SerializedName("S")
    public Map<String, StringDump> strings;
}

public class GhidraGenerator extends GhidraScript {
    private BasicBlockModel blockModel;
    private SymbolTable symbolTable;
    private PlatformProvider platformProvider;

    private static <T> Stream<T> streamFromIter(Iterable<T> iter) {
        return StreamSupport.stream(iter.spliterator(), false);
    }

    // Get dump for all strings in the program
    // Does NOT populate xrefs.
    private Map<Long, StringDump> allStrings() {
        var memory = this.currentProgram.getMemory();
        var rdata = this.platformProvider.getReadonlyBlock(memory);
        var strings = this.findStrings(new AddressSet(rdata.getAddressRange()), 5, 1, true, false);
        return strings
                .stream()
                .collect(Collectors.toMap(
                    str -> str.getAddress().getOffset(),
                    str -> new StringDump(str.getString(memory), new ArrayList<>())));
    }

    // Wrapper because stupid cancelled exception I don't want to handle
    private CodeBlock getCodeBlockContaining(Address addr, TaskMonitor monitor) {
        try {
            return this.blockModel.getFirstCodeBlockContaining(addr, monitor);
        }
        catch (CancelledException e) {
            return null;
        }
    }

    private List<AddressDump> getCallers(Function func) {
        var refManager = this.currentProgram.getReferenceManager();
        var funcManager = this.currentProgram.getFunctionManager();

        return streamFromIter(refManager.getReferencesTo(func.getEntryPoint()))
                .map(ref -> {
                    var to = ref.getFromAddress();
                    var block = this.getCodeBlockContaining(to, monitor);
                    if (block == null) {
                        // Any xref that does not have a corresponding block should be ignored
                        return null;
                    }
                    var blockAddr = block.getMinAddress();
                    if (blockAddr == null) {
                        // I don't even know how this can happen? Why would there be an empty code block?
                        return null;
                    }
                    var parent = funcManager.getFunctionContaining(to);
                    // It's ok if the parent function is null according to symbo's gen code so we'll accept it too
                    return new AddressDump(to, blockAddr,
                        parent == null ? null : parent.getEntryPoint());
                })
                .filter(Objects::nonNull)
                .toList();
    }

    // Returns the function offset containing the address or 0 if a function isn't found
    private Address getFunctionOffsetFor(Address addr) {
        var func = this.currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (func == null) {
            return null;
        }
        else {
            return func.getEntryPoint();
        }
    }

    // Get dump for all functions in the program
    private Map<Long, FunctionDump> allFunctionDumps(Map<Long, StringDump> stringMap,
            TaskMonitor monitor) {
        var funcIter =
            this.currentProgram.getFunctionManager().getFunctions(true);
        return streamFromIter(funcIter)
                .takeWhile(ignore -> !monitor.isCancelled())
                .map(func -> {
                    var addr = func.getEntryPoint();
                    return new FunctionDump(
                        func.getName(true),
                        new AddressDump(addr, addr, addr),
                        this.blockDumpsFor(func, stringMap, monitor),
                        this.getCallers(func));
                })
                .collect(Collectors.toMap(
                    dump -> Long.valueOf(dump.address.address),
                    dump -> dump));
    }

    private List<DestDump> callsFor(CodeBlock block) {
        var refManager = this.currentProgram.getReferenceManager();
        var funcManager = this.currentProgram.getFunctionManager();
        // var execBlock = this.currentProgram.getMemory().getExecuteSet();

        // Get all referenced addresses in the block
        // Create a dump for them. If they reference a valid function return the offset,
        // otherwise return an unknown dest.
        // Ignore the last instruction in the block. We process that when checking the branch dump
        var listing = this.currentProgram.getListing();
        var lastInst = listing.getInstructionContaining(block.getMaxAddress());
        var iter = AddressSetView.trimEnd(block, lastInst.getAddress());
        return streamFromIter(iter.getAddresses(true))
                .flatMap(addr -> Stream.of(refManager.getReferencesFrom(addr)))
                .filter(Objects::nonNull)
                .map(ref -> {
                    var to = ref.getToAddress();
                    var called = funcManager.getFunctionAt(to);
                    if (called == null) {
                        return null;
                        /* TODO: ARM has a lot of small data bits that are located in the executable section
                           So it's really annoying to detect what a function call is here
                           Instead for now I'm just going to ignore it if the location is not a defined function
                        if (execBlock.contains(to)) {
                            return DestDump.known(to);
                        }
                        else {
                            // This isn't a reference to executable memory so it's not a function call, ignore
                            return null;
                        }
                        */
                    }
                    else {
                        return DestDump.known(to);
                    }
                })
                .filter(Objects::nonNull)
                .toList();
    }

    private Stream<StringDump> stringsFor(CodeBlock block, Map<Long, StringDump> stringMap) {
        // Get each address in the block, find references in them, then see if the reference is a string dump
        // If the reference is a string dump, add it to the list
        var refManager = this.currentProgram.getReferenceManager();
        return streamFromIter(block.getAddresses(true))
                .flatMap(addr -> Stream.of(refManager.getReferencesFrom(addr)))
                .filter(Objects::nonNull)
                .map(ref -> stringMap.get(ref.getToAddress().getOffset()))
                .filter(Objects::nonNull);
    }

    // Wrapper because stupid exception I don't want to handle
    private Stream<CodeBlock> codeBlocksFor(Function func, TaskMonitor monitor) {
        try {
            return streamFromIter(
                this.blockModel.getCodeBlocksContaining(func.getBody(), monitor));
        }
        catch (CancelledException c) {
            return Stream.of();
        }
    }

    // Finds basic control flow blocks in each function and creates dumps for them
    private List<BlockDump> blockDumpsFor(Function func, Map<Long, StringDump> stringMap,
            TaskMonitor monitor) {
        // Taken directly from:
        // https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionGraph/src/main/java/ghidra/app/plugin/core/functiongraph/graph/FunctionGraphFactory.java#L307
        var funcAddr = func.getEntryPoint();

        return this.codeBlocksFor(func, monitor)
                .takeWhile(ignore -> !monitor.isCancelled())
                .map(block -> {
                    var startAddr = block.getMinAddress();
                    var addrDump = new AddressDump(startAddr, startAddr, funcAddr);
                    var strings = this.stringsFor(block, stringMap).map(string -> {
                        // Add ourselves to the string's xrefs
                        string.xrefs.add(addrDump);
                        // Only return the actual string value (weird Symbo format thing)
                        return string.string;
                    }).toList();

                    try {
                        return new BlockDump(
                            addrDump,
                            this.callsFor(block),
                            BranchDump.branchForBlock(this.currentProgram, block),
                            // Get the actual string value for each string dump
                            strings);
                    }
                    catch (Exception e) {
                        this.printf("Failed to process block at offset %s: %s\n",
                            block.getMinAddress(), e);
                        // This is annoying fuck you
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toList();
    }

    // Get all symbols the binary exports
    private List<Symbol> allExports() {
        // Taken directly from:
        // https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/symboltree/nodes/ExportsCategoryNode.java
        var externs = this.symbolTable.getExternalEntryPointIterator();
        return streamFromIter(externs)
                .flatMap(addr -> Stream.of(this.symbolTable.getSymbols(addr)))
                // Only keep C++ mangled symbols
                .filter(sym -> sym.getName().startsWith("_Z"))
                .toList();
    }

    private Map<String, VtableDump> allVtableDumps(TaskMonitor monitor) {
        var tables = this.platformProvider.getVirtualTables(this.currentProgram);
        return streamFromIter(tables)
                .takeWhile(ignore -> !monitor.isCancelled())
                .map(symbol -> {
                    try {
                        return VtableDump.vtableForSymbol(symbol, monitor);
                    }
                    catch (Exception e) {
                        this.printf("Couldn't get vtable for symbol: %s\n", e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(vtable -> vtable.name, vtable -> vtable));
    }

    @Override
    public void run() throws CancelledException, FileNotFoundException, IOException {
        // Init members
        this.platformProvider = PlatformProvider.valueOf(this.currentProgram);
        this.blockModel = new BasicBlockModel(this.currentProgram);
        this.symbolTable = this.currentProgram.getSymbolTable();

        var dump = new Dump();
        var strings = this.allStrings();

        this.println("Processing virtual tables");
        dump.vtables = this.allVtableDumps(this.monitor);

        this.println("Processing functions");
        dump.funcs = this.allFunctionDumps(strings, this.monitor);

        this.println("Processing string table");
        dump.strings = strings.values()
                .stream()
                .collect(
                    Collectors.toMap(
                        str -> str.string,
                        str -> str,
                        (first, second) -> {
                            // Merge xrefs
                            first.xrefs =
                                Stream.concat(first.xrefs.stream(), second.xrefs.stream()).toList();
                            return first;
                        }));

        var gson = new GsonBuilder()
                .registerTypeAdapter(DestDump.class, new DestDumpSerializer())
                .registerTypeAdapter(BranchDump.class, new BranchDumpSerializer())
                .setPrettyPrinting()
                .create();
        var json = gson.toJson(dump);

        var path = this.askFile("Output dump location", "OK");
        try (var file = new FileOutputStream(path)) {
            file.write(json.getBytes());
        }
    }
}