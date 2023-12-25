import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.task.TimeoutTaskMonitor;

public class MakeVTables extends GhidraScript {
    private final static String VTABLE_SYMBOL = "vtable";
    private final static int POINTER_SIZE = 4;

    class VTable {
        private Address address;
        public ArrayList<Function> entries;
        public HashSet<Function> refs;
        public int size;
        public int offset;

        private int getStructOffset() throws IllegalArgumentException, MemoryAccessException {
            var offset = getInt(this.address);
            if (offset > 0) {
                throw new IllegalArgumentException(
                    "Struct offset for %s is positive (0x%x)".formatted(this.address,
                        offset));
            }
            return offset;
        }

        private int getTypeInfo() throws MemoryAccessException {
            return getInt(this.address.addWrap(POINTER_SIZE));
        }

        private ArrayList<Function> getEntries() throws MemoryAccessException {
            // Get all entries in the vtable
            var space = this.address.getAddressSpace();
            // Get the span of addresses that are executable
            var execSpan = currentProgram.getMemory().getExecuteSet();
            // Actual vtable starts 2 slots down
            var iter = address.addWrap(2 * POINTER_SIZE);
            var entries = new ArrayList<Function>();
            while (true) {
                // For some reason the functions are all offset by 1? Not sure why
                var addr = space.getAddress(getInt(iter) - 1);
                if (!execSpan.contains(addr)) {
                    // We hit non-executable memory so this probably means the end of the vtable
                    break;
                }
                var func = getFunctionContaining(space.getAddress(getInt(iter)));
                if (func == null) {
                    // Create the function at the location because all vtables entries are functions
                    createFunction(addr, null);
                }
                else {
                    entries.add(func);
                }
                iter = iter.addWrap(POINTER_SIZE);
            }

            return entries;
        }

        private HashSet<Function> getRefs() {
            // Get references to the start of the actual vtable
            var refs = getReferencesTo(this.address.addWrap(2 * POINTER_SIZE));

            // Filter out references that are destructors
            var funcs = new HashSet<Function>();
            for (var ref : refs) {
                // Get the address that references the vtable start
                var from = ref.getFromAddress();
                var func = getFunctionContaining(from);

                // Skip either references that aren't in functions or are dtors
                if (func == null || func.getName().contains("~")) {
                    continue;
                }

                funcs.add(func);
            }

            return funcs;
        }

        VTable(Address address, long typeInfo)
                throws IllegalArgumentException, MemoryAccessException {
            this.address = address;

            // Validate parameters
            this.offset = this.getStructOffset();
            var checkedTypeInfo = this.getTypeInfo();
            if (checkedTypeInfo != typeInfo) {
                throw new IllegalArgumentException(
                    "Type info does not match type info passed (0x%x vs. 0x%x)".formatted(
                        checkedTypeInfo, typeInfo));
            }

            // Get entries
            this.entries = this.getEntries();
            this.size = (this.entries.size() + 2) * POINTER_SIZE;

            // Get xrefs
            this.refs = this.getRefs();
        }

        public void dump(FileOutputStream stream) throws IOException {
            stream.write("\tVTable at offset %s:\n".formatted(this.address).getBytes());
            stream.write(
                "\t\tVTable with size %d, struct offset %d:\n".formatted(this.size, this.offset)
                        .getBytes());
            for (var entry : this.entries) {
                stream.write("\t\t\t%s\n".formatted(
                    entry.getSignature().getPrototypeString(true)).getBytes());
            }
            stream.write("\t\tReferences:\n".getBytes());
            for (var ref : this.refs) {
                stream.write(
                    "\t\t\t%s\n".formatted(ref.getSignature().getPrototypeString(true)).getBytes());
            }
            stream.write('\n');
        }
    }

    class ClassSymbol {
        private final static String INVALID_SYMBOL = "The virtual table symbol passed was invalid";

        private long typeInfo;
        private Symbol symbol;
        public String namespace;
        public String name;
        public ArrayList<VTable> vtables;
        public long size;

        private ArrayList<VTable> getVTables() {
            var vtables = new ArrayList<VTable>();
            var iter = this.symbol.getAddress();
            while (true) {
                try {
                    var vtable = new VTable(iter, this.typeInfo);
                    vtables.add(vtable);
                    // printf("Adding vtable at %s with size %d\n".formatted(iter, vtable.size));
                    iter = iter.addWrap(vtable.size);
                }
                catch (Exception e) {
                    // This is fine we just exit when an exception happens
                    // printf("Got exception: %s\n", e);
                    break;
                }
            }
            return vtables;
        }

        private long getTypeInfo() throws IllegalArgumentException, MemoryAccessException {
            var offset = getInt(symbol.getAddress().add(POINTER_SIZE));
            var space = this.symbol.getAddress().getAddressSpace();
            var address = space.getAddress(offset);
            var symbol = this.symbol.getProgram().getSymbolTable().getPrimarySymbol(address);
            if (symbol == null) {
                throw new IllegalArgumentException(INVALID_SYMBOL);
            }
            return offset;
        }

        private ConstantPropagationAnalyzer getConstantAnalyzer(Program program) {
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

        private Address findAllocCallFor(Function func, TaskMonitor monitor)
                throws CancelledException {
            // Kind of stolen from FunctionDB.getReferencesFromBody
            var body = func.getBody();
            var manager = func.getProgram().getReferenceManager();

            for (var addr : body.getAddresses(true)) {
                if (monitor.isCancelled()) {
                    throw new CancelledException("Task cancelled while finding alloc calls");
                }

                var refs = manager.getReferencesFrom(addr);
                if (refs == null) {
                    continue;
                }

                for (var ref : refs) {
                    var called = getFunctionAt(ref.getToAddress());
                    if (called == null) {
                        continue;
                    }

                    // We found a call to operator new
                    if (called.getName().contains("operator.new")) {
                        return ref.getFromAddress();
                    }
                }
            }

            return null;
        }

        private boolean sameClass(Function func) {
            var name = func.getParentNamespace().getName(true);
            if (this.namespace.equals("")) {
                return name.equals(this.name);
            }
            else {
                return name.equals("%s::%s".formatted(this.namespace, this.name));
            }
        }

        // Returns null if not found
        private Address findAllocCall(TaskMonitor monitor)
                throws IllegalArgumentException, CancelledException {
            var allRefs = new HashSet<Function>();
            // Union all functions in each vtable's references
            for (var vtable : this.vtables) {
                allRefs.addAll(vtable.refs);
            }
            // Intersect all functions in each vtable's references
            for (var vtable : this.vtables) {
                allRefs.retainAll(vtable.refs);
            }
            // Loop through all the references
            var toLog = "Processing class %s::%s:\n".formatted(this.namespace, this.name);
            for (var ref : allRefs) {
                if (monitor.isCancelled()) {
                    throw new CancelledException(
                        "Task cancelled while looping through find alloc calls");
                }
                // Don't process refs that don't exist in the same namespace
                if (!this.sameClass(ref)) {
                    toLog += "\tSkipping %s since not in same class\n".formatted(ref.getName(true));
                    continue;
                }

                // If the reference isn't the constructor then just look for alloc calls within it
                if (!ref.getName().contains(this.name)) {
                    toLog += "\tProcessing ctor %s (address %s)\n".formatted(ref.getName(true),
                        ref.getSymbol().getAddress());
                    var call = this.findAllocCallFor(ref, monitor);
                    if (call != null) {
                        return call;
                    }
                }
                else {
                    var callers = ref.getCallingFunctions(monitor);
                    for (var caller : callers) {
                        if (monitor.isCancelled()) {
                            throw new CancelledException(
                                "Task cancelled while looping through constructor xref alloc calls");
                        }
                        // Ignore xrefs that aren't in the same namespace
                        if (!this.sameClass(caller)) {
                            toLog += "\tSkipping %s since not in same class\n"
                                    .formatted(caller.getName(true));
                            continue;
                        }
                        toLog += "\tProcessing xref %s (address %s)\n"
                                .formatted(caller.getName(), caller.getSymbol().getAddress());
                        var call = this.findAllocCallFor(caller, monitor);
                        if (call != null) {
                            return call;
                        }
                    }
                }
            }

            // print(toLog);
            throw new IllegalArgumentException("No call to alloc function found in all refs");
        }

        private long getSize() throws IllegalArgumentException, CancelledException {
            var program = this.symbol.getProgram();

            // Have a 5 second timeout
            var monitor =
                TimeoutTaskMonitor.timeoutIn(5, TimeUnit.SECONDS, new TaskMonitorAdapter(true));

            // Call must be nonnull otherwise it'll throw an exception which we'll propagate
            var call = this.findAllocCall(monitor);
            // Get the corresponding function containing the call
            var func = getFunctionContaining(call);

            // Propagate constant values so I can check what the call
            var analyzer = this.getConstantAnalyzer(program);
            // It irks me that this is spelled wrong
            var prop = new SymbolicPropogator(program);
            analyzer.flowConstants(program, func.getEntryPoint(), func.getBody(), prop, monitor);

            // Get the value of the register at the point of the call
            var reg = func.getProgram().getLanguage().getRegister("r0");
            return prop.getRegisterValue(call, reg).getValue();
        }

        ClassSymbol(Symbol symbol) throws IllegalArgumentException, MemoryAccessException {
            var namespace = symbol.getParentNamespace();
            this.name = namespace.getName();
            var parent = namespace.getParentNamespace();
            this.namespace = parent.isGlobal() ? "" : parent.getName();
            this.symbol = symbol;
            /* printf("Processing class %s (symbol %s)\n".formatted(this.name,
                this.symbol.getAddress()));
                */
            this.typeInfo = this.getTypeInfo();
            this.vtables = this.getVTables();
            try {
                this.size = this.getSize();
                printf("Class %s has size 0x%x\n".formatted(this.name, this.size));
            }
            catch (Exception e) {
                printf("Couldn't get size for class %s: %s\n".formatted(this.name, e));
            }
        }

        public void dump(FileOutputStream stream) throws IOException {
            stream.write("class %s (size %s):\n".formatted(this.name, this.size).getBytes());
            for (var vtable : this.vtables) {
                vtable.dump(stream);
            }
        }
    }

    private ArrayList<ClassSymbol> getClasses() {
        var table = this.currentProgram.getSymbolTable();
        SymbolIterator symbols = table.getSymbols(VTABLE_SYMBOL);
        var classes = new ArrayList<ClassSymbol>();
        for (var symbol : symbols) {
            try {
                classes.add(new ClassSymbol(symbol));
            }
            catch (Exception e) {
                this.printf("Couldn't convert symbol to virtual table: %s\n", e);
            }
        }
        return classes;
    }

    private void assertAndroid() throws IllegalArgumentException {
        var desc = this.currentProgram.getLanguage().getLanguageDescription();
        if (desc.getEndian() != Endian.LITTLE) {
            throw new IllegalArgumentException("Current program is not little endian");
        }
        if (!desc.getProcessor().toString().contains("ARM")) {
            throw new IllegalArgumentException("Processor for current program is not ARM-based");
        }
        if (desc.getSize() != POINTER_SIZE * 8) {
            throw new IllegalArgumentException("Current program processor is not 32-bits");
        }
        if (!this.currentProgram.getExecutableFormat().contains("ELF")) {
            throw new IllegalArgumentException("Current program is not an ELF file");
        }
    }

    @Override
    protected void run()
            throws CancelledException, FileNotFoundException, SecurityException, IOException {
        // Verify we're running on 32 bit Android
        this.assertAndroid();

        var file = this.askFile("Choose output dump", "OK");
        var classes = this.getClasses();
        try (var stream = new FileOutputStream(file)) {
            for (var c : classes) {
                c.dump(stream);
            }
        }
    }
}