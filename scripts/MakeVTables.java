import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.Optional;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
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
        private final static String ALLOC_FUNC = "operator.new";

        private long typeInfo;
        private Symbol symbol;
        public String namespace;
        public String name;
        public ArrayList<VTable> vtables;
        public long size;
        public boolean guessed;

        private ArrayList<VTable> getVTables() {
            var vtables = new ArrayList<VTable>();
            var iter = this.symbol.getAddress();
            while (true) {
                try {
                    var vtable = new VTable(iter, this.typeInfo);
                    vtables.add(vtable);
                    iter = iter.addWrap(vtable.size);
                }
                catch (Exception e) {
                    // This is fine we just exit when an exception happens
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

        private Optional<Address> findAllocCallForFunc(Function func, TaskMonitor monitor) {
            // Kind of stolen from FunctionDB.getReferencesFromBody
            return StreamSupport.stream(func.getBody().getAddresses(true).spliterator(), false)
                    .takeWhile(ignore -> !monitor.isCancelled())
                    .flatMap(
                        addr -> Stream.of(
                            func.getProgram().getReferenceManager().getReferencesFrom(addr)))
                    .filter(ref -> {
                        var called = getFunctionAt(ref.getToAddress());
                        return called != null && called.getName().contains(ALLOC_FUNC);
                    })
                    .map(ref -> ref.getFromAddress())
                    .findFirst();
        }

        private String fullName() {
            if (this.namespace.equals("")) {
                return name;
            }
            else {
                return "%s::%s".formatted(this.namespace, this.name);
            }
        }

        private boolean sameClass(Function func) {
            return this.fullName().equals(func.getParentNamespace().getName(true));
        }

        // Returns null if not found
        private Optional<Address> findAllocCall(TaskMonitor monitor) {
            HashSet<Function> allRefs = null;
            // Intersect all functions in each vtable's references
            for (var vtable : this.vtables) {
                if (allRefs == null) {
                    allRefs = vtable.refs;
                }
                else {
                    allRefs.retainAll(vtable.refs);
                }
            }

            return allRefs.stream()
                    .takeWhile(ignore -> !monitor.isCancelled())
                    .filter(ref -> this.sameClass(ref))
                    .flatMap(ref -> {
                        if (!ref.getName().equals(this.name)) {
                            // If it's not the ctor just check ourselves
                            return Stream.of(ref);
                        }
                        else {
                            // Otherwise check the references of the ctor
                            return ref.getCallingFunctions(monitor)
                                    .stream()
                                    .filter(caller -> this.sameClass(caller));
                        }
                    })
                    .map(func -> this.findAllocCallForFunc(func, monitor))
                    .filter(call -> call.isPresent())
                    .findFirst()
                    .orElse(Optional.empty());
        }

        private Optional<Long> getAllocSizeFromCall(Address call, TaskMonitor monitor) {
            var program = this.symbol.getProgram();

            // Get the corresponding function containing the call
            var func = getFunctionContaining(call);

            // Propagate constant values so I can check what the call
            var analyzer = this.getConstantAnalyzer(program);
            // It irks me that this is spelled wrong
            var prop = new SymbolicPropogator(program);
            try {
                analyzer.flowConstants(program, func.getEntryPoint(), func.getBody(), prop,
                    monitor);

                // Get the value of the register at the point of the call
                var reg = func.getProgram().getLanguage().getRegister("r0");
                return Optional.of(prop.getRegisterValue(call, reg).getValue());
            }
            catch (CancelledException c) {
                return Optional.empty();
            }
        }

        private Optional<Long> getAllocSize() {
            // Have a 5 second timeout
            var monitor =
                TimeoutTaskMonitor.timeoutIn(5, TimeUnit.SECONDS, new TaskMonitorAdapter(true));

            // Call must be nonnull otherwise it'll throw an exception which we'll propagate
            return this.findAllocCall(monitor)
                    .flatMap(call -> this.getAllocSizeFromCall(call, monitor));
        }

        private long getGuessedSize() {
            // Unimplemented
            return 0;
        }

        ClassSymbol(Symbol symbol) throws IllegalArgumentException, MemoryAccessException {
            var namespace = symbol.getParentNamespace();
            this.name = namespace.getName();
            var parent = namespace.getParentNamespace();
            this.namespace = parent.isGlobal() ? "" : parent.getName(true);
            this.symbol = symbol;
            this.typeInfo = this.getTypeInfo();
            this.vtables = this.getVTables();
            this.getAllocSize()
                    .ifPresentOrElse(
                        size -> {
                            this.size = size;
                            this.guessed = false;
                            // printf("Size for class %s is %s\n", this.fullName(), this.size);
                        },
                        () -> {
                            printf("Couldn't get size of class %s\n", this.fullName());
                            this.size = this.getGuessedSize();
                            this.guessed = true;
                        });
        }

        public void dump(FileOutputStream stream) throws IOException {
            var size = this.size > 0 ? Long.toString(this.size) : "unknown";
            stream.write("class %s (size %s):\n".formatted(this.fullName(), size).getBytes());
            for (var vtable : this.vtables) {
                vtable.dump(stream);
            }
        }
    }

    private List<ClassSymbol> getClasses() {
        // I don't know if this is slow or not but it seems to work fine
        return StreamSupport.stream(
            this.currentProgram.getSymbolTable().getSymbols(VTABLE_SYMBOL).spliterator(), false)
                .flatMap(symbol -> {
                    try {
                        return Stream.of(new ClassSymbol(symbol));
                    }
                    catch (Exception e) {
                        return Stream.empty();
                    }
                })
                .collect(Collectors.toList());
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