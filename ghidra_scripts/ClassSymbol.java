// Utility class to process C++ class symbols.

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.task.TimeoutTaskMonitor;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.SymbolicPropogator;
import java.util.HashSet;
import java.util.List;

public class ClassSymbol {
    private final static String INVALID_SYMBOL = "The virtual table symbol passed was invalid";
    private final static String ALLOC_FUNC = "operator.new";
    private final static String VTABLE_SYMBOL = "vtable";

    private GhidraScript script;
    private int pointerSize;
    private RTTISymbol rtti;
    private Symbol symbol;
    public String namespace;
    public String name;
    public ArrayList<VtableSymbol> vtables;
    public long size;
    public boolean guessed;

    private ArrayList<VtableSymbol> getVTables() {
        var vtables = new ArrayList<VtableSymbol>();
        var iter = this.symbol.getAddress();
        while (true) {
            try {
                var vtable =
                    new VtableSymbol(this.script, iter, this.rtti, this.pointerSize);
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

    private RTTISymbol getRTTI() throws IllegalArgumentException, MemoryAccessException {
        var offset =
            this.script.getInt(symbol.getAddress().add(this.pointerSize));
        var space = this.symbol.getAddress().getAddressSpace();
        var address = space.getAddress(offset);
        var symbol = this.symbol.getProgram().getSymbolTable().getPrimarySymbol(address);
        if (symbol == null) {
            throw new IllegalArgumentException(INVALID_SYMBOL);
        }
        return new RTTISymbol(this.script, address, this.pointerSize);
    }

    private Optional<Address> findAllocCallForFunc(Function func, TaskMonitor monitor) {
        // Kind of stolen from FunctionDB.getReferencesFromBody
        return StreamSupport.stream(func.getBody().getAddresses(true).spliterator(), false)
                .takeWhile(ignore -> !monitor.isCancelled())
                .flatMap(
                    addr -> Stream.of(
                        func.getProgram().getReferenceManager().getReferencesFrom(addr)))
                .filter(ref -> {
                    var called = this.script.getFunctionAt(ref.getToAddress());
                    return called != null && called.getName().contains(ALLOC_FUNC);
                })
                .map(ref -> ref.getFromAddress())
                .findAny();
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
                .findAny()
                .orElse(Optional.empty());
    }

    private Optional<Long> getAllocSizeFromCall(Address call, TaskMonitor monitor) {
        var program = this.symbol.getProgram();

        // Get the corresponding function containing the call
        var func = this.script.getFunctionContaining(call);

        // Propagate constant values so I can check what the call
        var analyzer = Util.getConstantAnalyzer(program);
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

    ClassSymbol(GhidraScript script, Symbol symbol, int pointerSize)
            throws IllegalArgumentException, MemoryAccessException {
        this.script = script;
        this.pointerSize = pointerSize;

        var namespace = symbol.getParentNamespace();
        this.name = namespace.getName();
        var parent = namespace.getParentNamespace();
        this.namespace = parent.isGlobal() ? "" : parent.getName(true);
        this.symbol = symbol;
        this.rtti = this.getRTTI();
        this.vtables = this.getVTables();
        this.getAllocSize()
                .ifPresentOrElse(
                    size -> {
                        this.size = size;
                        this.guessed = false;
                        // printf("Size for class %s is %s\n", this.fullName(), this.size);
                    },
                    () -> {
                        // printf("Couldn't get size of class %s\n", this.fullName());
                        this.size = this.getGuessedSize();
                        this.guessed = true;
                    });
    }

    public static List<ClassSymbol> getClassesFor(GhidraScript script, int pointerSize) {
        return StreamSupport.stream(
            script.getCurrentProgram().getSymbolTable().getSymbols(VTABLE_SYMBOL).spliterator(),
            false)
                .flatMap(symbol -> {
                    try {
                        // script.printf("Symbol for class %s\n", symbol.getName(true));
                        return Stream.of(new ClassSymbol(script, symbol, pointerSize));
                    }
                    catch (Exception e) {
                        script.printf("Couldn't get class for symbol %s: %s\n",
                            symbol.getName(true),
                            e);
                        return Stream.empty();
                    }
                })
                .toList();
    }

    public void dump(FileOutputStream stream) throws IOException {
        var size = this.size > 0 ? Long.toString(this.size) : "unknown";
        stream.write("class %s %s (size %s):\n"
                .formatted(this.fullName(), this.rtti.dumpParents(), size)
                .getBytes());
        for (var vtable : this.vtables) {
            vtable.dump(stream);
        }
    }
}
