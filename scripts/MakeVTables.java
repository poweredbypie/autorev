import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.CancelledException;

public class MakeVTables extends GhidraScript {
    private final static String VTABLE_SYMBOL = "vtable";
    private final static int POINTER_SIZE = 4;

    class VTable {
        private Address address;
        public ArrayList<Function> entries;
        public ArrayList<Function> refs;
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

        private ArrayList<Function> getRefs() {
            // Get references to the start of the actual vtable
            var refs = getReferencesTo(this.address.addWrap(2 * POINTER_SIZE));

            // Filter out references that are destructors
            var funcs = new ArrayList<Function>();
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
        public String name;
        public ArrayList<VTable> vtables;

        private ArrayList<VTable> getVTables() {
            var vtables = new ArrayList<VTable>();
            var iter = this.symbol.getAddress();
            while (true) {
                try {
                    var vtable = new VTable(iter, this.typeInfo);
                    vtables.add(vtable);
                    printf("Adding vtable at %s with size %d\n".formatted(iter, vtable.size));
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

        ClassSymbol(Symbol symbol) throws IllegalArgumentException, MemoryAccessException {
            this.name = symbol.getParentNamespace().getName(true);
            this.symbol = symbol;
            /* printf("Processing class %s (symbol %s)\n".formatted(this.name,
                this.symbol.getAddress()));
                */
            this.typeInfo = this.getTypeInfo();
            this.vtables = this.getVTables();
        }

        public void dump(FileOutputStream stream) throws IOException {
            stream.write("VTables for class %s:\n".formatted(this.name).getBytes());
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

    @Override
    protected void run()
            throws CancelledException, FileNotFoundException, SecurityException, IOException {
        var file = this.askFile("Choose output dump", "OK");
        var classes = this.getClasses();
        try (var stream = new FileOutputStream(file)) {
            for (var c : classes) {
                c.dump(stream);
            }
        }
    }
}