// Utility class to process a single C++ virtual table symbol.

import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class VtableSymbol {
    private GhidraScript script;
    private int pointerSize;

    private Address address;
    public ArrayList<Function> entries;
    public HashSet<Function> refs;
    public int size;
    public int offset;

    private int getStructOffset() throws IllegalArgumentException, MemoryAccessException {
        var offset = this.script.getInt(this.address);
        if (offset > 0) {
            throw new IllegalArgumentException(
                "Struct offset for %s is positive (0x%x)".formatted(this.address,
                    offset));
        }
        return offset;
    }

    private Address getRTTIAddress() throws MemoryAccessException {
        var space = this.address.getAddressSpace();
        return space.getAddress(this.script.getInt(this.address.add(this.pointerSize)));
    }

    private ArrayList<Function> getEntries() throws MemoryAccessException {
        // Get all entries in the vtable
        var space = this.address.getAddressSpace();
        // Get the span of addresses that are executable
        var execSpan = this.script.getCurrentProgram().getMemory().getExecuteSet();
        // Actual vtable starts 2 slots down
        var iter = address.addWrap(2 * this.pointerSize);
        var entries = new ArrayList<Function>();
        while (true) {
            // For some reason the functions are all offset by 1? Not sure why
            var addr = space.getAddress(this.script.getInt(iter) - 1);
            if (!execSpan.contains(addr)) {
                // We hit non-executable memory so this probably means the end of the vtable
                break;
            }
            var func =
                this.script.getFunctionContaining(space.getAddress(this.script.getInt(iter)));
            if (func == null) {
                // Create the function at the location because all vtables entries are functions
                this.script.createFunction(addr, null);
            }
            else {
                entries.add(func);
            }
            iter = iter.addWrap(this.pointerSize);
        }

        return entries;
    }

    private HashSet<Function> getRefs() {
        // Get references to the start of the actual vtable
        var refs = this.script.getReferencesTo(this.address.addWrap(2 * this.pointerSize));

        // Filter out references that are destructors
        var funcs = new HashSet<Function>();
        for (var ref : refs) {
            // Get the address that references the vtable start
            var from = ref.getFromAddress();
            var func = this.script.getFunctionContaining(from);

            // Skip either references that aren't in functions or are dtors
            if (func == null || func.getName().contains("~")) {
                continue;
            }

            funcs.add(func);
        }

        return funcs;
    }

    VtableSymbol(GhidraScript script, Address address, RTTISymbol rtti, int pointerSize)
            throws IllegalArgumentException, MemoryAccessException {
        this.script = script;
        this.pointerSize = pointerSize;
        this.address = address;

        // Validate parameters
        this.offset = this.getStructOffset();
        var rttiAddress = this.getRTTIAddress();
        if (!rtti.address.equals(rttiAddress)) {
            throw new IllegalArgumentException(
                "Type info does not match type info passed (0x%x vs. 0x%x)".formatted(rtti,
                    rttiAddress));
        }

        // Get entries
        this.entries = this.getEntries();
        this.size = (this.entries.size() + 2) * this.pointerSize;

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
