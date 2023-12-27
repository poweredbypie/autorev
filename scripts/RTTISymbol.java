import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;

public class RTTISymbol {
    private enum InheritType {
        // See https://itanium-cxx-abi.github.io/cxx-abi/abi.html#rtti
        NONE("__class_type_info"),
        ONE("__si_class_type_info"),
        MANY("__vmi_class_type_info");

        private String name;

        InheritType(String name) {
            this.name = name;
        }

        public static InheritType fromString(String text) throws IllegalArgumentException {
            for (var type : InheritType.values()) {
                if (type.name.equalsIgnoreCase(text)) {
                    return type;
                }
            }

            throw new IllegalArgumentException(
                "Unsupported inheritance hierarchy %s".formatted(text));
        }
    };

    private GhidraScript script;
    private int pointerSize;
    public DataType dataType;
    public List<String> parents;
    public Address address;

    // Gets the typeinfo structure's vtable
    private Symbol getVtable() throws IllegalArgumentException, MemoryAccessException {
        var space = this.address.getAddressSpace();
        // We have to subtract 2 slots for the struct offset and the typeinfo pointer
        var address = space.getAddress(this.script.getInt(this.address) - (2 * this.pointerSize));
        var vtable =
            this.script.getSymbolAt(address);
        if (vtable == null) {
            throw new IllegalArgumentException(
                "No typeinfo vtable at address %x".formatted(address));
        }

        return vtable;
    }

    private DataType getVtableType(Symbol vtable) throws IllegalArgumentException {
        var className = vtable.getParentNamespace().getName();
        var types = this.script.getDataTypes(className);
        if (types.length != 1) {
            throw new IllegalArgumentException("Too many or too little datatypes for class %s (%d)"
                    .formatted(className, types.length));
        }

        return types[0];
    }

    // Don't multiply by pointerSize before passing something to this because it already does that
    private String derefRTTI(Address address, int offset)
            throws IllegalArgumentException, MemoryAccessException {
        var rtti = address.getAddressSpace()
                .getAddress(
                    this.script.getInt(address.add(offset * this.pointerSize)));
        var symbol = this.script.getSymbolAt(rtti);
        if (symbol == null) {
            throw new IllegalArgumentException(
                "Couldn't dereference typeinfo at address %s, offset %x".formatted(address,
                    offset));
        }
        return symbol.getParentNamespace().getName(true);
    }

    private List<String> getSingleInherited()
            throws IllegalArgumentException, MemoryAccessException {
        /*
         * class __si_class_type_info {
         *      void *vtable;
         *      const char *__type_name;
         *      const __class_type_info *__base_type;
         * }
         */
        // The __base_type address is 2 slots down

        return List.of(this.derefRTTI(this.address, 2));
    }

    private List<String> getMultipleInherited()
            throws IllegalArgumentException, MemoryAccessException {
        /*
         * class __vmi_class_type_info {
         *      void *vtable;
         *      const char *__type_name;
         *      unsigned int __flags;
         *      unsigned int __base_count;
         *      // This is pseudocode
         *      __base_class_type_info __base_info[__base_count];
         * }
         * 
         * class __base_class_type_info {
         *      const __class_type_info *__base_type;
         *      long __offset_flags;
         * }
         */
        // Offset to base count is 3 down
        // Offset to base i is 4 + (i * 2) down

        // Assert that there are no repeat inheritance since this allows me to make some assumptions
        var flags = this.script.getInt(this.address.add(2 * this.pointerSize));
        if (flags != 0) {
            throw new IllegalArgumentException(
                "Assumption violated: flags for class is %x".formatted(flags));
        }

        var baseCount = this.script.getInt(this.address.add(3 * this.pointerSize));
        var parents = new ArrayList<String>();
        for (int i = 0; i < baseCount; i += 1) {
            parents.add(this.derefRTTI(this.address, 4 + (i * 2)));
        }
        return parents;
    }

    private List<String> getParents() throws IllegalArgumentException, MemoryAccessException {
        switch (InheritType.fromString(this.dataType.getName())) {
            case NONE:
                // Nothing, base class
                return List.of();
            case ONE:
                // Only one class
                return this.getSingleInherited();
            case MANY:
                // Many classes
                return this.getMultipleInherited();
            default:
                throw new IllegalArgumentException(
                    "Invalid inheritance type in switch (this should NEVER happen)");
        }
    }

    RTTISymbol(GhidraScript script, Address address, int pointerSize)
            throws IllegalArgumentException, MemoryAccessException {
        this.script = script;
        this.address = address;
        this.pointerSize = pointerSize;

        this.dataType = this.getVtableType(this.getVtable());
        this.parents = this.getParents();
    }

    // TODO: This is for dumping, you can remove this later
    public String dumpParents() {
        if (this.parents.size() == 0) {
            return "(base)";
        }

        return ": " + String.join(", ", this.parents);
    }
}
