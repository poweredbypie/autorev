import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
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

    private class Parent {
        public String name;
        public int offset;
        public boolean pub;

        Parent(String name, int offset, boolean pub) {
            this.name = name;
            this.offset = offset;
            this.pub = pub;
        }

        public String toString() {
            String specifier = this.pub ? "public" : "";
            return "%s %s (%x)".formatted(specifier, this.name, this.offset);
        }
    }

    private GhidraScript script;
    private int pointerSize;
    private List<Parent> parents;
    public DataType dataType;
    public Address address;

    // Gets the typeinfo structure's vtable
    private Symbol getVtable() throws IllegalArgumentException, MemoryAccessException {
        var space = this.address.getAddressSpace();
        // We have to subtract 2 slots for the struct offset and the typeinfo pointer
        var address =
            space.getAddress(this.script.getInt(this.address) - (2 * this.pointerSize));
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
            throw new IllegalArgumentException(
                "Too many or too little datatypes for class %s (%d)"
                        .formatted(className, types.length));
        }

        return types[0];
    }

    // Don't multiply by pointerSize before passing something to this because it already does that
    private Parent derefRTTI(Address address, int offset)
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
        return new Parent(
            symbol.getParentNamespace().getName(true),
            0,
            false);
    }

    private List<Parent> getSingleInherited()
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

    private List<Parent> getMultipleInherited()
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
        if ((flags & 2) != 0) {
            throw new IllegalArgumentException(
                "Assumption violated: no support for diamond repeats (lazy)");
        }

        var baseCount = this.script.getInt(this.address.add(3 * this.pointerSize));
        var parents = new ArrayList<Parent>();
        for (int i = 0; i < baseCount; i += 1) {
            var parent = this.derefRTTI(this.address, 4 + (i * 2));
            var baseFlags = this.script.getInt(this.address.add((5 + (i * 2)) * this.pointerSize));
            if ((baseFlags & 1) != 0) {
                throw new IllegalArgumentException(
                    "Assumption violated: no support for virtual inheritance (lazy)");
            }
            // Whether the parent is publicly inherited
            parent.pub = (baseFlags & 2) != 0;
            parent.offset = (baseFlags >> 8);
            parents.add(parent);
        }
        return parents;
    }

    private List<Parent> getParents() throws IllegalArgumentException, MemoryAccessException {
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

        var strings = this.parents.stream().map(parent -> parent.toString()).toList();
        return ": " + String.join(", ", strings);
    }
}
