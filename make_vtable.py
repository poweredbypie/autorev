# This isn't updated. See scripts/MakeVTables.java for the Java port.
syms = currentProgram.getSymbolTable().getSymbols('vtable')

class Class:
    def get_typeinfo(self):
        # Offset 0 is the offset from the struct instance
        # Offset 4 is the pointer to a typeinfo object
        offset = self.sym.address.add(4)
        addr = self.space.getAddress(offset)
        symbol = currentProgram.getSymbolTable().getPrimarySymbol(offset)
        if symbol is None:
            raise RuntimeError('No associated typeinfo for vtable symbol')
        else:
            self.typeinfo = offset

    def get_vtable(self) -> Address

    def get_vtables(self):
        iter = self.sym


    def __init__(self, sym):
        self.sym = sym
        self.space = self.sym.getAddressSpace()
        self.name = self.sym.getParentNamespace().getName(True)
        self.get_typeinfo()


for sym in syms:
    className = sym.getParentNamespace().getName(True)
    space = sym.address.getAddressSpace()
    # Always 8 down. I dunno why, probably an ABI thing
    vtable = sym.address.add(8)
    # Find the references to the vtable
    # refs = getReferencesTo(vtable)
    end = vtable
    while True:
        func = getFunctionContaining(space.getAddress(getInt(end)))
        if func is None:
            print('Did not find function for offset ' + end.toString() + ', exiting loop')
            break
        # Move to the next function
        end = end.add(4)

    size = end.subtract(vtable)
    print('Class ' + className + ' starting from offset ' + vtable.toString() + ' has vtable size ' + str(size))