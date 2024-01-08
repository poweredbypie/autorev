import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Endian;
import ghidra.util.exception.CancelledException;

public class MakeVTables extends GhidraScript {
    private final static int POINTER_SIZE = 4;

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
        var classes = ClassSymbol.getClassesFor(this, POINTER_SIZE);
        try (var stream = new FileOutputStream(file)) {
            for (var c : classes) {
                c.dump(stream);
            }
        }

        /*
         * TODO: rename Windows vtable functions
         * Pseudocode:
         * vtables = getSymbols('vftable')
         * for vtable in vtables:
         *      data = getDataAt(vtable.getAddress())
         *      assert(data.getDataType() typeof Structure)
         *      for i in range(0, data.getNumComponents()):
         *          # This is already dereferenced and everything
         *          addr = data.getComponent(i).getValue()
         *          assert(addr typeof Address)
         *          func = getFunctionContaining(addr)
         *          if func.isExternal():
         *              continue # This is probably a cocos or msvcprt function so we skip renaming
         *          
         *          func.setName(getAndroidNameFor(func))
         */
    }
}