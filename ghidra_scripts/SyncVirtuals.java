// Sync virtual functions between Windows and Android.

import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class SyncVirtuals extends GhidraScript {
    @Override
    protected void run() throws CancelledException, VersionException, IOException {
        var program = this.askProgram("Select Windows binary");
        this.printf("Program is %s", program);
        /* Strategy: apply names and signatures to virtual functions from Android to Windows
         * Pseudocode:
         * Map<string, Vtable> androidTables = getAndroidVTables()
         * for &vtable in androidTables:
         *      // Deduplicate two dtors
         *      vtable.removeDeletingDtor()
         * for vtable in windowsProgram.getSymbols('vftable'):
         *      androidVTable = androidTable.get(vtable.getName())
         *      if androidVTable != null:
         *          assert(vtable.getLength() == androidVTable.getLength())
         *          for index, func in androidVTable:
         *              vtable[index].fixup(func)
         */
    }
}
