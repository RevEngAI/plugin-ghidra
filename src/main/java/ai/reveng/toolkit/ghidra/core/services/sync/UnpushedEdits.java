package ai.reveng.toolkit.ghidra.core.services.sync;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;

/// The functions whose local edits have not reached the portal yet.
///
/// An edit is marked here when its push is scheduled and cleared only once a push succeeds, so a push
/// that fails, or never runs because Ghidra closed first, is still known about and "Sync with portal"
/// sends it. Sync cannot find these edits by itself: it leaves user-defined local names alone, because
/// it cannot tell an edit that never went up from one the portal has since overwritten.
///
/// The marks live in the program's user data, which is saved with the program but sits outside its
/// undo history and does not mark the program as changed.
public final class UnpushedEdits {

    private static final String OWNER = "RevEng.AI";

    public enum Kind {
        NAME("Unpushed function names"),
        TYPES("Unpushed function types");

        private final String propertyName;

        Kind(String propertyName) {
            this.propertyName = propertyName;
        }
    }

    private UnpushedEdits() {}

    public static synchronized void mark(Program program, Kind kind, Address entryPoint) {
        var userData = program.getProgramUserData();
        int tx = userData.startTransaction();
        try {
            userData.getBooleanProperty(OWNER, kind.propertyName, true).add(entryPoint);
        } finally {
            userData.endTransaction(tx);
        }
    }

    public static synchronized void clear(Program program, Kind kind, Address entryPoint) {
        var userData = program.getProgramUserData();
        int tx = userData.startTransaction();
        try {
            var marks = userData.getBooleanProperty(OWNER, kind.propertyName, false);
            if (marks != null) {
                marks.remove(entryPoint);
            }
        } finally {
            userData.endTransaction(tx);
        }
    }

    public static synchronized boolean isMarked(Program program, Kind kind, Address entryPoint) {
        var marks = program.getProgramUserData().getBooleanProperty(OWNER, kind.propertyName, false);
        return marks != null && marks.hasProperty(entryPoint);
    }

    /// The entry points marked for `kind`, in address order.
    public static synchronized List<Address> marked(Program program, Kind kind) {
        var marks = program.getProgramUserData().getBooleanProperty(OWNER, kind.propertyName, false);
        List<Address> entryPoints = new ArrayList<>();
        if (marks != null) {
            marks.getPropertyIterator().forEach(entryPoints::add);
        }
        return entryPoints;
    }
}
