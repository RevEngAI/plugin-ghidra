package ai.reveng.toolkit.ghidra.core.services.api.types;


/**
 * Data type for all reveng API responses or parameters that are a binary ID
 * They are called binary ID in the API doc, but they should be thought of as _analysis_ ids
 * for a single binary (identified by hash), there can be multiple analyses, which are distinguished by this ID
 */
@Deprecated
public record BinaryID(int value) implements Comparable<BinaryID> {
    public BinaryID {
        if (value < 0) {
            throw new IllegalArgumentException("BinaryID must be positive");
        }
    }

    @Override
    public int compareTo(BinaryID binaryID) {
        return Integer.compare(value, binaryID.value);
    }

    @Override
    public String toString() {
        return "BinaryID[" + value + ']';
    }
}
