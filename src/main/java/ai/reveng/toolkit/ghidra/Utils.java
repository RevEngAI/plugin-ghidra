package ai.reveng.toolkit.ghidra;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;

public class Utils {

    /**
     * Helper method
     * Can be replaced when/if <a href="https://github.com/NationalSecurityAgency/ghidra/pull/7346">this PR</a> gets merged
     */
    public static <ROW_TYPE, COLUMN_TYPE> void addRowToDescriptor(
            TableColumnDescriptor<ROW_TYPE> descriptor,
            String columnName,
            boolean visible,
            Class<COLUMN_TYPE> columnTypeClass,
            RowObjectAccessor<ROW_TYPE, COLUMN_TYPE> rowObjectAccessor) {

        var column = new AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, Object>() {
            @Override
            public String getColumnName() {
                return columnName;
            }

            @Override
            public COLUMN_TYPE getValue(ROW_TYPE rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObjectAccessor.access(rowObject);
            }

            @Override
            public Class<COLUMN_TYPE> getColumnClass() {
                return columnTypeClass;
            }

            @Override
            public Class<ROW_TYPE> getSupportedRowType() {
                // The reflection tricks in the regular implementation won't work anyway and will return null
                return null;
            }
        };
        if (visible){
            descriptor.addVisibleColumn(column);
        } else {
            descriptor.addHiddenColumn(column);
        }
    }

    public static <ROW_TYPE, COLUMN_TYPE> void addRowToDescriptor(
            TableColumnDescriptor<ROW_TYPE> descriptor,
            String columnName,
            Class<COLUMN_TYPE> columnTypeClass,
            RowObjectAccessor<ROW_TYPE, COLUMN_TYPE> rowObjectAccessor) {
        addRowToDescriptor(descriptor, columnName, true, columnTypeClass, rowObjectAccessor);
    }

    /**
     * Helper method to add a column with sort ordinal specification.
     * @param sortOrdinal 1-based sort priority (1 = primary sort), or -1 for no default sort
     * @param ascending true for ascending sort, false for descending
     */
    public static <ROW_TYPE, COLUMN_TYPE> void addRowToDescriptor(
            TableColumnDescriptor<ROW_TYPE> descriptor,
            String columnName,
            Class<COLUMN_TYPE> columnTypeClass,
            RowObjectAccessor<ROW_TYPE, COLUMN_TYPE> rowObjectAccessor,
            int sortOrdinal,
            boolean ascending) {

        var column = new AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, Object>() {
            @Override
            public String getColumnName() {
                return columnName;
            }

            @Override
            public COLUMN_TYPE getValue(ROW_TYPE rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObjectAccessor.access(rowObject);
            }

            @Override
            public Class<COLUMN_TYPE> getColumnClass() {
                return columnTypeClass;
            }

            @Override
            public Class<ROW_TYPE> getSupportedRowType() {
                return null;
            }
        };
        descriptor.addVisibleColumn(column, sortOrdinal, ascending);
    }



    @FunctionalInterface
    public interface RowObjectAccessor<ROW_TYPE, COLUMN_TYPE> {
        public COLUMN_TYPE access(ROW_TYPE rowObject) throws IllegalArgumentException;
    }

}


