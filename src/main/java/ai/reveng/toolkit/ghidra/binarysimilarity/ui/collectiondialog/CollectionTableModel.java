package ai.reveng.toolkit.ghidra.binarysimilarity.ui.collectiondialog;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

import static ai.reveng.toolkit.ghidra.Utils.addRowToDescriptor;

public class CollectionTableModel extends ThreadedTableModelStub<CollectionRowObject> {
	// column indexes
	final static byte NAME = 0;
	final static byte INCLUDE = 1;
	
	private PluginTool plugin;
	
	public CollectionTableModel(PluginTool plugin) {
		super("Collections Table Model", plugin);
		this.plugin = plugin;
	}

	@Override
	protected void doLoad(Accumulator<CollectionRowObject> accumulator, TaskMonitor monitor){
		var service = serviceProvider.getService(GhidraRevengService.class);
		if (service == null) return;
		monitor.setProgress(0);
		monitor.setMessage("Loading collections");
		service.getActiveCollections().forEach(collection -> {
			accumulator.add(new CollectionRowObject(collection, true));
		});
	}

	@Override
	public void clearData() {
		super.clearData();
	}

	@Override
	protected TableColumnDescriptor<CollectionRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<CollectionRowObject> descriptor = new TableColumnDescriptor<CollectionRowObject>();
		descriptor.addVisibleColumn(new CollectionNameTableColumn());
		descriptor.addVisibleColumn(new CollectionIncludeTableColumn());
		addRowToDescriptor(descriptor, "Scope", String.class, (row) -> row.getCollection().collectionScope());
		addRowToDescriptor(descriptor, "Created", String.class, (row) -> row.getCollection().creationDate());
//		addRowToDescriptor(descriptor, "Model", String.class, (row) -> row.getCollection().modelName());
		addRowToDescriptor(descriptor, "Description", String.class, (row) -> row.getCollection().description());
//		addRowToDescriptor(descriptor, "Owner", String.class, (row) -> row.getCollection().owner());

		return descriptor;
	}



	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		switch(columnIndex) {
			case INCLUDE:
				return true;
			default:
				return false;
		}
	}
	
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		switch(columnIndex) {
		case INCLUDE:
			if (aValue instanceof Boolean) {
				CollectionRowObject ro = getRowObject(rowIndex);
				ro.setInclude((Boolean) aValue);
				fireTableRowsUpdated(rowIndex, rowIndex);
				storeCollectionsInService();
			}
		default:
			break;
		}
	}

	public void storeCollectionsInService() {
		serviceProvider
				.getService(GhidraRevengService.class)
				.setActiveCollections(
						getModelData().stream()
								.filter(CollectionRowObject::isInclude)
								.map(CollectionRowObject::getCollection)
								.toList()
				);

	}


	private class CollectionNameTableColumn extends AbstractDynamicTableColumn<CollectionRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Collection Name";
		}

		@Override
		public String getValue(CollectionRowObject rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getCollectionName();
		}
	}
	
	private class CollectionIncludeTableColumn extends AbstractDynamicTableColumn<CollectionRowObject, Boolean, Object> {

		@Override
		public String getColumnName() {
			return "Include";
		}

		@Override
		public Boolean getValue(CollectionRowObject rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isInclude();
		}
		
	}
}
