# CLAUDE.md

Ghidra extension for the RevEng.AI toolkit (Java 21). Build with `GHIDRA_INSTALL_DIR=<ghidra> ./gradlew buildExtension`; test with `./gradlew test`.

## API access

**All RevEng.AI API calls must go through the generated `ai.reveng:sdk` client** (the `*Api` classes such as `CollectionsApi`, `SearchApi`, `AnalysesCoreApi`). Do not hand-roll HTTP requests — there is no manual request path left in `TypedApiImplementation`, and none should be reintroduced. Where a response cannot go through a generated model, use the generated `*Call` form and read the body directly, so the path, query and auth still come from the SDK.

If a generated SDK model rejects a live response (e.g. strict validation throwing on an undeclared field), fix it by bumping the SDK to a version whose model matches the API — not by falling back to a manual request. `SdkSchemaTest` guards the SDK version floor and the specific API/model surface the plugin depends on; update it when you change which SDK methods are used.

## Dependencies in the built extension

Runtime dependencies are copied into `lib/` and bundled into the extension zip. `lib/` is gitignored. The copy step does not prune old versions, so after bumping a dependency delete the previous jar from `lib/` before rebuilding — otherwise the zip ships two versions and the classloader may load the stale one.
