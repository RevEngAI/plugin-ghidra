# CLAUDE.md

Ghidra extension for the RevEng.AI toolkit (Java 21). Build with `GHIDRA_INSTALL_DIR=<ghidra> ./gradlew buildExtension`; test with `./gradlew test`.

## API access

**All RevEng.AI API calls must go through the generated `ai.reveng:sdk` client** (the `*Api` classes such as `CollectionsApi`, `SearchApi`, `AnalysesCoreApi`). Do not hand-roll HTTP requests. Where a response cannot go through a generated model, use the generated `*Call` form and read the body directly, so the path, query and auth still come from the SDK.

If a generated SDK model rejects a live response (e.g. strict validation throwing on an undeclared field), fix it by bumping the SDK to a version whose model matches the API — not by falling back to a manual request. `SdkSchemaTest` guards the SDK version floor and the specific API/model surface the plugin depends on; update it when you change which SDK methods are used.

## Dependencies in the built extension

Runtime dependencies are copied into `lib/` by Ghidra's `copyDependencies` task, put on the compile classpath, and bundled into the extension zip. The jars themselves are gitignored.

`copyDependencies` never removes anything, so `build.gradle` registers a `pruneStaleJars` task that deletes `lib/*.jar` and runs before it. Every build therefore starts from an empty `lib/` and ships exactly the jars that resolved; bumping or dropping a dependency needs no manual cleanup.
