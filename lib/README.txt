The "lib" directory holds the Jar files which this module depends upon at runtime. They are put
here by Gradle from the dependencies block of this module's build.gradle, and end up in the built
extension zip. The jars themselves are not checked in.

Do not place jars here by hand: every build first deletes lib/*.jar (see the pruneStaleJars task in
build.gradle) so that only the dependencies that actually resolved are shipped.
