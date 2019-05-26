# JavaCard SMPC RSA

The implementation of the adapted Smart-ID scheme for smart cards.

The project is based on the [JavaCard Template project with Gradle](https://github.com/crocs-muni/javacard-gradle-template-edu) by Dušan Klinec and Petr Švenda.

Using IntelliJ Idea is recommended.

The `applet/src/main/java/smpc_rsa/` folder contains the source code.

## Build

To build the project use the `build/buildJavaCard` Gradle task in the IntelliJ Idea
or use the `gradlew` wrapper script in the root folder.

```
./gradlew buildJavaCard  --info --rerun-tasks
```

NOTE: The `gradlew` script always uses only the last part of the task name. Therefore,
only `buildJavaCard` instead of `build/buildJavaCard` is needed.

The `applet/build/javacard/` folder then contains the resulting `.cap` files of
given applet versions.


## Test

To test the project use the `verification/test` Gradle task in the IntelliJ Idea
or use the `gradlew` wrapper script in the root folder.

```
./gradlew test  --info --rerun-tasks
```

## JavaCard Kits

The project can be configured to many versions of the JavaCard platform.
However, only JavaCard Kit 2.2.2 is attached to lower the size of this archive.

Other versions can be found in the [oracle_javacard_sdks](https://github.com/martinpaljak/oracle_javacard_sdks)
repository by Martin Paljak. Just clone it into the `libs-sdks` folder.

