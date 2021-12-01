# JavaCard SMPC RSA

[![Build Status](https://travis-ci.org/lzaoral/javacard-smpc-rsa.svg?branch=master)](https://travis-ci.org/lzaoral/javacard-smpc-rsa)

The implementation of the adapted Smart-ID scheme for smart cards.

The project is based on the [JavaCard Template project with Gradle](https://github.com/crocs-muni/javacard-gradle-template-edu)
by Dušan Klinec and Petr Švenda.

Using IntelliJ Idea is recommended.

The `applet/src/main/java/smpc_rsa/` folder contains the source code.

## Build

Do not forget to clone all git submodules!

```console
$ git submodule init
$ git submodule update
```

To build the project use the `build/buildJavaCard` Gradle task in the IntelliJ Idea
or use the `gradlew` wrapper script in the root folder.

```console
$ ./gradlew buildJavaCard --info --rerun-tasks
```

NOTE: The `gradlew` script always uses only the last part of the task name. Therefore,
only `buildJavaCard` instead of `build/buildJavaCard` is needed.

The `applet/build/javacard/` folder then contains the resulting `.cap` files of
given applet variants.

## Test

To test the project use the `verification/test` Gradle task in the IntelliJ Idea
or use the `gradlew` wrapper script in the root folder.

```console
$ ./gradlew test --info --rerun-tasks
```

## JavaCard Kits

The project can be configured with many versions of the JavaCard platform provided
by the [`oracle_javacard_sdks`](https://github.com/martinpaljak/oracle_javacard_sdks)
repository by Martin Paljak and which is a git submodule of this project linked to the
`libs-sdks` directory.
