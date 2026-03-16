plugins {
    java
}

group = "io.github.sentientzero"
version = "2.0.1"

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.12")
    implementation("com.google.code.gson:gson:2.11.0")
}

tasks.jar {
    archiveBaseName.set("gql-hound")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    manifest {
        attributes["Implementation-Title"] = "GQL Hound"
        attributes["Implementation-Version"] = version
    }
}
