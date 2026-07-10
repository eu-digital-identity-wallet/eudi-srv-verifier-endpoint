import org.jetbrains.kotlin.gradle.dsl.JvmDefaultMode
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import org.springframework.boot.gradle.plugin.SpringBootPlugin
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.kotlin.plugin.serialization)
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spotless)
    alias(libs.plugins.kover)
    alias(libs.plugins.dependencycheck)
}

repositories {
    mavenCentral()
    maven {
        url = uri("https://maven.waltid.dev/releases")
        mavenContent {
            releasesOnly()
        }
    }
}

dependencies {
    implementation(platform(libs.kotlin.bom))
    implementation(platform(libs.kotlinx.coroutines.bom))
    implementation(platform(libs.ktor.bom))
    implementation(platform(libs.kotlinx.serialization.bom))
    implementation(platform(libs.arrow.stack))
    implementation(platform(SpringBootPlugin.BOM_COORDINATES))

    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation(libs.nimbusds.oauth2.oidc.sdk)
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation(libs.bouncy.castle)
    implementation(libs.arrow.core)
    implementation(libs.arrow.fx.coroutines)
    implementation(libs.arrow.core.serialization)
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.webjars:webjars-locator-lite")
    implementation(libs.swagger.ui)
    implementation(libs.waltid.mdoc.credentials) {
        because("To verify CBOR credentials")
    }
    implementation(libs.kotlinx.datetime) {
        because("required by walt.id")
    }
    implementation(libs.cose.java) {
        because("required by walt.id")
    }
    implementation(libs.sd.jwt)
    implementation(libs.ktor.client.apache) {
        because("ktor client engine to use (required by SdJwtVcVerifier)")
    }
    implementation(libs.ktor.client.content.negotiation) {
        because("ktor client content negotiation (required by http client for SD-JWT)")
    }
    implementation(libs.ktor.client.serialization) {
        because("ktor client serialization (required by http client for SD-JWT)")
    }
    implementation(libs.tink) {
        because("Support OctetKeyPairs and extra EncryptionMethods")
    }
    implementation(libs.statium) {
        because("Get value in a position of a status list token")
    }
    implementation(libs.zxing)
    implementation(libs.uri)
    implementation(libs.aedile)

    implementation(libs.consultation)

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.projectreactor:reactor-test")
    testImplementation("org.springframework.boot:spring-boot-webtestclient")
}

kotlin {
    jvmToolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get())
        vendor = JvmVendorSpec.ADOPTIUM
        implementation = JvmImplementation.VENDOR_SPECIFIC
    }

    target {
        compilerOptions {
            javaParameters = true
            jvmDefault = JvmDefaultMode.ENABLE
            jvmTarget = JvmTarget.fromTarget(libs.versions.java.get())
            apiVersion = KotlinVersion.DEFAULT
            languageVersion = KotlinVersion.DEFAULT
            optIn.addAll(
                "kotlin.contracts.ExperimentalContracts",
                "kotlinx.serialization.ExperimentalSerializationApi",
            )
            freeCompilerArgs.addAll(
                "-Xjsr305=strict",
            )
        }
    }
}

tasks.test {
    useJUnitPlatform()
}

springBoot {
    buildInfo()
}

tasks.named<BootBuildImage>("bootBuildImage") {
    imageName = "$group/${project.name}"
    publish = false
    environment = System.getenv()

    docker {
        val environment = environment.get()
        publishRegistry {
            environment["REGISTRY_URL"]?.let { url = it }
            environment["REGISTRY_USERNAME"]?.let { username = it }
            environment["REGISTRY_PASSWORD"]?.let { password = it }
        }
        environment["DOCKER_METADATA_OUTPUT_TAGS"]?.let { tagStr ->
            tags = tagStr.split(delimiters = arrayOf("\n", " ")).onEach { println("Tag: $it") }
        }
    }
}

spotless {
    val ktlintVersion = libs.versions.ktlintVersion.get()

    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("FileHeader.txt")
    }

    kotlinGradle {
        ktlint(ktlintVersion)
    }
}

dependencyCheck {
    formats = mutableListOf("XML", "HTML")

    nvd {
        apiKey = System.getenv("NVD_API_KEY") ?: findProperty("nvdApiKey")?.toString() ?: ""
        delay = 10000
        maxRetryCount = 2
    }
}
