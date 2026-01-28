/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.domain

import eu.europa.ec.eudi.sdjwt.vc.ClaimPath
import eu.europa.ec.eudi.sdjwt.vc.ClaimPathElement
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URL

@Serializable
@JvmInline
value class Format(val value: String) {
    init {
        require(value.isNotBlank()) { "Format cannot be blank" }
    }

    override fun toString(): String = value

    companion object {
        val MsoMdoc: Format get() = Format(OpenId4VPSpec.FORMAT_MSO_MDOC)
        val SdJwtVc: Format get() = Format(OpenId4VPSpec.FORMAT_SD_JWT_VC)
        val W3CJwtVcJson: Format get() = Format(OpenId4VPSpec.FORMAT_W3C_SIGNED_JWT)
    }
}

@Serializable
data class DCQL(
    /**
     * A non-empty list of [Credential Queries][CredentialQuery], that specify the requested Verifiable Credentials
     */
    @SerialName(OpenId4VPSpec.DCQL_CREDENTIALS) @Required val credentials: Credentials,
    /**
     * A non-empty list of [credential set queries][CredentialSetQuery], that specifies additional constraints
     * on which of the requested Verifiable Credentials to return
     */
    @SerialName(OpenId4VPSpec.DCQL_CREDENTIAL_SETS) val credentialSets: CredentialSets? = null,

) : java.io.Serializable {
    init {
        credentialSets?.ensureKnownIds(credentials)
    }
}

/**
 * A non-empty list of [credential queries][CredentialQuery],
 * having unique [ids][CredentialQuery.id]
 */
@Serializable
@JvmInline
value class Credentials(val value: List<CredentialQuery>) : java.io.Serializable {

    init {
        require(value.isNotEmpty()) { "${OpenId4VPSpec.DCQL_CREDENTIALS} cannot be empty" }
        value.ensureUniqueIds()
    }

    val ids: List<QueryId> get() = value.map { it.id }

    override fun toString(): String = value.toString()

    companion object {

        @JvmStatic
        @JvmName("of")
        operator fun invoke(vararg value: CredentialQuery): Credentials = Credentials(value.toList())

        private fun List<CredentialQuery>.ensureUniqueIds() {
            val uniqueIds = map { it.id }.toSet()
            require(uniqueIds.size == size) {
                "Within the Authorization Request, the same credential query id MUST NOT be present more than once"
            }
        }
    }
}

/**
 * A non-empty list of [credential set queries][CredentialSetQuery]
 */
@Serializable
@JvmInline
value class CredentialSets(val value: List<CredentialSetQuery>) : java.io.Serializable {

    init {
        require(value.isNotEmpty()) {
            "${OpenId4VPSpec.DCQL_CREDENTIAL_SETS} cannot be empty, if provided"
        }
    }

    /**
     * Makes sure that all the [credential set queries][value]
     * have options that reference the ids of the given [Credentials]
     * @param credentials the queries against which the [credential set queries][value] will be checked
     * @throws IllegalArgumentException if the above check fails
     */
    fun ensureKnownIds(credentials: Credentials): CredentialSets = apply {
        val violations = value.mapIndexedNotNull { index, credentialSet ->
            val invaliOptions = credentialSet.options.mapIndexedNotNull { optionIndex, option ->
                option.unknownIds(credentials).takeIf { it.isNotEmpty() }?.let { unknownIds ->
                    optionIndex to unknownIds
                }
            }
            invaliOptions.takeIf { it.isNotEmpty() }?.let {
                index to invaliOptions
            }
        }.toMap()
        require(violations.isEmpty()) {
            buildString {
                appendLine("The following credential set queries have invalid options:")
                violations.forEach { (index, invaliOptions) ->
                    appendLine("[$index]:")
                    invaliOptions.forEach { (optionIndex, unknownIds) ->
                        appendLine("[$optionIndex]:")
                        appendLine("  Unknown credential query ids: $unknownIds")
                    }
                }
            }
        }
    }

    override fun toString(): String = value.toString()

    companion object {
        @JvmStatic
        @JvmName("of")
        operator fun invoke(vararg value: CredentialSetQuery) = CredentialSets(value.toList())
    }
}

@Serializable
@JvmInline
value class TrustedAuthorityType(val value: String) : java.io.Serializable {
    init {
        require(value.isNotBlank()) { "TrustedAuthorityType cannot be blank" }
    }

    override fun toString(): String = value

    companion object {
        val AuthorityKeyIdentifier: TrustedAuthorityType get() = TrustedAuthorityType(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE_AKI)
        val TrustedList: TrustedAuthorityType get() = TrustedAuthorityType(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE_ETSI_TL)
        val OpenIdFederation: TrustedAuthorityType get() = TrustedAuthorityType(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE_OPENID_FEDERATION)
    }
}

@Serializable
data class TrustedAuthority(
    @SerialName(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE) @Required val type: TrustedAuthorityType,
    @SerialName(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_VALUES) @Required val values: List<String>,
) : java.io.Serializable {
    init {
        require(values.isNotEmpty()) { "${OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_VALUES} cannot be empty" }
        require(values.all { it.isNotBlank() }) { "${OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_VALUES} cannot contain blank values" }
    }

    @Suppress("unused")
    companion object {
        fun authorityKeyIdentifiers(values: List<String>): TrustedAuthority =
            TrustedAuthority(TrustedAuthorityType.AuthorityKeyIdentifier, values)

        fun trustedLists(values: List<URL>): TrustedAuthority =
            TrustedAuthority(TrustedAuthorityType.TrustedList, values.map { it.toExternalForm() })

        fun federatedEntities(values: List<URL>): TrustedAuthority =
            TrustedAuthority(TrustedAuthorityType.OpenIdFederation, values.map { it.toExternalForm() })
    }
}

/**
 * The [value] must be a non-empty string consisting of alphanumeric, underscore (_) or hyphen (-) characters
 */
@Serializable
@JvmInline
value class QueryId(val value: String) : java.io.Serializable {
    init {
        DCQLId.ensureValid(value)
    }

    override fun toString(): String = value
}

/**
 * Represents a request for a presentation of one Credential.
 */
@Serializable
data class CredentialQuery(
    /**
     * A string identifying the Credential in the response and, if provided, the constraints in credential_sets
     */
    @SerialName(OpenId4VPSpec.DCQL_ID) @Required val id: QueryId,
    @SerialName(OpenId4VPSpec.DCQL_FORMAT) @Required val format: Format,
    /**
     * An object defining additional properties requested by the Verifier that apply
     * to the metadata and validity data of the Credential.
     * The properties of this object are defined per Credential Format.
     * @see [CredentialQuery.metaMsoMdoc]
     * @see [CredentialQuery.metaSdJwtVc]
     */
    @SerialName(OpenId4VPSpec.DCQL_META) @Required val meta: JsonObject,
    /**
     * A boolean which indicates whether multiple Credentials can be returned for this Credential Query
     */
    @SerialName(OpenId4VPSpec.DCQL_MULTIPLE) val multiple: Boolean? = null,
    @SerialName(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITIES) val trustedAuthorities: List<TrustedAuthority>? = null,
    /**
     * A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof.
     * The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required.
     * If set to false, the Verifier accepts a Credential without Cryptographic Holder Binding proof.
     */
    @SerialName(OpenId4VPSpec.DCQL_REQUIRE_CRYPTOGRAPHIC_HB) val requireCryptographicHolderBinding: Boolean? = null,
    /**
     * A non-empty list that specifies claims in the requested Credential.
     */
    @SerialName(OpenId4VPSpec.DCQL_CLAIMS) val claims: List<ClaimsQuery>? = null,
    /**
     *A non-empty set containing sets of identifiers for elements in claims that
     * specifies which combinations of claims for the Credential are requested
     */
    @SerialName(OpenId4VPSpec.DCQL_CLAIM_SETS) val claimSets: List<ClaimSet>? = null,

) : java.io.Serializable {

    init {
        if (claims != null) {
            claims.ensureValid(format)
            claimSets?.ensureValid(claims)
        } else {
            require(claimSets == null) {
                "Cannot provide ${OpenId4VPSpec.DCQL_CLAIM_SETS} without ${OpenId4VPSpec.DCQL_CLAIMS}"
            }
        }
        if (null != trustedAuthorities) {
            require(trustedAuthorities.isNotEmpty()) {
                "${OpenId4VPSpec.DCQL_TRUSTED_AUTHORITIES} cannot be empty"
            }
        }
    }

    @Suppress("unused")
    val multipleOrDefault: Boolean
        get() = multiple ?: DEFAULT_MULTIPLE_VALUE

    @Suppress("unused")
    val requireCryptographicHolderBindingOrDefault: Boolean
        get() = requireCryptographicHolderBinding ?: DEFAULT_REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_VALUE

    companion object {
        private const val DEFAULT_MULTIPLE_VALUE: Boolean = false
        private const val DEFAULT_REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_VALUE: Boolean = true
        fun sdJwtVc(
            id: QueryId,
            sdJwtVcMeta: DCQLMetaSdJwtVcExtensions,
            multiple: Boolean? = null,
            trustedAuthorities: List<TrustedAuthority>? = null,
            requireCryptographicHolderBinding: Boolean? = null,
            claims: List<ClaimsQuery>? = null,
            claimSets: List<ClaimSet>? = null,
        ): CredentialQuery {
            val meta = sdJwtVcMeta.let { jsonSupport.encodeToJsonElement(it).jsonObject }
            return CredentialQuery(
                id,
                Format.SdJwtVc,
                meta,
                multiple,
                trustedAuthorities,
                requireCryptographicHolderBinding,
                claims,
                claimSets,
            )
        }

        fun mdoc(
            id: QueryId,
            msoMdocMeta: DCQLMetaMsoMdocExtensions,
            multiple: Boolean? = null,
            trustedAuthorities: List<TrustedAuthority>? = null,
            requireCryptographicHolderBinding: Boolean? = null,
            claims: List<ClaimsQuery>? = null,
            claimSets: List<ClaimSet>? = null,
        ): CredentialQuery {
            val meta = msoMdocMeta.let { jsonSupport.encodeToJsonElement(it).jsonObject }
            return CredentialQuery(
                id,
                Format.MsoMdoc,
                meta,
                multiple,
                trustedAuthorities,
                requireCryptographicHolderBinding,
                claims,
                claimSets,
            )
        }

        private fun List<ClaimsQuery>.ensureValid(format: Format) {
            require(isNotEmpty()) { "At least one claim must be defined" }
            ensureUniqueIds()
            when (format) {
                Format.MsoMdoc -> forEach { ClaimsQuery.ensureMsoMdoc(it) }
                else -> forEach { ClaimsQuery.ensureNotMsoMdoc(it) }
            }
        }

        private fun List<ClaimsQuery>.ensureUniqueIds() {
            val ids = mapNotNull { it.id }
            val uniqueIdsNo = ids.toSet().count()
            require(uniqueIdsNo == ids.size) {
                "Within a CredentialQuery, the same id of claims MUST NOT be present more than once"
            }
        }

        private fun List<ClaimSet>.ensureValid(claims: List<ClaimsQuery>) {
            val claimIds = claims.mapNotNull { it.id }
            require(this.isNotEmpty()) { "${OpenId4VPSpec.DCQL_CLAIM_SETS} cannot be empty" }
            this.forEach { claimSet ->
                claimSet.ensureKnownClaimIds(claimIds)
            }
        }
    }
}

@Serializable
@JvmInline
value class ClaimSet(val value: List<ClaimId>) : java.io.Serializable {

    init {
        value.ensureValid()
    }

    fun ensureKnownClaimIds(claimIds: List<ClaimId>) {
        require(value.all { id -> id in claimIds }) { "Unknown claim ids" }
    }

    override fun toString(): String = value.toString()

    companion object {
        private fun List<ClaimId>.ensureValid() {
            ensureNotEmpty()
            ensureUniqueIds()
        }

        private fun List<ClaimId>.ensureNotEmpty() {
            require(isNotEmpty()) {
                "Each element of ${OpenId4VPSpec.DCQL_CLAIM_SETS} cannot be empty"
            }
        }

        private fun List<ClaimId>.ensureUniqueIds() {
            val uniqueIds = map { it.value }.toSet()
            require(uniqueIds.size == size) {
                "Within a ClaimSet, the same claim id MUST NOT be present more than once"
            }
        }
    }
}

val CredentialQuery.metaMsoMdoc: DCQLMetaMsoMdocExtensions? get() = meta.metaAs()
val CredentialQuery.metaSdJwtVc: DCQLMetaSdJwtVcExtensions? get() = meta.metaAs()
internal inline fun <reified T> JsonObject?.metaAs(): T? = this?.let { jsonSupport.decodeFromJsonElement(it) }

@Serializable
data class CredentialSetQuery(

    @SerialName(OpenId4VPSpec.DCQL_OPTIONS) @Required val options: List<CredentialQueryIds>,
    /**
     * A boolean which indicates whether this set of Credentials is required
     * to satisfy the particular use case at the Verifier.
     *
     * If omitted, the default value is true
     */
    @SerialName(OpenId4VPSpec.DCQL_REQUIRED) val required: Boolean? = null,
) : java.io.Serializable {

    init {
        require(options.isNotEmpty()) { "${OpenId4VPSpec.DCQL_OPTIONS} cannot be empty" }
        val emptyOptions =
            options.mapIndexedNotNull { index, credentialSet -> index.takeIf { credentialSet.value.isEmpty() } }
        require(emptyOptions.isEmpty()) {
            "${OpenId4VPSpec.DCQL_OPTIONS} must contain non-empty arrays. Violations at $emptyOptions"
        }
    }

    @Suppress("unused")
    val requiredOrDefault: Boolean
        get() = required ?: DEFAULT_REQUIRED_VALUE

    companion object {

        private const val DEFAULT_REQUIRED_VALUE: Boolean = true
    }
}

/**
 * A non-empty list of [query ids][QueryId]
 */
@Serializable
@JvmInline
value class CredentialQueryIds(val value: List<QueryId>) : java.io.Serializable {

    init {
        value.ensureValid()
    }

    fun unknownIds(credentials: Credentials): List<QueryId> = value.filter { it !in credentials.ids }

    override fun toString(): String = value.toString()

    companion object {

        fun List<QueryId>.ensureValid() {
            ensureNotEmpty()
            ensureUniqueIds()
        }

        private fun List<QueryId>.ensureNotEmpty() {
            require(isNotEmpty()) { "${OpenId4VPSpec.DCQL_OPTIONS} elements cannot be empty" }
        }

        private fun List<QueryId>.ensureUniqueIds() {
            val uniqueIds = map { it.value }.toSet()
            require(uniqueIds.size == size) {
                "Within a CredentialSet, the same credential query id MUST NOT be present more than once"
            }
        }
    }
}

@Serializable
@JvmInline
value class ClaimId(val value: String) : java.io.Serializable {
    init {
        DCQLId.ensureValid(value)
    }

    override fun toString(): String = value
}

@Serializable
data class ClaimsQuery(
    @SerialName(OpenId4VPSpec.DCQL_ID) val id: ClaimId? = null,
    @Required @SerialName(OpenId4VPSpec.DCQL_PATH) val path: ClaimPath,
    @SerialName(OpenId4VPSpec.DCQL_VALUES) val values: JsonArray? = null,
    @SerialName(OpenId4VPSpec.DCQL_MSO_MDOC_INTENT_TO_RETAIN) override val intentToRetain: Boolean? = null,
) : MsoMdocClaimsQueryExtension, java.io.Serializable {

    init {
        values?.ensureContainsOnlyPrimitives()
    }

    companion object {
        fun sdJwtVc(
            id: ClaimId? = null,
            path: ClaimPath,
            values: JsonArray? = null,
        ): ClaimsQuery = ClaimsQuery(id, path, values, null)

        fun mdoc(
            id: ClaimId? = null,
            path: ClaimPath,
            values: JsonArray? = null,
            intentToRetain: Boolean? = null,
        ): ClaimsQuery = ClaimsQuery(id, path, values, intentToRetain).also { ensureMsoMdoc(it) }

        fun mdoc(
            id: ClaimId? = null,
            namespace: String,
            claimName: String,
            values: JsonArray? = null,
            intentToRetain: Boolean? = null,
        ): ClaimsQuery = mdoc(id, ClaimPath.claim(namespace).claim(claimName), values, intentToRetain)

        fun ensureMsoMdoc(claimsQuery: ClaimsQuery) {
            require(2 == claimsQuery.path.value.size) {
                "ClaimPaths for MSO MDoc based formats must have exactly two elements"
            }
            require(claimsQuery.path.value.all { it is ClaimPathElement.Claim }) {
                "ClaimPaths for MSO MDoc based formats must contain only Claim ClaimPathElements"
            }
        }

        fun ensureNotMsoMdoc(claimsQuery: ClaimsQuery) {
            require(null == claimsQuery.intentToRetain) {
                "'${OpenId4VPSpec.DCQL_MSO_MDOC_INTENT_TO_RETAIN}' can be used only with MSO MDoc based formats"
            }
        }

        fun JsonArray.ensureContainsOnlyPrimitives() {
            val nonPrimitiveElements = mapIndexedNotNull { index, jsonElement ->
                if (jsonElement !is JsonPrimitive || jsonElement == JsonNull) {
                    index
                } else null
            }
            require(nonPrimitiveElements.isEmpty()) {
                "${OpenId4VPSpec.DCQL_VALUES} should contain only primitive, non-null, elements. Violations at $nonPrimitiveElements"
            }
        }
    }
}

//
// SD-JWT-VC
//

@Serializable
data class DCQLMetaSdJwtVcExtensions(
    /**
     * Specifies allowed values for the type of the requested Verifiable Credential.
     * All elements in the array MUST be valid type identifiers.
     * The Wallet may return credentials that inherit from any of the specified types
     */
    @SerialName(OpenId4VPSpec.DCQL_SD_JWT_VC_VCT_VALUES) @Required val vctValues: List<String>,

) : java.io.Serializable {
    init {
        require(vctValues.isNotEmpty()) { "${OpenId4VPSpec.DCQL_SD_JWT_VC_VCT_VALUES} cannot be empty" }
        require(vctValues.all { it.isNotBlank() }) { "${OpenId4VPSpec.DCQL_SD_JWT_VC_VCT_VALUES} cannot contain blank values" }
    }
}

//
//
//  MSO_MDOC
//

@Serializable
@JvmInline
value class MsoMdocDocType(val value: String) : java.io.Serializable {
    init {
        require(value.isNotBlank()) { "Doctype can't be blank" }
    }

    override fun toString(): String = value
}

/**
 * The following is an ISO mdoc specific parameter in the [meta parameter][CredentialQuery.meta]
 */
@Serializable
data class DCQLMetaMsoMdocExtensions(

    /**
     * Specifies an allowed value for the doctype of the requested Verifiable Credential.
     * It MUST be a valid doctype identifier as defined
     */
    @SerialName(OpenId4VPSpec.DCQL_MSO_MDOC_DOCTYPE_VALUE) @Required val doctypeValue: MsoMdocDocType,
) : java.io.Serializable

/**
 * The following are ISO mdoc specific parameters to be used in a [Claims Query][ClaimsQuery]
 */
interface MsoMdocClaimsQueryExtension : java.io.Serializable {

    /**
     * OPTIONAL. A boolean that is equivalent to IntentToRetain variable defined in Section 8.3.2.1.2.1 of [ISO.18013-5].
     */
    @SerialName(OpenId4VPSpec.DCQL_MSO_MDOC_INTENT_TO_RETAIN)
    val intentToRetain: Boolean?
}

internal object DCQLId {
    const val REGEX: String = "^[a-zA-Z0-9_-]+$"
    fun ensureValid(value: String): String {
        require(value.isNotEmpty()) { "Value cannot be be empty" }
        require(REGEX.toRegex().matches(value)) {
            "The value must be a non-empty string consisting of alphanumeric, underscore (_) or hyphen (-) characters"
        }
        return value
    }
}
