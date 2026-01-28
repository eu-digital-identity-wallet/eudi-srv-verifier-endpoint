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

/**
 * Remote Qualified Electronic Signature
 */
object RQES {

    const val SIGNATURE_QUALIFIER_EU_EIDAS_QES = "eu_eidas_qes"
    const val SIGNATURE_QUALIFIER_EU_EIDAS_AES = "eu_eidas_aes"
    const val SIGNATURE_QUALIFIER_EU_EIDAS_AES_QC = "eu_eidas_aesqc"
    const val SIGNATURE_QUALIFIER_EU_EIDAS_QE_SEAL = "eu_eidas_qeseal"
    const val SIGNATURE_QUALIFIER_EU_EIDAS_AE_SEAL = "eu_eidas_aeseal"
    const val SIGNATURE_QUALIFIER_EU_EIDAS_AE_SEAL_QC = "eu_eidas_aesealqc"
    const val SIGNATURE_QUALIFIER_ZA_ECTA_AES = "za_ecta_aes"
    const val SIGNATURE_QUALIFIER_ZA_ECTA_OES = "za_ecta_oes"

    const val ACCESS_MODE_PUBLIC = "public"
    const val ACCESS_MODE_OTP = "OTP"
    const val ACCESS_MODE_BASIC_AUTHENTICATION = "Basic_Auth"
    const val ACCESS_MODE_DIGEST_AUTHENTICATION = "Digest_Auth"
    const val ACCESS_MODE_OAUTH20 = "OAuth_20"

    const val DOCUMENT_ACCESS_METHOD_ACCESS_MODE = "document_access_mode"
    const val DOCUMENT_ACCESS_METHOD_OTP = "oneTimePassword"

    const val DOCUMENT_DIGEST_LABEL = "label"
    const val DOCUMENT_DIGEST_HASH = "hash"
    const val DOCUMENT_DIGEST_HASH_ALGORITHM = "hashAlgorithmOID"
    const val DOCUMENT_DIGEST_DOCUMENT_LOCATION_URI = "documentLocation_uri"
    const val DOCUMENT_DIGEST_DOCUMENT_LOCATION_METHOD = "documentLocation_method"
    const val DOCUMENT_DIGEST_DATA_TO_BE_SIGNED_REPRESENTATION = "DTBS/R"
    const val DOCUMENT_DIGEST_DATA_TO_BE_SIGNED_REPRESENTATION_HASH_ALGORITHM = "DTBS/RHashAlgorithmOID"

    const val TYPE_QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION = "qes_authorization"
    const val QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER = "signatureQualifier"
    const val QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_CREDENTIAL_ID = "credentialID"
    const val QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_DOCUMENT_DIGESTS = "documentDigests"
    const val QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_PROCESS_ID = "processID"

    const val TYPE_QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE = "qcert_creation_acceptance"
    const val QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE_TERM_AND_CONDITIONS_URI = "QC_terms_conditions_uri"
    const val QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE_HASH = "QC_hash"
    const val QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE_HASH_ALGORITHM = "QC_hashAlgorithmOID"
}
