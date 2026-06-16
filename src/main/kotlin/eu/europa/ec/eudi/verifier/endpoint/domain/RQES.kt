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
    const val DOCUMENT_DIGEST_HASH_TYPE = "hashType"
    const val DOCUMENT_DIGEST_SIGNED_PROPERTIES = "signed_props"
    const val DOCUMENT_DIGEST_CIRCUMSTANTIAL_DATA = "circumstantialData"

    const val TYPE_QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION = "https://cloudsignatureconsortium.org/2025/qes-approval"
    const val TYPE_QUALIFIED_ELECTRONIC_SIGNATURE_REQUEST = "https://cloudsignatureconsortium.org/2025/qes"
    const val QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER = "signatureQualifier"
    const val QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_CREDENTIAL_ID = "credentialID"
    const val QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_DOCUMENT_DIGESTS = "documentDigests"

    const val ACCESS_CONTROL_METHOD_TYPE = "type"
    const val ATTRIBUTE_ATTRIBUTE_NAME = "name"
    const val ATTRIBUTE_ATTRIBUTE_VALUE = "value"

    const val SIGNATURE_CREATION_APPROVAL_NUMBER_OF_SIGNATURES = "numSignatures"
    const val SIGNATURE_CREATION_APPROVAL_HASH_ALGORITHM_OID = "hashAlgorithmOID"

    const val SIGNATURE_REQUEST_RESPONSE_URI = "responseURI"

    const val ADES_PARAMETERS_SIGNATURE_FORMAT = "signature_format"
    const val ADES_PARAMETERS_SIGNATURE_CONFORMANCE_LEVEL = "conformance_level"
    const val ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY = "signed_envelope_property"
    const val ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_DETACHED = "Detached"
    const val ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ATTACHED = "Attached"
    const val ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_PARALLEL = "Parallel"
    const val ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ENVELOPED = "Enveloped"
    const val ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ENVELOPING = "Enveloping"
    const val ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_CERTIFICATION = "Certification"
    const val ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_REVISION = "Revision"
    const val ADES_PARAMETERS_SIGNATURE_SIGNED_PROPERTIES = "signed_props"
    const val ADES_PARAMETERS_SIGNATURE_REFERENCE_URI = "referenceUri"

    const val SIGNING_ALGORITHM_SIGN_ALGO = "signAlgo"
    const val SIGNING_ALGORITHM_SIGN_ALGO_PARAMS = "signAlgoParams"

    const val REQUESTS_SIGNATURE_REQUESTS = "signatureRequests"
    const val DOCUMENTS_DOCUMENT_REFERENCE_LABEL = "label"
    const val DOCUMENTS_DOCUMENT_REFERENCE_HREF = "href"
    const val DOCUMENTS_DOCUMENT_REFERENCE_ACCESS = "access"
    const val DOCUMENTS_DOCUMENT_REFERENCE_CHECKSUM = "checksum"
    const val DOCUMENTS_DOCUMENT_REFERENCE_HASH_VALUE = "value"
    const val DOCUMENTS_DOCUMENT_REFERENCE_HASH_ALGORITHM_OID = "algorithmOID"
    const val DOCUMENTS_DOCUMENT_REFERENCE_CIRCUMSTANTIAL_DATA = "circumstantialData"

    const val DOCUMENTS_DOCUMENT_DATA_LABEL = "label"
    const val DOCUMENTS_DOCUMENT_DATA_DOCUMENT = "document"
    const val DOCUMENTS_DOCUMENT_DATA_DOCUMENT_TYPE = "documentType"
    const val DOCUMENTS_DOCUMENT_DATA_CIRCUMSTANTIAL_DATA = "circumstantialData"

    const val DOCUMENTS_DOCUMENT_TYPE_SOD = "sod"
    const val DOCUMENTS_DOCUMENT_TYPE_SFD = "sfd"
}
