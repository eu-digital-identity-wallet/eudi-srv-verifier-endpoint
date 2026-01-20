# Verifier 

## Use Cases 

* Initiate Presentation
* Retrieve Request Object 
* Retrieve Presentation Definition
* Send Presentation

### Initiate Presentation

Actors: 

* Developer/Tester
* Verifier app

Intention: To Provide a presentation definition in order to initiate a `Presentation Process`.

Steps:

1. Tester provides a Presentation Definition (in JSON) and hits `Initiate Presentation` button
2. Back-ends gets the Presentation Definition, validates it and initiates `Presentation Process`
3. Back-end identifies each `Presentation Process` in terms of a UUID
4. Back-end stores (in memory) the `Presentation Process` 
5. Back-end returns to UI a `AutherizationRequest` which is actually object with two attributes
   1. client_id (just a fixed string value, for now) and
   2. request_uri : A URL encoded URL pointing to `request_uri` end point. This URL (the request_uri) will have to include somehow (path variable, query variable etc) the UUID of the `Presentation Process`
6. Finally the UI draws either a QR code and/or a deep link for the `AuthorizationRequest`.

For details on AuthorizationRequest using request_uri please check [JAR](https://www.rfc-editor.org/rfc/rfc9101.html)


### Retrieve Request Object (request_uri protocol end-point)

This is defined in [JAR](https://www.rfc-editor.org/rfc/rfc9101.html)


Actors: Wallet, Verifier (back-end)
Intention: Wallet wants to retrieve the Request Object. 

This `RequestObject` is actually a JWT which includes (as claims) the
parameters of an OpenID4VP AuthorizationRequest (actually of any OAUTH2 authorization request)

Preconditions:

* Wallet has been informed about the URL of the request_uri (using QR or deep link)

Steps: 

1. Wallets sends a HTTP Get to the `request_uri` end point 
2. Verifiers extracts from the call the UUID of the `PresentationProcess`  and checks its repo to locate the process.
3. if found should return a `RequestObject` as defined in JAR with a HTTP 200

### Retrieve Presentation Definition (presentation_definition_uri protocol end-point)

This is defined in OpenID4VP protocol

Actors: Wallet, Verifier (back-end)
Intention: Wallet wants to get the `PresentationDefinition` from the Verifier

Preconditions:

* Wallet has received the `RequestObject` and this includes a `presentation_definition_uri`. This URL should somehow include the UUID of the `PresentationProcess` (path or query param)

Steps:

1. Wallet sends a HTTP Get to the `presentation_definition_uri`
2. Verifiers extracts from the call the UUID of the `PresentationProcess`  and checks its repo to locate the process
3. if found should return a `PresentationDefinition` in JSON as defined with HTTP 200

### Send Presentation (`direct-post.jwt protocol end-point)

This is defined in OpenID4VP protocol.

Actors: Wallet, Verifier (back-end)
Intention: Wallet wants to send to the Verifier his response which include the Verifiable Presentations

TBD