- `.well-known/smart-configuration` and the RFC 8414 metadata name the EHR
  launch API as `launch_registration_endpoint` (`{issuer}/launch`) whenever
  the app launch is configured, so an EHR reads it from the documents
  instead of building the path (#657).
