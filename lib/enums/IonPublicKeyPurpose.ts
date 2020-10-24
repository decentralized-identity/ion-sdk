/**
 * DID Document key purpose.
 */
enum IonPublicKeyPurpose {
  Authentication = 'authentication',
  AssertionMethod = 'assertionMethod',
  CapabilityInvocation = 'capabilityInvocation',
  CapabilityDelegation = 'capabilityDelegation',
  KeyAgreement = 'keyAgreement'
}

export default IonPublicKeyPurpose;
