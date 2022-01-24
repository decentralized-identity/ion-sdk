/**
 * ION SDK error codes.
 */
export default {
  DeltaExceedsMaximumSize: 'DeltaExceedsMaximumSize',
  DidDocumentPublicKeyIdDuplicated: 'DidDocumentPublicKeyIdDuplicated',
  DidDocumentPublicKeyMissingOrIncorrectType: 'DidDocumentPublicKeyMissingOrIncorrectType',
  DidDocumentServiceIdDuplicated: 'DidDocumentServiceIdDuplicated',
  DidSuffixIncorrectLength: 'DidSuffixIncorrectLength',
  EncodedStringIncorrectEncoding: 'EncodedStringIncorrectEncoding',
  IdNotUsingBase64UrlCharacterSet: 'IdNotUsingBase64UrlCharacterSet',
  IdTooLong: 'IdTooLong',
  JwkEs256kMissingOrInvalidCrv: 'JwkEs256kMissingOrInvalidCrv',
  JwkEs256kMissingOrInvalidKty: 'JwkEs256kMissingOrInvalidKty',
  JwkEs256kHasIncorrectLengthOfX: 'JwkEs256kHasIncorrectLengthOfX',
  JwkEs256kHasIncorrectLengthOfY: 'JwkEs256kHasIncorrectLengthOfY',
  JwkEs256kHasIncorrectLengthOfD: 'JwkEs256kHasIncorrectLengthOfD',
  JwkEd25519MissingOrInvalidCrv: 'JwkEd25519MissingOrInvalidCrv',
  JwkEd25519MissingOrInvalidKty: 'JwkEd25519MissingOrInvalidKty',
  JwkEd25519HasIncorrectLengthOfX: 'JwkEd25519HasIncorrectLengthOfX',
  JwkEd25519HasIncorrectLengthOfD: 'JwkEd25519HasIncorrectLengthOfD',
  MultihashStringNotAMultihash: 'MultihashStringNotAMultihash',
  MultihashUnsupportedHashAlgorithm: 'MultihashUnsupportedHashAlgorithm',
  PublicKeyJwkEd25519HasUnexpectedProperty: 'PublicKeyJwkEd25519HasUnexpectedProperty',
  PublicKeyJwkEs256kHasUnexpectedProperty: 'PublicKeyJwkEs256kHasUnexpectedProperty',
  PublicKeyPurposeDuplicated: 'PublicKeyPurposeDuplicated',
  ServiceEndpointCannotBeAnArray: 'ServiceEndpointCannotBeAnArray',
  ServiceEndpointStringNotValidUri: 'ServiceEndpointStringNotValidUri',
  ServiceTypeTooLong: 'ServiceTypeTooLong',
  UnsupportedKeyType: 'UnsupportedKeyType'
};
