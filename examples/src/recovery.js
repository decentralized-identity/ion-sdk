// Example on how to deactivate a DID
(async () => {
  const IonSdk = require('@decentralized-identity/ion-sdk');
  const ION = require('@decentralized-identity/ion-tools');
  const request = require('request');
  const util = require('util');
  const requestPromise = util.promisify(request);

  // const nodeURL = 'http://localhost:3000';
  const nodeURL = 'https://testnet.sidetree-cardano.com/cardano';

  // You need the DID suffix
  const didSuffix = 'EiBxybhTu8_RJJzmL07edduRbt6wqHCuwvW4lM2wKuy3Fw';

  // You need your recovery key generated when creating the DID
  const recoveryKey = {
    publicJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      x: 'sCIL-0AR8Emnso1VY1Iz7J1X7aj2-K6jmTfYm5LskdA',
      y: 'bmzZtB3FtvXEnbD_rIWhGNrxfNCPGnrUDYyyFvJqOsE'
    },
    privateJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      d: 'jHg89tnJX6dKs4r9TyQ2WZtT5-ylJLwyhgFolYpiBm4',
      x: 'sCIL-0AR8Emnso1VY1Iz7J1X7aj2-K6jmTfYm5LskdA',
      y: 'bmzZtB3FtvXEnbD_rIWhGNrxfNCPGnrUDYyyFvJqOsE'
    }
  };

  // Generate a new update key
  // Should be stored somewhere, you'll need it later for your proofs
  const newUpdateKey = await ION.generateKeyPair('secp256k1'); // also supports Ed25519
  console.log('Your new updaate key:');
  console.log(newUpdateKey);

  // You need to regenerate or reuse all keys used in the DID document
  const authKeys = {
    publicJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      x: 'cazusMNVpXe523nqv43SGn-4BXbx2jujhH9GdJWnPLA',
      y: 'EqydSU2Hxk9MzNNbBOxwVGDHhS_UcaRbTDOazspvH-Y'
    },
    privateJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      d: 'Ds7VNZqtXmc3NdWUVY7LScjPa258O1FCCtRKrX26lAA',
      x: 'cazusMNVpXe523nqv43SGn-4BXbx2jujhH9GdJWnPLA',
      y: 'EqydSU2Hxk9MzNNbBOxwVGDHhS_UcaRbTDOazspvH-Y'
    }
  };

  // Recreate you W3C DID document
  const didDocument = {
    publicKeys: [
      {
        id: 'key-1',
        type: 'EcdsaSecp256k1VerificationKey2019',
        publicKeyJwk: authKeys.publicJwk,
        purposes: ['authentication']
      }
    ],
    services: [
      {
        id: 'domain-1',
        type: 'LinkedDomains',
        serviceEndpoint: 'https://foo.example.com'
      }
    ]
  };

  // Create the recovery request body ready to be posted in /operations of Sidetree API
  const recoveryRequest = await IonSdk.IonRequest.createRecoverRequest({
    didSuffix: didSuffix,
    signer: IonSdk.LocalSigner.create(recoveryKey.privateJwk),
    recoveryPublicKey: recoveryKey.publicJwk,
    nextRecoveryPublicKey: recoveryKey.publicJwk, // recommended to change recovery key
    nextUpdatePublicKey: newUpdateKey.publicJwk,
    document: didDocument
  });
  console.log('POST operation: ' + JSON.stringify(recoveryRequest));

  // POST recovery boddy to Sidetree-Cardano node API
  const resp = await requestPromise({
    url: nodeURL + '/operations',
    method: 'POST',
    body: JSON.stringify(recoveryRequest)
  });
  console.log(resp.statusMessage);

})();
