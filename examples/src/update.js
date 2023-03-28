/** Example on how to update a DID */
(async () => {
  const randomBytes = require('randombytes');
  const ed25519 = require('@transmute/did-key-ed25519');
  const secp256k1 = require('@transmute/did-key-secp256k1');
  const IonSdk = require('@decentralized-identity/ion-sdk');
  const request = require('request');
  const util = require('util');
  const requestPromise = util.promisify(request);

  // const nodeURL = 'http://localhost:3000';
  const nodeURL = 'https://testnet.sidetree-cardano.com/cardano';

  // You need the DID suffix
  const didSuffix = 'EiBxybhTu8_RJJzmL07edduRbt6wqHCuwvW4lM2wKuy3Fw';

  // You need the update private key generated when creating the DID
  const updateKey = {
    publicJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      x: '_5O3aMu92QVDucDWaFiu6xaEnkByG2SYMspeIWCOSUU',
      y: 'SJql7lhWHzoJY7fJvdxpOcCC2JMMnAnugYM9Gskm6q4'
    },
    privateJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      d: '-WRKIVPdrhTz2CPhlc7LCnOMVlHFavdJtLWgZx4JEf8',
      x: '_5O3aMu92QVDucDWaFiu6xaEnkByG2SYMspeIWCOSUU',
      y: 'SJql7lhWHzoJY7fJvdxpOcCC2JMMnAnugYM9Gskm6q4'
    }
  };

  // Generate a new authentication key to be updated in the W3C DID document for this example
  // Should be stored somewhere, you'll need it later in for your proofs
  const newAuthnKeys = await generateKeyPair('secp256k1'); // also supports Ed25519
  console.log('Your new DID authentication key:');
  console.log(newAuthnKeys);

  // Create the update operation. In this exaample we update the authorization key and services
  const updateOperation = {
    didSuffix: didSuffix,
    idsOfPublicKeysToRemove: ['key-1'],
    publicKeysToAdd: [
      {
        id: 'key-2',
        type: 'EcdsaSecp256k1VerificationKey2019',
        publicKeyJwk: newAuthnKeys.publicJwk,
        purposes: ['authentication']
      }
    ],
    idsOfServicesToRemove: ['domain-1'],
    servicesToAdd: [{
      id: 'some-service-2',
      type: 'SomeServiceType',
      serviceEndpoint: 'http://www.example.com'
    }]
  };

  // Create the update request body ready to be posted in /operations of Sidetree API
  const updateRequest = await IonSdk.IonRequest.createUpdateRequest({
    didSuffix: updateOperation.didSuffix,
    updatePublicKey: updateKey.publicJwk,
    nextUpdatePublicKey: updateKey.publicJwk, // it's recommended to change that key on each update
    signer: IonSdk.LocalSigner.create(updateKey.privateJwk),
    idsOfServicesToRemove: updateOperation.idsOfServicesToRemove,
    servicesToAdd: updateOperation.servicesToAdd,
    idsOfPublicKeysToRemove: updateOperation.idsOfPublicKeysToRemove,
    publicKeysToAdd: updateOperation.publicKeysToAdd
  });
  console.log('POST operation: ' + JSON.stringify(updateRequest));

  // POST the update boddy to Sidetree-Cardano node API
  const resp = await requestPromise({
    url: nodeURL + '/operations',
    method: 'POST',
    body: JSON.stringify(updateRequest)
  });
  console.log(resp.statusMessage);

  // Helper function to generate keys
  // You can use your prefered key generator
  // type: secp256k1 | Ed25519
  async function generateKeyPair (type) {
    let keyGenerator = secp256k1.Secp256k1KeyPair;
    if (type === 'Ed25519') { keyGenerator = ed25519.Ed25519KeyPair; };
    const keyPair = await keyGenerator.generate({
      secureRandom: () => randomBytes(32)
    });
    const { publicKeyJwk, privateKeyJwk } = await keyPair.toJsonWebKeyPair(true);
    return {
      publicJwk: publicKeyJwk,
      privateJwk: privateKeyJwk
    };
  }

})();
