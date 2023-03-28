/** Example on how to deactivate a DID */
(async () => {
  const IonSdk = require('@decentralized-identity/ion-sdk');
  const request = require('request');
  const util = require('util');
  const requestPromise = util.promisify(request);

  // const nodeURL = 'http://localhost:3000';
  const nodeURL = 'https://testnet.sidetree-cardano.com/cardano';

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

  // Create the deactivate request body ready to be posted in /operations of Sidetree API
  const deactivateRequest = await IonSdk.IonRequest.createDeactivateRequest({
    didSuffix: 'EiBNEmIolaIKXiyrmC58UoaCYzaD0q1FvXOcX2di-6isdg',
    recoveryPublicKey: recoveryKey.publicJwk,
    signer: IonSdk.LocalSigner.create(recoveryKey.privateJwk)
  });
  console.log('POST operation: ' + JSON.stringify(deactivateRequest));

  // POST boddy to Sidetree-Cardano node API
  const resp = await requestPromise({
    url: nodeURL + '/operations',
    method: 'POST',
    body: JSON.stringify(deactivateRequest)
  });
  console.log(resp.statusMessage);

})();
