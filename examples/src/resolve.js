/** Example on how to resolve a DID */
(async () => {
  const request = require('request');
  const util = require('util');
  const requestPromise = util.promisify(request);

  const nodeURL = 'http://localhost:3000';
  // const nodeURL = 'https://testnet.sidetree-cardano.com/cardano';

  // DID to resolve
  const did = 'did:ada:EiAaf8BXolZrMqSKZK_zTjfCKwFHO-WjLtW_avtXHtkJJg';

  // GET resolution from Sidetree-Cardano node
  // If you receive a did_not_found response, note that
  // it may take some time for the transaction to be confirmed
  // in the blockchain and validated by sidetree
  const resp = await requestPromise(nodeURL + '/identifiers/' + did);
  const respBody = JSON.parse(JSON.stringify(resp.body));
  console.log(respBody);

})();
