import { DID } from './did.js';
import {generateKeyPair} from './utils.js';
import { writeFile } from 'fs/promises';

// Generate keys and ION DID
let authnKeys = await generateKeyPair();
let did = new DID({
  content: {
    publicKeys: [
      {
        id: 'key-1',
        type: 'EcdsaSecp256k1VerificationKey2019',
        publicKeyJwk: authnKeys.publicJwk,
        purposes: [ 'authentication' ]
      }
    ],
    services: [
      {
        id: 'domain-1',
        type: 'LinkedDomains',
        serviceEndpoint: 'https://foo.example.com'
      }
    ]
  }
});

// Generate and publish create request to an ION node
// let createRequest = await did.generateRequest(0);
// let anchorResponse = await anchor(createRequest);

// Store the key material and source data of all operations that have been created for the DID
let didOps = await did.getAllOperations();
await writeFile('./ion-did-ops-v1.json', JSON.stringify({ ops: didOps }));

const longFormURI  = await did.getURI();
const shortFormURI = await did.getURI('short');


console.log(longFormURI);
console.log(shortFormURI);
