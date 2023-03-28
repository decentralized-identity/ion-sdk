# Step by step tutorial to operate with DIDs
This tutorial will guide you through the process of creating, resolving and updating DID using the sample code provided in this folder.

## Environment
Code is written in JavaScript, so you'll need to have node installed.
You can run your own sidetree node following the instruction given on [README.md](https://github.com/rodolfomiranda/sidetree-cardano/blob/master/README.md). Or you can use a testnet node deployed at `testnet.sidetree-cardano.com`.
In the code samples, uncomment the correct `nodeURL`:
- If you run the node: `const nodeURL = 'http://localhost:3000';`
- If you use the cloud node: `const nodeURL = 'https://testnet.sidetree-cardano.com/cardano';`

## Create your DID
Firt things first, you need to create a DID. Just run:
`node create.js`
and will return something like this:
```
Your update key:
{
  publicJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    x: 'ljka_gbBFyIelE3yMDY1lUUPwukDj7f58k7jGN9muhI',
    y: 'xGQN4VrnDTy6mMAO-kPp2qtqOcZIfoiNMRbgqZB6Qkc'
  },
  privateJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    d: 'LmCStJ7s05Oc75zWDX0mTUMzUZKXNJUcBFmnFfxIL_I',
    x: 'ljka_gbBFyIelE3yMDY1lUUPwukDj7f58k7jGN9muhI',
    y: 'xGQN4VrnDTy6mMAO-kPp2qtqOcZIfoiNMRbgqZB6Qkc'
  }
}
Your recovery key:
{
  publicJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    x: 'S4KEaZYlYLtKUG3YOnMJ-oYzv11A156KyZf3DutHV20',
    y: 'tkE42HNNlWOauPHSb8VpY5Wnn_ZiloDABWSk0oChQg8'
  },
  privateJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    d: 'SQuKOsHzkS71acE3JiRatjKLdaEwxmP8_ZAfeahzUek',
    x: 'S4KEaZYlYLtKUG3YOnMJ-oYzv11A156KyZf3DutHV20',
    y: 'tkE42HNNlWOauPHSb8VpY5Wnn_ZiloDABWSk0oChQg8'
  }
}
Your DID authentication key:
{
  publicJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    x: 'MBo4ZHApb8vfzzNXj673BRE5F2RouBhJGqzqtgiiB1g',
    y: 'IENiXjOJt-TOJJvvTq0UaENrk76qH4U4LUKhM0rdbxk'
  },
  privateJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    d: '1dfSeK5CUzggXsJTpZZmyRxacTOXcd8t1ORwqsYeZVk',
    x: 'MBo4ZHApb8vfzzNXj673BRE5F2RouBhJGqzqtgiiB1g',
    y: 'IENiXjOJt-TOJJvvTq0UaENrk76qH4U4LUKhM0rdbxk'
  }
}
POST operation: {"type":"create","suffixData":{"deltaHash":"EiB1UBzS_O3OINjBub3QB549QHMdhHvQspvfdZwwWOgAsA","recoveryCommitment":"EiCqoMGfQKKmaxONsAoBuxUuPpMXrqnQ4Jv0dmwaMl1WWQ"},"delta":{"updateCommitment":"EiAWGSlddbHJReo2sOD-0-RM1ChgEtEAc1HOFqNtdyHo6g","patches":[{"action":"replace","document":{"publicKeys":[{"id":"key-1","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"kty":"EC","crv":"secp256k1","x":"MBo4ZHApb8vfzzNXj673BRE5F2RouBhJGqzqtgiiB1g","y":"IENiXjOJt-TOJJvvTq0UaENrk76qH4U4LUKhM0rdbxk"},"purposes":["authentication"]}],"services":[{"id":"domain-1","type":"LinkedDomains","serviceEndpoint":"https://foo.example.com"}]}}]}}
{"@context":"https://w3id.org/did-resolution/v1","didDocument":{"id":"did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ","@context":["https://www.w3.org/ns/did/v1",{"@base":"did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ"}],"service":[{"id":"#domain-1","type":"LinkedDomains","serviceEndpoint":"https://foo.example.com"}],"verificationMethod":[{"id":"#key-1","controller":"","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"kty":"EC","crv":"secp256k1","x":"MBo4ZHApb8vfzzNXj673BRE5F2RouBhJGqzqtgiiB1g","y":"IENiXjOJt-TOJJvvTq0UaENrk76qH4U4LUKhM0rdbxk"}}],"authentication":["#key-1"]},"didDocumentMetadata":{"method":{"published":false,"recoveryCommitment":"EiCqoMGfQKKmaxONsAoBuxUuPpMXrqnQ4Jv0dmwaMl1WWQ","updateCommitment":"EiAWGSlddbHJReo2sOD-0-RM1ChgEtEAc1HOFqNtdyHo6g"},"canonicalId":"did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ"}}
Your generated DID: did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ
```
Too much information. Let's explore it:

Firstly, you need to generate two keys that will be used in all operations regarding your DID: **update key and recovery key**.

In the code, you can generate *secp256k1* or *ed25519* private and public key pairs with a library from Transmute, but you can use your preferred library. The most important thing is that you must keep  those two keyspairs secured since they will be needed for all operations. They prove that your are the owner of the DID, and hence the owner of all credentials received for that DID.

Secondly, you need to create your DID document that conforms with W3C DID v1 specification. In there, you will include all required and optional properties, as in this case we included the authentication keys with a service endopoint. For that reason, we also had to generate the authentication keypair (and keep it safe!!).

The resulting execution log shows the three generated private and public keys pairs:
```
Your update key:
{
  publicJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    x: 'ljka_gbBFyIelE3yMDY1lUUPwukDj7f58k7jGN9muhI',
    y: 'xGQN4VrnDTy6mMAO-kPp2qtqOcZIfoiNMRbgqZB6Qkc'
  },
  privateJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    d: 'LmCStJ7s05Oc75zWDX0mTUMzUZKXNJUcBFmnFfxIL_I',
    x: 'ljka_gbBFyIelE3yMDY1lUUPwukDj7f58k7jGN9muhI',
    y: 'xGQN4VrnDTy6mMAO-kPp2qtqOcZIfoiNMRbgqZB6Qkc'
  }
}
Your recovery key:
{
  publicJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    x: 'S4KEaZYlYLtKUG3YOnMJ-oYzv11A156KyZf3DutHV20',
    y: 'tkE42HNNlWOauPHSb8VpY5Wnn_ZiloDABWSk0oChQg8'
  },
  privateJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    d: 'SQuKOsHzkS71acE3JiRatjKLdaEwxmP8_ZAfeahzUek',
    x: 'S4KEaZYlYLtKUG3YOnMJ-oYzv11A156KyZf3DutHV20',
    y: 'tkE42HNNlWOauPHSb8VpY5Wnn_ZiloDABWSk0oChQg8'
  }
}
Your DID authentication key:
{
  publicJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    x: 'MBo4ZHApb8vfzzNXj673BRE5F2RouBhJGqzqtgiiB1g',
    y: 'IENiXjOJt-TOJJvvTq0UaENrk76qH4U4LUKhM0rdbxk'
  },
  privateJwk: {
    kty: 'EC',
    crv: 'secp256k1',
    d: '1dfSeK5CUzggXsJTpZZmyRxacTOXcd8t1ORwqsYeZVk',
    x: 'MBo4ZHApb8vfzzNXj673BRE5F2RouBhJGqzqtgiiB1g',
    y: 'IENiXjOJt-TOJJvvTq0UaENrk76qH4U4LUKhM0rdbxk'
  }
}
```

Then, we need to generate a `create` body of the operation that will be submitted to sidetree node. We use [ion-sdk](https://github.com/decentralized-identity/ion-sdk) provided by the Decentralized Identity Foundation that help with that matter. The operation body looks like this:
```
{
   "type":"create",
   "suffixData":{
      "deltaHash":"EiB1UBzS_O3OINjBub3QB549QHMdhHvQspvfdZwwWOgAsA",
      "recoveryCommitment":"EiCqoMGfQKKmaxONsAoBuxUuPpMXrqnQ4Jv0dmwaMl1WWQ"
   },
   "delta":{
      "updateCommitment":"EiAWGSlddbHJReo2sOD-0-RM1ChgEtEAc1HOFqNtdyHo6g",
      "patches":[
         {
            "action":"replace",
            "document":{
               "publicKeys":[
                  {
                     "id":"key-1",
                     "type":"EcdsaSecp256k1VerificationKey2019",
                     "publicKeyJwk":{
                        "kty":"EC",
                        "crv":"secp256k1",
                        "x":"MBo4ZHApb8vfzzNXj673BRE5F2RouBhJGqzqtgiiB1g",
                        "y":"IENiXjOJt-TOJJvvTq0UaENrk76qH4U4LUKhM0rdbxk"
                     },
                     "purposes":[
                        "authentication"
                     ]
                  }
               ],
               "services":[
                  {
                     "id":"domain-1",
                     "type":"LinkedDomains",
                     "serviceEndpoint":"https://foo.example.com"
                  }
               ]
            }
         }
      ]
   }
}
```

Finally, the generated body is POSTed to the `/operations` method of the sidetree node, resulting in:
```
{
   "@context":"https://w3id.org/did-resolution/v1",
   "didDocument":{
      "id":"did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ",
      "@context":[
         "https://www.w3.org/ns/did/v1",
         {
            "@base":"did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ"
         }
      ],
      "service":[
         {
            "id":"#domain-1",
            "type":"LinkedDomains",
            "serviceEndpoint":"https://foo.example.com"
         }
      ],
      "verificationMethod":[
         {
            "id":"#key-1",
            "controller":"",
            "type":"EcdsaSecp256k1VerificationKey2019",
            "publicKeyJwk":{
               "kty":"EC",
               "crv":"secp256k1",
               "x":"MBo4ZHApb8vfzzNXj673BRE5F2RouBhJGqzqtgiiB1g",
               "y":"IENiXjOJt-TOJJvvTq0UaENrk76qH4U4LUKhM0rdbxk"
            }
         }
      ],
      "authentication":[
         "#key-1"
      ]
   },
   "didDocumentMetadata":{
      "method":{
         "published":false,
         "recoveryCommitment":"EiCqoMGfQKKmaxONsAoBuxUuPpMXrqnQ4Jv0dmwaMl1WWQ",
         "updateCommitment":"EiAWGSlddbHJReo2sOD-0-RM1ChgEtEAc1HOFqNtdyHo6g"
      },
      "canonicalId":"did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ"
   }
}
```
The `id` of the document shows your newly created DID:
`did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ`

## Resolve your DID into a DID Document
Sidetree-Cardano writes sidetree documents in the ledger as transaction metadata. The block that holds the transaction takes some time to be mint and more time to be confirmed as a valid block. So, just after a few minutes you will be ready to retrieve (resolve) your DID document:

DID resolution is a simple GET request to `/identifiers/{did}`. You can use the code provided in `resolve.js` or just execute a simple `curl` from your bash terminal:

`curl https://testnet.sidetree-cardano.com/identifiers/did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ`
```
{
   "@context":"https://w3id.org/did-resolution/v1",
   "didDocument":{
      "id":"did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ",
      "@context":[
         "https://www.w3.org/ns/did/v1",
         {
            "@base":"did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ"
         }
      ],
      "service":[
         {
            "id":"#domain-1",
            "type":"LinkedDomains",
            "serviceEndpoint":"https://foo.example.com"
         }
      ],
      "verificationMethod":[
         {
            "id":"#key-1",
            "controller":"",
            "type":"EcdsaSecp256k1VerificationKey2019",
            "publicKeyJwk":{
               "kty":"EC",
               "crv":"secp256k1",
               "x":"MBo4ZHApb8vfzzNXj673BRE5F2RouBhJGqzqtgiiB1g",
               "y":"IENiXjOJt-TOJJvvTq0UaENrk76qH4U4LUKhM0rdbxk"
            }
         }
      ],
      "authentication":[
         "#key-1"
      ]
   },
   "didDocumentMetadata":{
      "method":{
         "published":true,
         "recoveryCommitment":"EiCqoMGfQKKmaxONsAoBuxUuPpMXrqnQ4Jv0dmwaMl1WWQ",
         "updateCommitment":"EiAWGSlddbHJReo2sOD-0-RM1ChgEtEAc1HOFqNtdyHo6g"
      },
      "canonicalId":"did:ada:EiDfLfmqWKLEgbALdWg2jj3m8LFbfFSwPdee6JvFE5VfTQ"
   }
}
```
Lovely. You got the DID document with all your **public** identity information!!

## Update your DID document


## Recovery and Deactivate

