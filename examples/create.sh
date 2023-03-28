curl -v -X 'POST' \
  'http://localhost:3000/operations' \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d '{
  "type": "create",
  "suffix_data": "{
    "deltaHash": "EiAzwUc_XV4JvM-822FFzsZb3uoVhSNftm07JOg4Qf5Y8g",
    "recoveryCommitment": "EiDqaQ5q6DtQ4IqIp-zuMTl0z2-wsugvPVUjt4dSX4ZzZQ"
  }",
  "delta": "{
    "updateCommitment": "EiCMSgdsr8kqNCVl220dPudRNjS4bTAfDegUAldVijUnBQ",
    "patches": [
      {
        "action": "replace",
        "document": {
          "publicKeys": [
            {
              "id": "key-02",
              "type": "EcdsaSecp256k1VerificationKey2019",
              "publicKeyJwk": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "obG_vqK1rlk6iME7-YGRrz9Onb3J2geQx_wyj5kxF2Q",
                "y": "myCKHtpK2Heyh9gquPLjPsD9ni9_76_kbf1sTP_Lt34"
              },
              "purposes": [
                "authentication"
              ]
            }
          ],
          "services": [
            {
              "id": "domain-02",
              "type": "LinkedDomains",
              "serviceEndpoint": "https://test.example.com"
            }
          ]
        }
      }
    ]
  }"
}'
