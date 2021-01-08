# Presentation Exchange

This document shows how to use [Presentation Exchange](https://identity.foundation/presentation-exchange) by examples.
Code examples can be found [here](example_test.go).

1. This example demonstrates `predicate` and `limit_disclosure` usage.
   The `presentation definition` below requires field `age` to be greater or equal to 18.
   Also, we have `limit_disclosure=true` which requires that output data is limited to the entries specified in the `fields` property.
   The `predicate` means that the result should be expressed as a boolean value.
```json
{
  "id": "31e2f0f1-6b70-411d-b239-56aed5321884",
  "purpose": "To sell you a drink we need to know that you are an adult.",
  "input_descriptors": [
    {
      "id": "867bfe7a-5b91-46b2-9ba4-70028b8d9cc8",
      "purpose": "Your age should be greater or equal to 18.",
      "schema": [
        {
          "uri": "https://www.w3.org/TR/vc-data-model/#types"
        }
      ],
      "constraints": {
        "limit_disclosure": true,
        "fields": [
          {
            "path": [
              "$.age"
            ],
            "filter": {
              "type": "integer",
              "minimum": 18
            },
            "predicate": "required"
          }
        ]
      }
    }
  ]
}
```
Let's say we have such a credential in our database.
```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "age": 21,
  "credentialSchema": [
    {
      "id": "https://www.w3.org/TR/vc-data-model/#types"
    }
  ],
  "first_name": "Jesse",
  "id": "2dc74354-e965-4883-be5e-bfec48bf60c7",
  "issuer": "",
  "last_name": "Pinkman",
  "type": "VerifiableCredential"
}
```
As a result, we will have the following `verifiable presentation`:
```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://identity.foundation/presentation-exchange/submission/v1"
  ],
  "presentation_submission": {
    "id": "accd5adf-1dbf-4ed9-9ba2-d687476126cb",
    "definition_id": "31e2f0f1-6b70-411d-b239-56aed5321884",
    "descriptor_map": [
      {
        "id": "867bfe7a-5b91-46b2-9ba4-70028b8d9cc8",
        "format": "ldp_vp",
        "path": "$.verifiableCredential[0]"
      }
    ]
  },
  "type": [
    "VerifiablePresentation",
    "PresentationSubmission"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1"
      ],
      "age": true,
      "credentialSchema": [
        {
          "id": "https://www.w3.org/TR/vc-data-model/#types"
        }
      ],
      "credentialSubject": null,
      "id": "2dc74354-e965-4883-be5e-bfec48bf60c7",
      "issuer": "",
      "type": "VerifiableCredential"
    }
  ]
}
```

As you can see the VP has a credential without `first_name` and `last_name` (because of `limit_disclosure`).
Also, instead of `age`, we have a boolean value (because of `predicate`).