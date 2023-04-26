/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

const (
	schemaV1 = `{
  "required": [
    "@context",
    "id"
  ],
  "properties": {
    "@context": {
    "oneOf": [
      {
        "type": "string",
        "pattern": "^https://(w3id.org|www.w3.org/ns)/did/v1$"
      },
      {
        "type": "array",
        "items": [
          {
            "type": "string",
            "pattern": "^https://(w3id.org|www.w3.org/ns)/did/v1$"
          }
        ],
        "uniqueItems": true,
        "additionalItems": {
          "oneOf": [
            {
              "type": "object"
            },
            {
              "type": "string"
            }
          ]
        }
      }
    ]
  },
    "id": {
      "type": "string"
    },
    "alsoKnownAs": {
      "type": "array",
      "items": {
        "type": "string",
        "format": "uri"
      },
      "uniqueItems": true
    },
    "publicKey": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/publicKey"
      }
    },
    "verificationMethod": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/publicKey"
      }
    },
    "authentication": {
      "type": "array",
      "items": {
        "oneOf": [
          {
            "$ref": "#/definitions/publicKey"
          },
          {
            "type": "string"
          }
        ]
      }
    },
    "service": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/service"
      }
    },
    "created": {
      "type": "string"
    },
    "updated": {
      "type": "string"
    },
    "proof": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/proof"
      }
    }
  },
  "definitions": {
    "proof": {
      "type": "object",
      "required": [ "type", "creator", "created", "proofValue"],
      "properties": {
        "type": {
          "type": "string",
          "format": "uri-reference"
        },
        "creator": {
          "type": "string",
          "format": "uri-reference"
        },
        "created": {
          "type": "string"
        },
        "proofValue": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "nonce": {
          "type": "string"
        }
      }
    },
    "publicKey": {
      "required": [
        "id",
        "type",
        "controller"
      ],
      "type": "object",
      "minProperties": 4,
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "controller": {
          "type": "string"
        }
      }
    },
    "serviceEndpoint": {
      "type": "object",
	  "minProperties": 1,
	  "properties": {
		"uri": {
		   "type": "string",
		   "format": "uri"
		},
		"accept": {
		   "type": "array",
		   "items": [
			  {
				 "type": "string"
			  }
		   ]
		},
		"routingKeys": {
		   "type": "array",
		   "items": [
			  {
				 "type": "string"
			  }
		   ]
		}
	  }
    },
    "service": {
      "required": [
        "id",
        "type",
        "serviceEndpoint"
      ],
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
			"oneOf": [
			  {
				"type": "string"
			  },
			  {
				"type": "array",
				"items": [
				  {
					"type": "string"
				  }
				]
              }
		   	]
        },
        "serviceEndpoint": {
           "oneOf": [
            {
              "type": "array",
			  "items": {
				"$ref": "#/definitions/serviceEndpoint"
			  }
            },
            {
              "type": "object"
            },
            {
              "type": "string",
              "format": "uri"
            }
          ]
        }
      }
    }
   }
}`

	schemaV011 = `{
  "required": [
    "@context",
    "id"
  ],
  "properties": {
    "@context": {
      "type": ["array","string"],
      "items": [
        {
          "type": "string",
          "pattern": "^https://(w3id.org|www.w3.org/ns)/did/v0.11$"
        }
      ],
      "additionalItems": {
        "type": "string",
        "format": "uri"
      }
    },
    "id": {
      "type": "string"
    },
    "alsoKnownAs": {
      "type": "array",
      "items": {
        "type": "string",
        "format": "uri"
      },
      "uniqueItems": true
    },
    "publicKey": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/publicKey"
      }
    },
    "authentication": {
      "type": ["array","string"],
      "items": {
        "oneOf": [
          {
            "$ref": "#/definitions/publicKey"
          },
          {
            "$ref": "#/definitions/publicKeyReferenced"
          },
		  {
            "type": "string"
          }
        ]
      }
    },
    "service": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/service"
      }
    },
    "created": {
      "type": "string"
    },
    "updated": {
      "type": "string"
    },
    "proof": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/proof"
      }
    }
  },
  "definitions": {
	"proof": {
      "type": "object",
      "required": [ "type", "creator", "created", "signatureValue"],
      "properties": {
        "type": {
          "type": "string",
          "format": "uri-reference"
        },
        "creator": {
          "type": "string",
          "format": "uri-reference"
        },
        "created": {
          "type": "string"
        },
        "signatureValue": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "nonce": {
          "type": "string"
        }
	  }
    },
    "publicKey": {
      "required": [
        "id",
        "type"
      ],
      "type": "object",
      "minProperties": 3,
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "owner": {
          "type": "string"
        }
      }
    },
    "publicKeyReferenced": {
      "required": [
        "type",
        "publicKey"
      ],
      "type": "object",
      "minProperties": 2,
      "maxProperties": 2,
      "properties": {
        "type": {
          "type": "string"
        },
        "publicKey": {
          "type": "string"
        }
      }
    },
    "serviceEndpoint": {
      "type": "object",
	  "minProperties": 1,
	  "properties": {
		"uri": {
		   "type": "string",
		   "format": "uri"
		},
		"accept": {
		   "type": "array",
		   "items": [
			  {
				 "type": "string"
			  }
		   ]
		},
		"routingKeys": {
		   "type": "array",
		   "items": [
			  {
				 "type": "string"
			  }
		   ]
		}
	  }
    },
    "service": {
      "required": [
        "id",
        "type",
        "serviceEndpoint"
      ],
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
			"oneOf": [
			  {
				"type": "string"
			  },
			  {
				"type": "array",
				"items": [
				  {
					"type": "string"
				  }
				]
              }
		   	]
        },
        "serviceEndpoint": {
           "oneOf": [
            {
              "type": "array",
			  "items": {
				"$ref": "#/definitions/serviceEndpoint"
			  }
            },
            {
              "type": "object"
            },
            {
              "type": "string",
              "format": "uri"
            }
          ]
        }
      }
    }
  }
}`
	schemaV12019 = `{
  "required": [
    "@context",
    "id"
  ],
  "properties": {
    "@context": {
      "type": ["array","string"],
      "items": [
        {
          "type": "string",
          "pattern": "^https://(w3id.org|www.w3.org/ns)/did/v1$"
        }
      ],
      "additionalItems": {
        "type": "string",
        "format": "uri"
      }
    },
    "id": {
      "type": "string"
    },
    "alsoKnownAs": {
      "type": "array",
      "items": {
        "type": "string",
        "format": "uri"
      },
      "uniqueItems": true
    },
    "publicKey": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/publicKey"
      }
    },
    "authentication": {
      "type": "array",
      "items": {
      }
    },
    "service": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/service"
      }
    },
    "created": {
      "type": "string"
    },
    "updated": {
      "type": "string"
    },
    "proof": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/proof"
      }
    }
  },
  "definitions": {
	"proof": {
      "type": "object",
      "required": [ "type", "creator", "created", "proofValue"],
      "properties": {
        "type": {
          "type": "string",
          "format": "uri-reference"
        },
        "creator": {
          "type": "string",
          "format": "uri-reference"
        },
        "created": {
          "type": "string"
        },
        "proofValue": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "nonce": {
          "type": "string"
        }
	  }
    },
    "publicKey": {
      "required": [
        "id",
        "type"
      ],
      "type": "object",
      "minProperties": 3,
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "controller": {
          "type": "string"
        }
      }
    },
    "serviceEndpoint": {
      "type": "object",
	  "minProperties": 1,
	  "properties": {
		"uri": {
		   "type": "string",
		   "format": "uri"
		},
		"accept": {
		   "type": "array",
		   "items": [
			  {
				 "type": "string"
			  }
		   ]
		},
		"routingKeys": {
		   "type": "array",
		   "items": [
			  {
				 "type": "string"
			  }
		   ]
		}
	  }
    },
    "service": {
      "required": [
        "type",
        "serviceEndpoint"
      ],
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
			"oneOf": [
			  {
				"type": "string"
			  },
			  {
				"type": "array",
				"items": [
				  {
					"type": "string"
				  }
				]
              }
		   	]
        },
        "serviceEndpoint": {
           "oneOf": [
            {
              "type": "array",
			  "items": {
				"$ref": "#/definitions/serviceEndpoint"
			  }
            },
            {
              "type": "object"
            },
            {
              "type": "string",
              "format": "uri"
            }
          ]
        }
      }
    }
  }
}`
)
