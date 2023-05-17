/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

// DefinitionJSONSchemaV1 is the JSONSchema definition for PresentationDefinition.
// nolint:lll
// https://github.com/decentralized-identity/presentation-exchange/blob/9a6abc6d2b0f08b6339c9116132fa94c4c834418/test/presentation-definition/schema.json
const DefinitionJSONSchemaV1 = `
{
   "$schema":"http://json-schema.org/draft-07/schema#",
   "title":"Presentation Definition",
   "definitions":{
      "schema":{
         "type":"object",
         "properties":{
            "uri":{
               "type":"string"
            },
            "required":{
               "type":"boolean"
            }
         },
         "required":[
            "uri"
         ],
         "additionalProperties":false
      },
      "filter":{
         "type":"object",
         "properties":{
            "type":{
               "type":"string"
            },
            "format":{
               "type":"string"
            },
            "pattern":{
               "type":"string"
            },
            "minimum":{
               "type":[
                  "number",
                  "string"
               ]
            },
            "minLength":{
               "type":"integer"
            },
            "maxLength":{
               "type":"integer"
            },
            "exclusiveMinimum":{
               "type":[
                  "number",
                  "string"
               ]
            },
            "exclusiveMaximum":{
               "type":[
                  "number",
                  "string"
               ]
            },
            "maximum":{
               "type":[
                  "number",
                  "string"
               ]
            },
            "const":{
               "type":[
                  "number",
                  "string"
               ]
            },
            "enum":{
               "type":"array",
               "items":{
                  "type":[
                     "number",
                     "string"
                  ]
               }
            },
            "not":{
               "type":"object",
               "minProperties":1
            }
         },
         "required":[
            "type"
         ],
         "additionalProperties":false
      },
      "format":{
         "type":"object",
         "patternProperties":{
            "^jwt$|^jwt_vc$|^jwt_vp$":{
               "type":"object",
               "properties":{
                  "alg":{
                     "type":"array",
                     "minItems":1,
                     "items":{
                        "type":"string"
                     }
                  }
               },
               "required":[
                  "alg"
               ],
               "additionalProperties":false
            },
            "^ldp_vc$|^ldp_vp$|^ldp$":{
               "type":"object",
               "properties":{
                  "proof_type":{
                     "type":"array",
                     "minItems":1,
                     "items":{
                        "type":"string"
                     }
                  }
               },
               "required":[
                  "proof_type"
               ],
               "additionalProperties":false
            },
            "additionalProperties":false
         },
         "additionalProperties":false
      },
      "submission_requirements":{
         "type":"object",
         "oneOf":[
            {
               "properties":{
                  "name":{
                     "type":"string"
                  },
                  "purpose":{
                     "type":"string"
                  },
                  "rule":{
                     "type":"string",
                     "enum":[
                        "all",
                        "pick"
                     ]
                  },
                  "count":{
                     "type":"integer",
                     "minimum":1
                  },
                  "min":{
                     "type":"integer",
                     "minimum":0
                  },
                  "max":{
                     "type":"integer",
                     "minimum":0
                  },
                  "from":{
                     "type":"string"
                  }
               },
               "required":[
                  "rule",
                  "from"
               ],
               "additionalProperties":false
            },
            {
               "properties":{
                  "name":{
                     "type":"string"
                  },
                  "purpose":{
                     "type":"string"
                  },
                  "rule":{
                     "type":"string",
                     "enum":[
                        "all",
                        "pick"
                     ]
                  },
                  "count":{
                     "type":"integer",
                     "minimum":1
                  },
                  "min":{
                     "type":"integer",
                     "minimum":0
                  },
                  "max":{
                     "type":"integer",
                     "minimum":0
                  },
                  "from_nested":{
                     "type":"array",
                     "minItems":1,
                     "items":{
                        "$ref":"#/definitions/submission_requirements"
                     }
                  }
               },
               "required":[
                  "rule",
                  "from_nested"
               ],
               "additionalProperties":false
            }
         ]
      },
      "input_descriptors":{
         "type":"object",
         "properties":{
            "id":{
               "type":"string"
            },
            "name":{
               "type":"string"
            },
            "purpose":{
               "type":"string"
            },
            "group":{
               "type":"array",
               "items":{
                  "type":"string"
               }
            },
            "schema":{
               "type":"array",
               "items":{
                  "$ref":"#/definitions/schema"
               }
            },
            "constraints":{
               "type":"object",
               "properties":{
                  "limit_disclosure":{
                     "type":"string",
                     "enum":[
                        "required",
                        "preferred"
                     ]
                  },
                  "statuses":{
                     "type":"object",
                     "properties":{
                        "active":{
                           "type":"object",
                           "properties":{
                              "directive":{
                                 "type":"string",
                                 "enum":[
                                    "required",
                                    "allowed",
                                    "disallowed"
                                 ]
                              }
                           }
                        },
                        "suspended":{
                           "type":"object",
                           "properties":{
                              "directive":{
                                 "type":"string",
                                 "enum":[
                                    "required",
                                    "allowed",
                                    "disallowed"
                                 ]
                              }
                           }
                        },
                        "revoked":{
                           "type":"object",
                           "properties":{
                              "directive":{
                                 "type":"string",
                                 "enum":[
                                    "required",
                                    "allowed",
                                    "disallowed"
                                 ]
                              }
                           }
                        }
                     }
                  },
                  "fields":{
                     "type":"array",
                     "items":{
                        "$ref":"#/definitions/field"
                     }
                  },
                  "subject_is_issuer":{
                     "type":"string",
                     "enum":[
                        "required",
                        "preferred"
                     ]
                  },
                  "is_holder":{
                     "type":"array",
                     "items":{
                        "type":"object",
                        "properties":{
                           "field_id":{
                              "type":"array",
                              "items":{
                                 "type":"string"
                              }
                           },
                           "directive":{
                              "type":"string",
                              "enum":[
                                 "required",
                                 "preferred"
                              ]
                           }
                        },
                        "required":[
                           "field_id",
                           "directive"
                        ],
                        "additionalProperties":false
                     }
                  },
                  "same_subject":{
                     "type":"array",
                     "items":{
                        "type":"object",
                        "properties":{
                           "field_id":{
                              "type":"array",
                              "items":{
                                 "type":"string"
                              }
                           },
                           "directive":{
                              "type":"string",
                              "enum":[
                                 "required",
                                 "preferred"
                              ]
                           }
                        },
                        "required":[
                           "field_id",
                           "directive"
                        ],
                        "additionalProperties":false
                     }
                  }
               },
               "additionalProperties":false
            }
         },
         "required":[
            "id",
            "schema"
         ],
         "additionalProperties":false
      },
      "field":{
         "type":"object",
         "oneOf":[
            {
               "properties":{
                  "id":{
                     "type":"string"
                  },
                  "path":{
                     "type":"array",
                     "items":{
                        "type":"string"
                     }
                  },
                  "purpose":{
                     "type":"string"
                  },
                  "filter":{
                     "$ref":"#/definitions/filter"
                  }
               },
               "required":[
                  "path"
               ],
               "additionalProperties":false
            },
            {
               "properties":{
                  "id":{
                     "type":"string"
                  },
                  "path":{
                     "type":"array",
                     "items":{
                        "type":"string"
                     }
                  },
                  "purpose":{
                     "type":"string"
                  },
                  "filter":{
                     "$ref":"#/definitions/filter"
                  },
                  "predicate":{
                     "type":"string",
                     "enum":[
                        "required",
                        "preferred"
                     ]
                  }
               },
               "required":[
                  "path",
                  "filter",
                  "predicate"
               ],
               "additionalProperties":false
            }
         ]
      }
   },
   "type":"object",
   "properties":{
      "presentation_definition":{
         "type":"object",
         "properties":{
            "id":{
               "type":"string"
            },
            "name":{
               "type":"string"
            },
            "purpose":{
               "type":"string"
            },
            "format":{
               "$ref":"#/definitions/format"
            },
            "submission_requirements":{
               "type":"array",
               "items":{
                  "$ref":"#/definitions/submission_requirements"
               }
            },
            "input_descriptors":{
               "type":"array",
               "items":{
                  "$ref":"#/definitions/input_descriptors"
               }
            }
         },
         "required":[
            "id",
            "input_descriptors"
         ],
         "additionalProperties":false
      }
   }
}`

// DefinitionJSONSchemaV2 is the JSONSchema definition for PresentationDefinition.
// nolint:lll
const DefinitionJSONSchemaV2 = `
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Presentation Definition Envelope",
  "definitions": {
    "status_directive": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "directive": {
          "type": "string",
          "enum": ["required", "allowed", "disallowed"]
        },
        "type": {
          "type": "array",
          "minItems": 1,
          "items": { "type": "string" }
        }
      }
    },
    "field": {
      "type": "object",
      "oneOf": [
        {
          "properties": {
            "id": { "type": "string" },
            "path": {
              "type": "array",
              "items": { "type": "string" }
            },
            "purpose": { "type": "string" },
            "intent_to_retain": { "type": "boolean" },
            "optional": { "type": "boolean" },
            "filter": { "$ref": "http://json-schema.org/draft-07/schema#" }
          },
          "required": ["path"],
          "additionalProperties": false
        },
        {
          "properties": {
            "id": { "type": "string" },
            "path": {
              "type": "array",
              "items": { "type": "string" }
            },
            "purpose": { "type": "string" },
            "intent_to_retain": { "type": "boolean" },
            "filter": { "$ref": "http://json-schema.org/draft-07/schema#" },
            "predicate": {
              "type": "string",
              "enum": ["required", "preferred"]
            }
          },
          "required": ["path", "filter", "predicate"],
          "additionalProperties": false
        }
      ]
    },
    "input_descriptor": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "id": { "type": "string" },
        "name": { "type": "string" },
        "purpose": { "type": "string" },
        "format": {
		  "$schema": "http://json-schema.org/draft-07/schema#",
		  "title": "Presentation Definition Claim Format Designations",
		  "type": "object",
		  "additionalProperties": false,
		  "patternProperties": {
			"^jwt$|^jwt_vc$|^jwt_vp$": {
			  "type": "object",
			  "additionalProperties": false,
			  "properties": {
				"alg": {
				  "type": "array",
				  "minItems": 1,
				  "items": { "type": "string" }
				}
			  }
			},
			"^ldp_vc$|^ldp_vp$|^ldp$": {
			  "type": "object",
			  "additionalProperties": false,
			  "properties": {
				"proof_type": {
				  "type": "array",
				  "minItems": 1,
				  "items": { "type": "string" }
				}
			  }
			}
		  }
		},
        "group": { "type": "array", "items": { "type": "string" } },
        "constraints": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "limit_disclosure": { "type": "string", "enum": ["required", "preferred"] },
            "statuses": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "active": { "$ref": "#/definitions/status_directive" },
                "suspended": { "$ref": "#/definitions/status_directive" },
                "revoked": { "$ref": "#/definitions/status_directive" }
              }
            },
            "fields": {
              "type": "array",
              "items": { "$ref": "#/definitions/field" }
            },
            "subject_is_issuer": { "type": "string", "enum": ["required", "preferred"] },
            "is_holder": {
              "type": "array",
              "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                  "field_id": {
                    "type": "array",
                    "items": { "type": "string" }
                  },
                  "directive": {
                    "type": "string",
                    "enum": ["required", "preferred"]
                  }
                },
                "required": ["field_id", "directive"]
              }
            },
            "same_subject": {
              "type": "array",
              "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                  "field_id": {
                    "type": "array",
                    "items": { "type": "string" }
                  },
                  "directive": {
                    "type": "string",
                    "enum": ["required", "preferred"]
                  }
                },
                "required": ["field_id", "directive"]
              }
            }
          }
        }
      },
      "required": ["id"]
    },
    "submission_requirement": {
      "type": "object",
      "oneOf": [
        {
          "properties": {
            "name": { "type": "string" },
            "purpose": { "type": "string" },
            "rule": {
              "type": "string",
              "enum": ["all", "pick"]
            },
            "count": { "type": "integer", "minimum": 1 },
            "min": { "type": "integer", "minimum": 0 },
            "max": { "type": "integer", "minimum": 0 },
            "from": { "type": "string" }
          },
          "required": ["rule", "from"],
          "additionalProperties": false
        },
        {
          "properties": {
            "name": { "type": "string" },
            "purpose": { "type": "string" },
            "rule": {
              "type": "string",
              "enum": ["all", "pick"]
            },
            "count": { "type": "integer", "minimum": 1 },
            "min": { "type": "integer", "minimum": 0 },
            "max": { "type": "integer", "minimum": 0 },
            "from_nested": {
              "type": "array",
              "minItems": 1,
              "items": {
                "$ref": "#/definitions/submission_requirement"
              }
            }
          },
          "required": ["rule", "from_nested"],
          "additionalProperties": false
        }
      ]
    },
    "presentation_definition": {
      "type": "object",
      "properties": {
        "id": { "type": "string" },
        "name": { "type": "string" },
        "purpose": { "type": "string" },
        "format": {
		  "$schema": "http://json-schema.org/draft-07/schema#",
		  "title": "Presentation Definition Claim Format Designations",
		  "type": "object",
		  "additionalProperties": false,
		  "patternProperties": {
			"^jwt$|^jwt_vc$|^jwt_vp$": {
			  "type": "object",
			  "additionalProperties": false,
			  "properties": {
				"alg": {
				  "type": "array",
				  "minItems": 1,
				  "items": { "type": "string" }
				}
			  }
			},
			"^ldp_vc$|^ldp_vp$|^ldp$": {
			  "type": "object",
			  "additionalProperties": false,
			  "properties": {
				"proof_type": {
				  "type": "array",
				  "minItems": 1,
				  "items": { "type": "string" }
				}
			  }
			}
		  }
		},
        "frame": {
          "type": "object",
          "additionalProperties": true
        },
        "submission_requirements": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/submission_requirement"
          }
        },
        "input_descriptors": {
          "type": "array",
          "items": { "$ref": "#/definitions/input_descriptor" }
        }
      },
      "required": ["id", "input_descriptors"],
      "additionalProperties": false
    }
  },
  "type": "object",
  "properties": {
    "presentation_definition": {"$ref": "#/definitions/presentation_definition"}
  }
}`
