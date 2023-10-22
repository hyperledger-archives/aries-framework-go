package thresholdwallet

type Wallet interface {
	// Open opens makes the wallet's services available.
	Open() error

	// Close shutdowns the wallet's services.
	Close() error

	// Store adds a new document to wallet.
	Store(document *Document) error

	// AddCollection adds a new collection to wallet.
	AddCollection(collectionID string) error

	// Get retrieves a document from the wallet based on its content type and ID.
	Get(contentType ContentType, documentID string) (*Document, error)

	// GetCollection retrieves all documents from a collection based on the collectionID.
	GetCollection(collectionID string) ([]*Document, error)

	// Remove removes a document from the wallet based on its ID.
	Remove(contentType ContentType, documentID string) error

	// RemoveCollection removes an entire collection from the wallet.
	RemoveCollection(collectionID string) error

	// Sign signs the credential and produces a signed credential.
	Sign(credential *Document) (*Document, error)

	// Verify verifies the signature of the credential with the provided public key.
	Verify(signedCredential *Document, publicKey *Document) (bool, error)
}
