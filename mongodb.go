// Package mongodb is an enhanced wrapper for MongoDB Driver with better connection management,
// error handling, and performance optimizations.
//
// This package uses the standard "_id" field to find or add a document.
//
// It is important to know that you will have to index the id field for optimum performance.
//
// Example:
//
//	import "github.com/akshaybabloo/mongodb/v6"
//
//	type data struct {
//	    ID   string `bson:"_id"`
//	    Name string `bson:"name"`
//	}
//
//	func main() {
//	    client, err := mongodb.NewMongoClient("mongodb://localhost:27017/?retryWrites=true&w=majority", "test")
//	    if err != nil {
//	        panic(err)
//	    }
//	    defer client.Close()
//
//	    testData := data{
//	        ID:   "user1",
//	        Name: "Akshay",
//	    }
//
//	    ctx := context.Background()
//	    result, err := client.Add(ctx, "test_collection", testData)
//	    if err != nil {
//	        panic(err)
//	    }
//	    fmt.Println(result.InsertedID)
//	}
//
// Example with Explicit Encryption:
//
//	// Assume 'client' is an initialized *mongodb.Client with encryption enabled.
//	ctx := context.Background()
//
//	// 1. Create a new Data Encryption Key (DEK)
//	// This key should be created once and stored securely. For this example, we create it every time.
//	dataKeyId, err := client.CreateDataKey(ctx)
//	if err != nil {
//	    panic(err)
//	}
//
//	// 2. Encrypt a value
//	// Use "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic" for searchable encryption
//	// or "AEAD_AES_256_CBC_HMAC_SHA_512-Random" for non-searchable.
//	secretMessage := "this is a secret"
//	encryptedData, err := client.Encrypt(ctx, dataKeyId, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", secretMessage)
//	if err != nil {
//	    panic(err)
//	}
//
//	// 3. Store the encrypted value
//	type encryptedDoc struct {
//	    ID          string      `bson:"_id"`
//	    SecretField bson.Binary `bson:"secretField"`
//	}
//	_, err = client.Add(ctx, "encrypted_collection", encryptedDoc{ID: "doc1", SecretField: encryptedData})
//	if err != nil {
//	    panic(err)
//	}
//
//	// 4. Retrieve and decrypt
//	var retrievedDoc encryptedDoc
//	findResult := client.GetCustom(ctx, "encrypted_collection", bson.M{"_id": "doc1"})
//	if err = findResult.Err(); err != nil {
//	    panic(err)
//	}
//	if err = findResult.Decode(&retrievedDoc); err != nil {
//	    panic(err)
//	}
//
//	decryptedValue, err := client.Decrypt(ctx, retrievedDoc.SecretField)
//	if err != nil {
//	    panic(err)
//	}
//
//	var decryptedMessage string
//	if err := decryptedValue.Unmarshal(&decryptedMessage); err != nil {
//	    panic(err)
//	}
//	fmt.Println("Decrypted:", decryptedMessage) // "Decrypted: this is a secret"
package mongodb

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Client wraps MongoDB client with simplified operations and improved connection management
type Client struct {
	// ConnectionUrl which connects to MongoDB atlas or local deployment
	ConnectionUrl string
	// DatabaseName with database name
	DatabaseName string
	// client holds the MongoDB client instance
	client *mongo.Client
	// mutex for thread-safe operations
	mutex sync.RWMutex
	// connected tracks connection state
	connected bool
	// encryption is the encryption client
	encryption *EncryptionClient
	// clientEncryption is the explicit encryption client
	clientEncryption *mongo.ClientEncryption
}

// EncryptionClient holds the encryption client and its options
type EncryptionClient struct {
	// KmsProvider is the Key Management Service provider (e.g., "local", "aws", "gcp", "azure")
	KmsProvider string
	// MasterKey is the master key used for encryption
	MasterKey []byte
	// KeyVaultNamespace is the namespace for the key vault collection
	KeyVaultNamespace string
	// SchemaMap is the schema map for field encryption. It is optional for explicit encryption.
	SchemaMap map[string]interface{}
}

// NewMongoClient creates a new MongoDB client and establishes connection
func NewMongoClient(connectionURL string, databaseName string) (*Client, error) {
	if connectionURL == "" {
		return nil, errors.New("connection URL cannot be empty")
	}
	if databaseName == "" {
		return nil, errors.New("database name cannot be empty")
	}

	c := &Client{
		ConnectionUrl: connectionURL,
		DatabaseName:  databaseName,
	}

	if err := c.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	return c, nil
}

// NewMongoClientWithEncryption creates a new MongoDB client with encryption enabled
func NewMongoClientWithEncryption(connectionURL string, databaseName string, encryption *EncryptionClient) (*Client, error) {
	if connectionURL == "" {
		return nil, errors.New("connection URL cannot be empty")
	}
	if databaseName == "" {
		return nil, errors.New("database name cannot be empty")
	}
	if encryption == nil {
		return nil, errors.New("encryption client cannot be nil")
	}
	if encryption.KmsProvider == "" {
		return nil, errors.New("KMS provider cannot be empty")
	}
	if len(encryption.MasterKey) == 0 {
		return nil, errors.New("master key cannot be empty")
	}
	if encryption.KeyVaultNamespace == "" {
		return nil, errors.New("key vault namespace cannot be empty")
	}
	// The schema map is not required for explicit encryption, so the check has been removed.

	c := &Client{
		ConnectionUrl: connectionURL,
		DatabaseName:  databaseName,
		encryption:    encryption,
	}

	if err := c.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Set up the client for explicit encryption
	clientEncryptionOpts := options.ClientEncryption().
		SetKeyVaultNamespace(c.encryption.KeyVaultNamespace).
		SetKmsProviders(map[string]map[string]interface{}{
			"local": {
				"key": c.encryption.MasterKey,
			},
		})

	clientEncryption, err := mongo.NewClientEncryption(c.client, clientEncryptionOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create client encryption: %w", err)
	}
	c.clientEncryption = clientEncryption

	return c, nil
}

// connect establishes connection to MongoDB
func (c *Client) connect() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.connected {
		return nil
	}

	clientOptions := options.Client().ApplyURI(c.ConnectionUrl)

	// For explicit encryption, AutoEncryptionOptions should NOT be set on the client.
	// The manual setup in NewMongoClientWithEncryption is correct.

	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return err
	}

	// Ping to verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		// Use a new context for Disconnect as the previous one might be done.
		disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer disconnectCancel()
		_ = client.Disconnect(disconnectCtx) // Attempt to disconnect on ping failure
		return err
	}

	c.client = client
	c.connected = true
	return nil
}

// Close disconnects from MongoDB
func (c *Client) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.connected || c.client == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if c.clientEncryption != nil {
		_ = c.clientEncryption.Close(ctx)
	}

	err := c.client.Disconnect(ctx)
	c.connected = false
	c.client = nil
	return err
}

// getClient returns the MongoDB client, ensuring connection
func (c *Client) getClient() (*mongo.Client, error) {
	c.mutex.RLock()
	if c.connected && c.client != nil {
		c.mutex.RUnlock()
		return c.client, nil
	}
	c.mutex.RUnlock()

	// Need to reconnect
	if err := c.connect(); err != nil {
		return nil, err
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.client, nil
}

// validateParams validates common parameters
func (c *Client) validateParams(collectionName string) error {
	if collectionName == "" {
		return errors.New("collection name cannot be empty")
	}
	return nil
}

// getCollection returns a MongoDB collection
func (c *Client) getCollection(collectionName string) (*mongo.Collection, error) {
	if err := c.validateParams(collectionName); err != nil {
		return nil, err
	}

	client, err := c.getClient()
	if err != nil {
		return nil, err
	}

	db := client.Database(c.DatabaseName)
	return db.Collection(collectionName), nil
}

// Add inserts a single document to MongoDB
func (c *Client) Add(ctx context.Context, collectionName string, data interface{}) (*mongo.InsertOneResult, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return nil, err
	}

	return collection.InsertOne(ctx, data)
}

// AddMany inserts multiple documents to MongoDB
func (c *Client) AddMany(ctx context.Context, collectionName string, data []interface{}) (*mongo.InsertManyResult, error) {
	if len(data) == 0 {
		return nil, errors.New("data slice cannot be empty")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return nil, err
	}

	return collection.InsertMany(ctx, data)
}

// Update updates a document by its ID
func (c *Client) Update(ctx context.Context, collectionName string, id string, data interface{}) (*mongo.UpdateResult, error) {
	if id == "" {
		return nil, errors.New("id cannot be empty")
	}
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return nil, err
	}

	return collection.UpdateOne(ctx, bson.M{"_id": id}, bson.D{{"$set", data}})
}

// UpdateCustom updates a document using a custom filter
func (c *Client) UpdateCustom(ctx context.Context, collectionName string, filter interface{}, data interface{}, updateOptions ...options.Lister[options.UpdateOneOptions]) (*mongo.UpdateResult, error) {
	if filter == nil {
		return nil, errors.New("filter cannot be nil")
	}
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return nil, err
	}

	return collection.UpdateOne(ctx, filter, bson.D{{"$set", data}}, updateOptions...)
}

// UpdateMany updates multiple documents using a filter
func (c *Client) UpdateMany(ctx context.Context, collectionName string, filter interface{}, data interface{}, updateOptions ...options.Lister[options.UpdateManyOptions]) (*mongo.UpdateResult, error) {
	if filter == nil {
		return nil, errors.New("filter cannot be nil")
	}
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return nil, err
	}

	return collection.UpdateMany(ctx, filter, bson.D{{"$set", data}}, updateOptions...)
}

// Delete deletes a document by ID
func (c *Client) Delete(ctx context.Context, collectionName string, id string) (*mongo.DeleteResult, error) {
	if id == "" {
		return nil, errors.New("id cannot be empty")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return nil, err
	}

	return collection.DeleteOne(ctx, bson.M{"_id": id})
}

// DeleteCustom deletes a document using a custom filter
func (c *Client) DeleteCustom(ctx context.Context, collectionName string, filter interface{}) (*mongo.DeleteResult, error) {
	if filter == nil {
		return nil, errors.New("filter cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return nil, err
	}

	return collection.DeleteOne(ctx, filter)
}

// DeleteMany deletes multiple documents using a filter
func (c *Client) DeleteMany(ctx context.Context, collectionName string, filter interface{}) (*mongo.DeleteResult, error) {
	if filter == nil {
		return nil, errors.New("filter cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return nil, err
	}

	return collection.DeleteMany(ctx, filter)
}

// Get finds one document by ID
func (c *Client) Get(ctx context.Context, collectionName string, id string) *mongo.SingleResult {
	collection, err := c.getCollection(collectionName)
	if err != nil {
		// To align with mongo-go-driver, return a SingleResult that will report the error.
		return mongo.NewSingleResultFromDocument(nil, err, nil)
	}

	return collection.FindOne(ctx, bson.M{"_id": id})
}

// GetCustom finds one document using a custom filter
func (c *Client) GetCustom(ctx context.Context, collectionName string, filter interface{}, findOptions ...options.Lister[options.FindOneOptions]) *mongo.SingleResult {
	collection, err := c.getCollection(collectionName)
	if err != nil {
		return mongo.NewSingleResultFromDocument(nil, err, nil)
	}
	return collection.FindOne(ctx, filter, findOptions...)
}

// FindByID finds all documents with the same ID (renamed from GetAll for clarity)
func (c *Client) FindByID(ctx context.Context, collectionName string, id string, result interface{}) error {
	if id == "" {
		return errors.New("id cannot be empty")
	}
	if result == nil {
		return errors.New("result cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return err
	}

	cursor, err := collection.Find(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	return cursor.All(ctx, result)
}

// FindAll finds all documents using a custom filter
func (c *Client) FindAll(ctx context.Context, collectionName string, filter interface{}, result interface{}, findOptions ...options.Lister[options.FindOptions]) error {
	if filter == nil {
		return errors.New("filter cannot be nil")
	}
	if result == nil {
		return errors.New("result cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return err
	}

	cursor, err := collection.Find(ctx, filter, findOptions...)
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	return cursor.All(ctx, result)
}

// Exists checks if a document exists by ID
func (c *Client) Exists(ctx context.Context, collectionName string, id string) (bool, error) {
	if id == "" {
		return false, errors.New("id cannot be empty")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return false, err
	}

	count, err := collection.CountDocuments(ctx, bson.M{"_id": id})
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// ExistsCustom checks if a document exists using a custom filter
func (c *Client) ExistsCustom(ctx context.Context, collectionName string, filter interface{}) (bool, error) {
	if filter == nil {
		return false, errors.New("filter cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return false, err
	}

	count, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// Aggregate performs an aggregation operation on a collection
func (c *Client) Aggregate(ctx context.Context, collectionName string, pipeline interface{}, result interface{}, aggregateOptions ...options.Lister[options.AggregateOptions]) error {
	if pipeline == nil {
		return errors.New("pipeline cannot be nil")
	}
	if result == nil {
		return errors.New("result cannot be nil")
	}

	collection, err := c.getCollection(collectionName)
	if err != nil {
		return err
	}

	cursor, err := collection.Aggregate(ctx, pipeline, aggregateOptions...)
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	return cursor.All(ctx, result)
}

// Collection returns a MongoDB collection
// Note: The client connection is managed internally, no need to manually disconnect
func (c *Client) Collection(collectionName string) (*mongo.Collection, error) {
	return c.getCollection(collectionName)
}

// Database returns the MongoDB database
func (c *Client) Database() (*mongo.Database, error) {
	client, err := c.getClient()
	if err != nil {
		return nil, err
	}

	return client.Database(c.DatabaseName), nil
}

// RawClient returns the underlying MongoDB client
// Note: Do not disconnect this client manually, use Close() method instead
func (c *Client) RawClient() (*mongo.Client, error) {
	return c.getClient()
}

// DropDatabase drops the entire database
func (c *Client) DropDatabase(ctx context.Context) error {
	db, err := c.Database()
	if err != nil {
		return err
	}

	return db.Drop(ctx)
}

// Ping tests the connection to MongoDB
func (c *Client) Ping(ctx context.Context) error {
	client, err := c.getClient()
	if err != nil {
		return err
	}

	return client.Ping(ctx, nil)
}

// CreateDataKey creates a new data key for encryption.
// It returns the key's UUID as a hex-encoded string.
func (c *Client) CreateDataKey(ctx context.Context) (string, error) {
	if c.encryption == nil {
		return "", errors.New("encryption client is not initialized")
	}
	if c.clientEncryption == nil {
		return "", errors.New("explicit encryption client is not initialized")
	}

	dataKeyID, err := c.clientEncryption.CreateDataKey(ctx, c.encryption.KmsProvider, options.DataKey())
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(dataKeyID.Data), nil
}

// Encrypt encrypts a value using a specified data key ID and algorithm.
func (c *Client) Encrypt(ctx context.Context, dataKeyID string, algorithm string, value interface{}) (bson.Binary, error) {
	if c.clientEncryption == nil {
		return bson.Binary{}, errors.New("explicit encryption client is not initialized")
	}
	if dataKeyID == "" {
		return bson.Binary{}, errors.New("data key ID cannot be empty")
	}
	if algorithm == "" {
		return bson.Binary{}, errors.New("encryption algorithm cannot be empty")
	}

	// The data key ID from CreateDataKey is a hex-encoded string of a UUID.
	// We need to decode it and reconstruct the BSON Binary type with the correct UUID subtype.
	dataKeyUUIDBytes, err := hex.DecodeString(dataKeyID)
	if err != nil {
		return bson.Binary{}, fmt.Errorf("invalid data key ID: must be a hex-encoded UUID: %w", err)
	}
	keyIDBinary := bson.Binary{
		Subtype: bson.TypeBinaryUUID, // Subtype for UUID is 0x04
		Data:    dataKeyUUIDBytes,
	}

	// To encrypt a single value, it must be converted to a bson.RawValue.
	// The standard way to do this is to wrap it in a document, marshal it,
	// and then look up the raw value from the marshalled document.
	docWrapper := bson.D{{"v", value}}
	marshalledDoc, err := bson.Marshal(docWrapper)
	if err != nil {
		return bson.Binary{}, fmt.Errorf("failed to marshal value into BSON document: %w", err)
	}
	rawValue, err := bson.Raw(marshalledDoc).LookupErr("v")
	if err != nil {
		return bson.Binary{}, fmt.Errorf("failed to lookup raw BSON value: %w", err)
	}

	// Set the encryption options, including the key ID and the algorithm.
	// Valid algorithms include "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic" and
	// "AEAD_AES_256_CBC_HMAC_SHA_512-Random".
	encryptOpts := options.Encrypt().
		SetKeyID(keyIDBinary).
		SetAlgorithm(algorithm)

	encryptedValue, err := c.clientEncryption.Encrypt(ctx, rawValue, encryptOpts)
	if err != nil {
		return bson.Binary{}, fmt.Errorf("failed to encrypt value: %w", err)
	}

	return encryptedValue, nil
}

// Decrypt decrypts a value. The returned bson.RawValue then needs to be unmarshalled
// into the appropriate Go type using its Unmarshal() method.
func (c *Client) Decrypt(ctx context.Context, value bson.Binary) (bson.RawValue, error) {
	if c.clientEncryption == nil {
		return bson.RawValue{}, errors.New("explicit encryption client is not initialized")
	}

	decryptedValue, err := c.clientEncryption.Decrypt(ctx, value)
	if err != nil {
		return bson.RawValue{}, fmt.Errorf("failed to decrypt value: %w", err)
	}

	return decryptedValue, nil
}

// IsConnected returns the connection status
func (c *Client) IsConnected() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.connected
}
