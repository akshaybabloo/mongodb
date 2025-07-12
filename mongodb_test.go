package mongodb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var client *Client

type data struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`
}

// init sets up the client for the test suite.
func init() {
	var err error
	mongoURL := os.Getenv("MONGO_URL")
	if mongoURL == "" {
		mongoURL = "mongodb://root:example@localhost:27017/?retryWrites=true&w=majority"
	}
	client, err = NewMongoClient(
		mongoURL,
		"test")
	if err != nil {
		panic(err)
	}
}

// setupEncryptedClient is a helper function to create a client with encryption enabled for tests.
func setupEncryptedClient(t *testing.T) *Client {
	t.Helper()

	// A 96-byte master key for local testing only. DO NOT use this in production.
	masterKey := make([]byte, 96)
	_, err := rand.Read(masterKey)
	if err != nil {
		t.Fatalf("Failed to generate random master key: %v", err)
	}

	keyVaultNamespace := "encryption.__keyVault"
	// SchemaMap is not needed for explicit encryption but is included for completeness
	// if you were to mix with automatic encryption.
	schemaMap := map[string]interface{}{}

	encryptionClient := &EncryptionClient{
		KmsProvider:       "local",
		MasterKey:         masterKey,
		KeyVaultNamespace: keyVaultNamespace,
		SchemaMap:         schemaMap, // Not used by explicit encryption
	}

	mongoURL := os.Getenv("MONGO_URL")
	if mongoURL == "" {
		mongoURL = "mongodb://root:example@localhost:27017/?retryWrites=true&w=majority"
	}

	encryptedClient, err := NewMongoClientWithEncryption(
		mongoURL,
		"test_encryption", // Use a separate DB for encryption tests
		encryptionClient,
	)
	if err != nil {
		t.Fatalf("Failed to create encrypted client: %s", err)
	}

	// Clean up the database after the test
	t.Cleanup(func() {
		err := encryptedClient.DropDatabase(context.Background())
		if err != nil {
			t.Logf("Failed to drop test_encryption database: %v", err)
		}
		encryptedClient.Close()
	})

	return encryptedClient
}

func TestClient_Add(t *testing.T) {
	testData := data{
		ID:   "1231",
		Name: "Akshay",
	}
	ctx := context.Background()
	done, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Errorf("Unable to add data. %s", err)
	}
	t.Logf("The ID is %s", done.InsertedID)
}

func TestClient_AddMany(t *testing.T) {
	var testData = []interface{}{
		data{
			ID:   "111",
			Name: "Akshay",
		},
		data{
			ID:   "222",
			Name: "Raj",
		},
	}

	ctx := context.Background()
	done, err := client.AddMany(ctx, "test_collection", testData)
	if err != nil {
		t.Errorf("Unable to add data. %s", err)
	}
	t.Logf("The IDs are %v", done.InsertedIDs)
}

func TestClient_Exists(t *testing.T) {
	testData := data{
		ID:   "1233455",
		Name: "Akshay",
	}
	ctx := context.Background()
	done, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Errorf("Unable to add data. %s", err)
	}
	t.Logf("The ID is %s", done.InsertedID)

	// Actual test
	exists, err := client.Exists(ctx, "test_collection", "1233455")
	if err != nil {
		t.Errorf("Unable to check existence. %s", err)
	}
	if !exists {
		t.Errorf("Expected document to exist, but it doesn't")
	}
	t.Logf("Exists: %v", exists)

	existsCustom, err := client.ExistsCustom(ctx, "test_collection", bson.M{"_id": "1233455"})
	if err != nil {
		t.Errorf("Unable to check existence with custom query. %s", err)
	}
	if !existsCustom {
		t.Errorf("Expected document to exist by custom query, but it doesn't")
	}
	t.Logf("Exists with custom query: %v", existsCustom)
}

func TestClient_DeleteMany(t *testing.T) {
	var testData = []interface{}{
		data{
			ID:   "1",
			Name: "Akshay",
		},
		data{
			ID:   "2",
			Name: "Raj",
		},
	}
	ctx := context.Background()
	done, err := client.AddMany(ctx, "test_collection", testData)
	if err != nil {
		t.Errorf("Unable to add data. %s", err)
	}
	t.Logf("The IDs are %v", done.InsertedIDs)

	deleted, err := client.DeleteMany(ctx, "test_collection", bson.M{"_id": bson.M{"$in": bson.A{"1", "2"}}})
	if err != nil {
		t.Errorf("Unable to delete data. %s", err)
	}
	if deleted.DeletedCount != 2 {
		t.Errorf("Expected 2 documents to be deleted, got %d", deleted.DeletedCount)
	}
	t.Logf("Deleted items: %d", deleted.DeletedCount)
}

func TestClient_Get(t *testing.T) {
	testData := data{
		ID:   "get-id-2",
		Name: "Akshay",
	}

	ctx := context.Background()
	done, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Errorf("Unable to add data. %s", err)
	}
	t.Logf("The ID is %s", done.InsertedID)

	// Actual test
	var decodeData data
	res := client.Get(ctx, "test_collection", "get-id-2")
	if res.Err() != nil {
		t.Errorf("No data found: %v", res.Err())
		return
	}
	err = res.Decode(&decodeData)
	if err != nil {
		t.Errorf("Failed to decode data: %v", err)
	}
	t.Logf("%v", decodeData)
}

func TestClient_GetCustom(t *testing.T) {
	testData := data{
		ID:   "get-custom-id-2",
		Name: "Akshay",
	}
	ctx := context.Background()
	_, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Fatalf("Unable to add data: %v", err)
	}

	// Actual test
	var decodeData data
	res := client.GetCustom(ctx, "test_collection", bson.M{"_id": "get-custom-id-2"})
	if res.Err() != nil {
		t.Errorf("No data found: %v", res.Err())
		return
	}
	err = res.Decode(&decodeData)
	if err != nil {
		t.Errorf("Failed to decode data: %v", err)
	}
	t.Logf("%v", decodeData)

}

func TestClient_FindAll(t *testing.T) {
	testData := data{
		ID:   "findall-id-1",
		Name: "Akshay",
	}
	ctx := context.Background()
	_, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Errorf("Unable to add data. %s", err)
	}

	// Actual test
	var result []data
	err = client.FindAll(ctx, "test_collection", bson.M{"name": "Akshay"}, &result)
	if err != nil {
		t.Errorf("Error finding data: %v", err)
	}
	if len(result) == 0 {
		t.Errorf("No data found")
	}
	t.Logf("%v", result)
}

func TestClient_Update(t *testing.T) {
	testData := data{
		ID:   "update-id-1",
		Name: "OriginalName",
	}
	ctx := context.Background()
	_, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Fatalf("Unable to add data: %s", err)
	}

	updateData := bson.M{"name": "UpdatedName"}
	updateResult, err := client.Update(ctx, "test_collection", "update-id-1", updateData)
	if err != nil {
		t.Fatalf("Unable to update data: %s", err)
	}
	if updateResult.ModifiedCount != 1 {
		t.Errorf("Expected 1 document to be updated, got %d", updateResult.ModifiedCount)
	}

	// Verify update
	var got data
	res := client.Get(ctx, "test_collection", "update-id-1")
	if err := res.Err(); err != nil {
		t.Fatalf("Unable to get data: %s", err)
	}
	err = res.Decode(&got)
	if err != nil {
		t.Fatalf("Unable to decode data: %s", err)
	}
	if got.Name != "UpdatedName" {
		t.Errorf("Expected Name to be 'UpdatedName', got '%s'", got.Name)
	}
}

func TestClient_UpdateCustom(t *testing.T) {
	testData := data{
		ID:   "updatecustom-id-1",
		Name: "OriginalName",
	}
	ctx := context.Background()
	_, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Fatalf("Unable to add data: %s", err)
	}

	updateData := bson.M{"name": "CustomUpdatedName"}
	updateResult, err := client.UpdateCustom(ctx, "test_collection", bson.M{"_id": "updatecustom-id-1"}, updateData)
	if err != nil {
		t.Fatalf("Unable to update data: %s", err)
	}
	if updateResult.ModifiedCount != 1 {
		t.Errorf("Expected 1 document to be updated, got %d", updateResult.ModifiedCount)
	}

	// Verify update
	var got data
	res := client.Get(ctx, "test_collection", "updatecustom-id-1")
	if err := res.Err(); err != nil {
		t.Fatalf("Unable to get data: %s", err)
	}
	err = res.Decode(&got)
	if err != nil {
		t.Fatalf("Unable to decode data: %s", err)
	}
	if got.Name != "CustomUpdatedName" {
		t.Errorf("Expected Name to be 'CustomUpdatedName', got '%s'", got.Name)
	}
}

func TestClient_UpdateMany(t *testing.T) {
	testData := []interface{}{
		data{ID: "updatemany-id-1", Name: "Name1"},
		data{ID: "updatemany-id-2", Name: "Name2"},
	}
	ctx := context.Background()
	_, err := client.AddMany(ctx, "test_collection", testData)
	if err != nil {
		t.Fatalf("Unable to add data: %s", err)
	}

	updateData := bson.M{"name": "BulkUpdated"}
	updateResult, err := client.UpdateMany(ctx, "test_collection", bson.M{"_id": bson.M{"$in": []string{"updatemany-id-1", "updatemany-id-2"}}}, updateData)
	if err != nil {
		t.Fatalf("Unable to update many: %s", err)
	}
	if updateResult.ModifiedCount != 2 {
		t.Errorf("Expected 2 documents to be updated, got %d", updateResult.ModifiedCount)
	}

	// Verify updates
	var results []data
	err = client.FindAll(ctx, "test_collection", bson.M{"_id": bson.M{"$in": []string{"updatemany-id-1", "updatemany-id-2"}}}, &results)
	if err != nil {
		t.Fatalf("Unable to find updated documents: %s", err)
	}
	for _, d := range results {
		if d.Name != "BulkUpdated" {
			t.Errorf("Expected Name to be 'BulkUpdated', got '%s' for ID '%s'", d.Name, d.ID)
		}
	}
}

func TestClient_Delete(t *testing.T) {
	testData := data{
		ID:   "delete-id-4",
		Name: "Akshay",
	}
	ctx := context.Background()
	done, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Errorf("Unable to add data. %s", err)
	}
	t.Logf("The ID is %s", done.InsertedID)

	// Actual test
	deleted, err := client.Delete(ctx, "test_collection", "delete-id-4")
	if err != nil {
		t.Errorf("Unable to delete data. %s", err)
	}
	if deleted.DeletedCount != 1 {
		t.Errorf("Expected 1 document to be deleted, got %d", deleted.DeletedCount)
	}
	t.Logf("Number deleted %d", deleted.DeletedCount)
}

func TestClient_DeleteCustom(t *testing.T) {
	testData := data{
		ID:   "delete-custom-id-4",
		Name: "Akshay",
	}
	ctx := context.Background()
	done, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Errorf("Unable to add data. %s", err)
	}
	t.Logf("The ID is %s", done.InsertedID)

	// Actual test
	deleted, err := client.DeleteCustom(ctx, "test_collection", bson.M{"_id": "delete-custom-id-4"})
	if err != nil {
		t.Errorf("Unable to delete data. %s", err)
	}
	if deleted.DeletedCount != 1 {
		t.Errorf("Expected 1 document to be deleted, got %d", deleted.DeletedCount)
	}
	t.Logf("Number deleted %d", deleted.DeletedCount)
}

func TestClient_Collection(t *testing.T) {
	collection, err := client.Collection("test_collection")
	if err != nil {
		t.Errorf("something went wrong. %s", err)
	}
	if collection.Name() != "test_collection" {
		t.Errorf("Collection name incorrect")
	}
}

func TestClient_DB(t *testing.T) {
	db, err := client.Database()
	if err != nil {
		t.Fatalf("Failed to get database: %v", err)
	}
	if db.Name() != "test" {
		t.Errorf("Database name incorrect")
	}
}

func TestClient_FindByID(t *testing.T) {
	// Add a single test document
	testData := data{ID: "findbyid-test-unique", Name: "TestData"}
	ctx := context.Background()
	_, err := client.Add(ctx, "test_collection", testData)
	if err != nil {
		t.Fatalf("Unable to add test data: %s", err)
	}

	// Test FindByID - should find the single document
	var results []data
	err = client.FindByID(ctx, "test_collection", "findbyid-test-unique", &results)
	if err != nil {
		t.Fatalf("Unable to find by ID: %s", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 document, got %d", len(results))
	}

	if len(results) > 0 {
		if results[0].ID != "findbyid-test-unique" {
			t.Errorf("Expected ID 'findbyid-test-unique', got '%s'", results[0].ID)
		}
		if results[0].Name != "TestData" {
			t.Errorf("Expected Name 'TestData', got '%s'", results[0].Name)
		}
	}

	// Test with non-existent ID
	var emptyResults []data
	err = client.FindByID(ctx, "test_collection", "non-existent-id", &emptyResults)
	if err != nil {
		t.Fatalf("FindByID should not error for non-existent ID: %s", err)
	}
	if len(emptyResults) != 0 {
		t.Errorf("Expected 0 documents for non-existent ID, got %d", len(emptyResults))
	}
}

func TestClient_Ping(t *testing.T) {
	ctx := context.Background()
	err := client.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping failed: %s", err)
	}
	t.Logf("Ping successful")
}

func TestClient_IsConnected(t *testing.T) {
	// Use a separate client for this test to avoid interfering with others
	tempClient, err := NewMongoClient(client.ConnectionUrl, client.DatabaseName)
	if err != nil {
		t.Fatalf("Failed to create temp client: %v", err)
	}

	connected := tempClient.IsConnected()
	if !connected {
		t.Errorf("Expected client to be connected, but it's not")
	}
	t.Logf("Client connection status: %v", connected)

	err = tempClient.Close()
	if err != nil {
		t.Fatalf("Unable to close client: %s", err)
	}

	connected = tempClient.IsConnected()
	if connected {
		t.Errorf("Expected client to be disconnected after Close(), but it's still connected")
	}

	// Reconnect by performing an operation
	ctx := context.Background()
	err = tempClient.Ping(ctx)
	if err != nil {
		t.Fatalf("Unable to reconnect: %s", err)
	}

	connected = tempClient.IsConnected()
	if !connected {
		t.Errorf("Expected client to be connected after Ping(), but it's not")
	}
	t.Logf("Client reconnected successfully")
	tempClient.Close()
}

func TestClient_ExplicitEncryption(t *testing.T) {
	encryptedClient := setupEncryptedClient(t)
	ctx := context.Background()

	// 1. Create a new Data Encryption Key (DEK)
	dataKeyID, err := encryptedClient.CreateDataKey(ctx)
	if err != nil {
		t.Fatalf("Failed to create data key: %s", err)
	}
	if _, err := hex.DecodeString(dataKeyID); err != nil {
		t.Fatalf("CreateDataKey should return a hex-encoded string, but got an error decoding it: %v", err)
	}
	t.Logf("Successfully created data key with ID: %s", dataKeyID)

	// 2. Encrypt a value
	originalSecret := "my top secret value that is very long"
	// Use "AEAD_AES_256_CBC_HMAC_SHA_512-Random" for non-searchable encryption.
	algorithm := "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
	encryptedData, err := encryptedClient.Encrypt(ctx, dataKeyID, algorithm, originalSecret)
	if err != nil {
		t.Fatalf("Failed to encrypt value: %s", err)
	}
	if encryptedData.Subtype == 0 || len(encryptedData.Data) == 0 {
		t.Fatalf("Encrypt returned an empty bson.Binary: %+v", encryptedData)
	}
	t.Logf("Successfully encrypted data")

	// 3. Store the encrypted value
	type encryptedDoc struct {
		ID          string      `bson:"_id"`
		SecretField bson.Binary `bson:"secretField"`
	}
	docID := "explicit-doc-1"
	_, err = encryptedClient.Add(ctx, "explicit_test_coll", encryptedDoc{ID: docID, SecretField: encryptedData})
	if err != nil {
		t.Fatalf("Failed to add encrypted document: %s", err)
	}
	t.Logf("Successfully stored encrypted document with ID: %s", docID)

	// 4. Retrieve and decrypt
	var retrievedDoc encryptedDoc
	res := encryptedClient.GetCustom(ctx, "explicit_test_coll", bson.M{"_id": docID})
	if err := res.Err(); err != nil {
		t.Fatalf("Failed to retrieve encrypted document: %s", err)
	}
	if err = res.Decode(&retrievedDoc); err != nil {
		t.Fatalf("Failed to decode retrieved document: %s", err)
	}

	// 5. Decrypt the value
	decryptedRawValue, err := encryptedClient.Decrypt(ctx, retrievedDoc.SecretField)
	if err != nil {
		t.Fatalf("Failed to decrypt value: %s", err)
	}
	t.Logf("Successfully decrypted data")

	// 6. Unmarshal the BSON raw value back to a Go string
	var decryptedSecret string
	if err := decryptedRawValue.Unmarshal(&decryptedSecret); err != nil {
		t.Fatalf("Failed to unmarshal decrypted BSON value: %s", err)
	}

	// 7. Verify the result
	if originalSecret != decryptedSecret {
		t.Errorf("Decrypted secret does not match original. \nOriginal: %s\nDecrypted: %s", originalSecret, decryptedSecret)
	}
	t.Logf("Successfully verified decrypted secret matches original value.")
}

func TestClient_Aggregate(t *testing.T) {
	// Insert sample data
	testData := []interface{}{
		data{ID: "agg-1", Name: "Alice"},
		data{ID: "agg-2", Name: "Bob"},
		data{ID: "agg-3", Name: "Alice"},
	}
	ctx := context.Background()
	_, err := client.AddMany(ctx, "test_collection_agg", testData)
	if err != nil {
		t.Fatalf("Unable to add data for aggregation: %s", err)
	}
	t.Cleanup(func() {
		client.Collection("test_collection_agg")
	})

	// Aggregation pipeline: group by name and count
	pipeline := bson.A{
		bson.M{"$match": bson.M{"name": bson.M{"$in": bson.A{"Alice", "Bob"}}}},
		bson.M{"$group": bson.M{"_id": "$name", "count": bson.M{"$sum": 1}}},
		bson.M{"$sort": bson.M{"_id": 1}},
	}

	type aggResult struct {
		ID    string `bson:"_id"`
		Count int    `bson:"count"`
	}
	var results []aggResult

	err = client.Aggregate(ctx, "test_collection_agg", pipeline, &results)
	if err != nil {
		t.Fatalf("Aggregate failed: %s", err)
	}

	if len(results) != 2 {
		t.Fatalf("Expected 2 aggregation results, got %d", len(results))
	}
	if results[0].ID != "Alice" || results[0].Count != 2 {
		t.Errorf("Expected Alice to have count 2, got %d", results[0].Count)
	}
	if results[1].ID != "Bob" || results[1].Count != 1 {
		t.Errorf("Expected Bob to have count 1, got %d", results[1].Count)
	}

	// Test error on nil pipeline
	err = client.Aggregate(ctx, "test_collection_agg", nil, &results)
	if err == nil {
		t.Errorf("Expected error for nil pipeline, got nil")
	}

	// Test error on nil result
	err = client.Aggregate(ctx, "test_collection_agg", pipeline, nil)
	if err == nil {
		t.Errorf("Expected error for nil result, got nil")
	}
}

// TestMain runs last to clean up the database.
func TestMain(m *testing.M) {
	// Run all tests
	code := m.Run()

	// Clean up the main test database after all tests in the package have run
	if client != nil {
		err := client.DropDatabase(context.Background())
		if err != nil {
			// Log the error but don't fail the test run
			// as some tests might have already closed the client or dropped the DB.
			// In a real-world scenario, you might want more robust error handling here.
			// For this test suite, it's primarily for cleanup.
		}
		client.Close()
	}

	os.Exit(code)
}
