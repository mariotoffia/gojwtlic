package licpol

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

// InMemStoreBuilder is a simple builder to create a opa storeage for in memory use.
type InMemStoreBuilder struct {
	err  error
	data map[string]map[string]interface{}
	ctx  context.Context
}

// NewInMemStoreBuilder creates a new in-memory store builder
func NewInMemStoreBuilder(ctx context.Context) *InMemStoreBuilder {

	return &InMemStoreBuilder{
		data: map[string]map[string]interface{}{},
		ctx:  ctx,
	}

}

// Error returns the current error state.
func (isb *InMemStoreBuilder) Error() error {

	return isb.err

}

// ClearError will clear any error state.
func (isb *InMemStoreBuilder) ClearError() *InMemStoreBuilder {

	isb.err = nil
	return isb

}

// Add will add a single data-set with a specified path. The path is separated with a '/'.
func (isb *InMemStoreBuilder) Add(path string, data map[string]interface{}) *InMemStoreBuilder {

	if isb.err != nil {
		return isb
	}

	if _, ok := isb.data[path]; ok {
		isb.err = fmt.Errorf("already exists data for path %s", path)
		return isb
	}

	isb.data[path] = data
	return isb

}

// AddJSON will add a single _JSON_ datafile to the in memory store. The path is separated with '/'.
func (isb *InMemStoreBuilder) AddJSON(path, json string) *InMemStoreBuilder {

	if isb.err != nil {
		return isb
	}

	var jsonData map[string]interface{}

	if err := util.UnmarshalJSON([]byte(json), &jsonData); err != nil {
		isb.err = err
		return isb
	}

	return isb.Add(path, jsonData)

}

// Build will iterate all paths and build up a in-memory store.
func (isb *InMemStoreBuilder) Build() storage.Store {

	if isb.err != nil {
		return nil
	}

	store := inmem.New()

	txn, err := store.NewTransaction(isb.ctx, storage.WriteParams)
	if err != nil {
		isb.err = err
		return nil
	}

	for k, v := range isb.data {

		if err := store.Write(isb.ctx, txn, storage.AddOp, strings.Split(k, "/"), v); err != nil {
			isb.err = err
			return nil
		}

	}

	if err := store.Commit(isb.ctx, txn); err != nil {
		isb.err = err
		return nil
	}

	return store

}
