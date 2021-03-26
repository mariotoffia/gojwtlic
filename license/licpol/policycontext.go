package licpol

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// tag::prp[]

// PolicyRetrievalPointChange is determining the change type in a `PolicyRetrievalPoint`
type PolicyRetrievalPointChange int

const (
	// PolicyRetrievalPointChangeModuleAdded is set when a module has been added to the set
	PolicyRetrievalPointChangeModuleAdded PolicyRetrievalPointChange = 1
	// PolicyRetrievalPointChangeModuleRemovedis is set when a module has been removed from the set.
	PolicyRetrievalPointChangeModuleRemoved PolicyRetrievalPointChange = 2
)

// PolicyRetrievalPointChangeFunc is invoked by a _PRP_ when a underlying change has occurred.
type PolicyRetrievalPointChangeFunc func(p PolicyRetrievalPoint, module string, change PolicyRetrievalPointChange)

// PolicyRetrievalPoint is a data source for policies where the `PolicyContext` uses
// to load polices that are not manually registered.
type PolicyRetrievalPoint interface {
	// IsShareable determines if this instance may be shared by different contexts.
	//
	// This is often true to _PRPs_ that is static and loaded it's policies upon creation.
	IsShareable() bool

	// CanMutate specifies if this _PRP_ may mutate over time, i.e. after `Initialize`
	// has been called.
	//
	// Even local data, such as local filesystem _PRP_ may mutate, if it is not loading
	// *all* _policies_ directly.
	CanMutate() bool

	// HasRemoteDataSource is stating if this _PRP_ is getting it's policies from a remote
	// datasource or if it's local e.g. embedded or filesystem.
	HasRemoteDataSource() bool

	/// Initialize gives the _PRP_ a chance to initialize, if not yet has done so.
	//
	// CAUTION: This initialization may not exceed several hundreds of microseconds!
	//
	// It the implementation needs to load all policies, do this before this function is called.
	// If a caller specifies the _change_ function, the implementation is _REQUIRED_ to notify
	// the _change_ function!
	Initialize(c context.Context, change PolicyRetrievalPointChangeFunc)

	// GetModules returns all it's modules (even if those are not yet loaded)
	//
	// If the provider do not on forehand knows the module names it has in it's domain
	// get it reads from a datasource that is altering. If the _force_ is set to `true`
	// it will do a scan and return those.
	GetModuleNames(c context.Context, force bool) []string

	// GetModule returns a module by it's name.
	//
	// If the module is not yet loaded, and the implementation supports dynamic loading
	// it is _REQUIRED_ to try-load the module. If it fails, a empty module is returned.
	GetModule(c context.Context, name string) string

	// EvictModules will force the _PRP_ to unload the policies for specified modules
	// if it can.
	//
	// This only applicable on _PRPs_ that `CanMutate` returns `true`.
	EvictModules(modules []string)

	// GetModules will get all modules that this _PRP_ is manageing.
	//
	// If the _force_ flag is set to `true`, and it is able to dynamically load, it is
	// _REQUIRED_ to do a full scan and return *everything*.
	//
	// CAUTION: Since it may load vast amounts of policies if _force_ is set to `true`, hence use caution!!
	GetModules(c context.Context, force bool) map[string]string

	// Process is invoked when a `PolicyRetrievalPoint` cannot be executed in background. This gives the
	//
	// This gives the _PRP_ a small amount of time to do it's processing (if needed).
	Process(c context.Context)
}

// end::prp[]
// tag::policy-context[]

// PolicyContext is a context where polices operates under. It supports
// the notion of sub-context and hence local overrides in e.g policies may
// be registered. However, it will traverse the through parent until e.g.
// a policy that is searched for and hence all policies are reachable even
// on leafs.
type PolicyContext interface {
	// ClearError will clear any error state.
	ClearError() PolicyContext
	// Error returns the error state in this `PolicyContext`, if any.
	Error() error
	// CreateSubContext will create a sub-context and puts the current as Parent.
	//
	// If the current instance is set to error state, it will return the current instance
	// without creating a sub-context.
	CreateSubContext() PolicyContext
	// Parent is the parent context. If root context it will return `nil`
	Parent() PolicyContext
	// RegisterModules will register modules that may be used to create compiles.
	//
	// If a already module is registered it will skip it an register the rest and put
	// the instance to error state.
	RegisterModules(modules map[string]string) PolicyContext
	// RegisterModule will register a single module into the context.
	//
	// If already registered, it will set the context in error state.
	RegisterModule(name, module string) PolicyContext

	// RegisterPRP registers one or more `PolicyRetrievalPoint`.
	//
	// All `PolicyRetrievalPoint.Initialize` function will be invoked and must not been invoked earlier!
	RegisterPRP(c context.Context, p ...PolicyRetrievalPoint) PolicyContext

	// CompleModuleSet will lookup modules that has been earlier registered using
	// `RegisterModules` and create a single compilation of it. Since it is named,
	// it will set the `PolicyContext` to error state if already compiled. The compiles may
	// later on be used by `Policy()` since it is cached.
	//
	// If it is a sub policy and the _name_ do not exist in the sub-policy, it will register
	// it there and hence _override_ the parent compile. If any of the modules specified do not
	// exist, it will not compile and set the context into error state.
	CompileModuleSet(name string, module ...string) PolicyContext
	// Policy will return the policy earlier compiled using `CompileModuleSet`. If it fails
	// is will return nil and set an error state.
	Policy(name string) *ast.Compiler
	// NewEval is *exactly* the same as `rego.New()` but gives the `PolicyContext` the ability to
	// do custom processing.
	NewEval(options ...func(r *rego.Rego)) *rego.Rego
}

// end::policy-context[]

// policyContext implements the `PolicyContext` interface.
type policyContext struct {
	err      error
	parent   *policyContext
	modules  map[string]string
	compiled map[string]*ast.Compiler
	prp      []PolicyRetrievalPoint
}

// New creates a new `PolicyContext` compatible instance.
func New() PolicyContext {

	return &policyContext{
		modules:  map[string]string{},
		compiled: map[string]*ast.Compiler{},
	}
}

func (pc *policyContext) RegisterPRP(c context.Context, p ...PolicyRetrievalPoint) PolicyContext {

	for i := range p {

		p[i].Initialize(c, nil)

	}

	pc.prp = append(pc.prp, p...)
	return pc
}

// ClearError will clear any error state.
func (pc *policyContext) ClearError() PolicyContext {
	pc.err = nil
	return pc
}

// Error returns the error state in this `PolicyContext`, if any.
func (pc *policyContext) Error() error {
	return pc.err
}

// CreateSubContext will create a sub-context and puts the current as Parent.
func (pc *policyContext) CreateSubContext() PolicyContext {

	if pc.err != nil {
		return pc
	}

	return &policyContext{
		parent: pc,
	}

}

// Parent is the parent context. If root context it will return `nil`
func (pc *policyContext) Parent() PolicyContext {
	return pc.parent
}

// Registers modules that may be used to create compiles.
func (pc *policyContext) RegisterModules(modules map[string]string) PolicyContext {

	if pc.err != nil {
		return pc
	}

	for k, v := range modules {

		if _, ok := pc.modules[k]; ok {
			pc.err = fmt.Errorf("module %s already registered", k)
		} else {
			pc.modules[k] = v
		}

	}

	return pc
}

// Registers modules that may be used to create compiles.
func (pc *policyContext) RegisterModule(name, module string) PolicyContext {

	if pc.err != nil {
		return pc
	}

	if _, ok := pc.modules[name]; ok {
		pc.err = fmt.Errorf("module %s already registered", name)
	} else {
		pc.modules[name] = module
	}

	return pc
}

// CompleModuleSet will lookup modules that has been earlier registered using
// `RegisterModules` and create a single compilation of it. Since it is named,
// it will set the `PolicyContext` to error state if already compiled. The compiles may
// later on be used by `Policy()` since it is cached.
//
// If it is a sub policy and the _name_ do not exist in the sub-policy, it will register
// it there and hence _override_ the parent compile.
func (pc *policyContext) CompileModuleSet(name string, module ...string) PolicyContext {

	if pc.err != nil {
		return pc
	}

	if _, ok := pc.compiled[name]; ok {
		pc.err = fmt.Errorf("compiled policy %s already present", name)
	}

	m := map[string]string{}
	for _, mod := range module {

		if v, ok := pc.modules[mod]; ok {
			m[mod] = v
		} else {

			v := pc.getModuleFromParent(mod)

			if v != "" {
				m[mod] = v
			} else {
				pc.err = fmt.Errorf("could not find module %s while compiling", mod)
				return nil
			}

		}

	}

	comp, err := ast.CompileModules(m)

	if err != nil {
		pc.err = err
	} else {
		pc.compiled[name] = comp
	}

	return pc
}

// Policy will return the policy earlier compiled using `CompileModuleSet`. If it fails
// is will return nil and set an error state.
func (pc *policyContext) Policy(name string) *ast.Compiler {

	if pc.err != nil {
		return nil
	}

	if comp, ok := pc.compiled[name]; ok {
		return comp
	}

	pc.err = fmt.Errorf("compiled policy %s do not exist", name)
	return nil

}

// NewEval is *exactly* the same as `rego.New()`.
func (pc *policyContext) NewEval(options ...func(r *rego.Rego)) *rego.Rego {

	if pc.err != nil {
		return nil
	}

	return rego.New(options...)
}

// getModuleFromParent searches the whole parent chain for a module.
//
// If not found an empty string is returned.
func (pc *policyContext) getModuleFromParent(module string) string {

	parent := pc.parent
	if parent == nil {
		return ""
	}

	if v, ok := parent.modules[module]; ok {
		return v
	}

	return parent.getModuleFromParent(module)
}
