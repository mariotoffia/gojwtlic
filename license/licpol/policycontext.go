package licpol

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

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

// policyContext implements the `PolicyContext` interface.
type policyContext struct {
	err      error
	parent   *policyContext
	modules  map[string]string
	compiled map[string]*ast.Compiler
}

// New creates a new `PolicyContext` compatible instance.
func New() PolicyContext {

	return &policyContext{
		modules:  map[string]string{},
		compiled: map[string]*ast.Compiler{},
	}
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
