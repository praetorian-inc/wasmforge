// Package objc is a low-level pure Go objective-c runtime sysshim for WasmForge.
// It routes all ObjC runtime calls through purego's SyscallN which in turn
// goes through the darwin bridge host functions.

//go:build wasip1

package objc

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sync"
	"unicode"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/internal/strings"
	"github.com/praetorian-inc/wasmforge/guest/darwin"
)

// Registered libobjc function pointers — populated by init().
var (
	objc_msgSend_fn            uintptr
	objc_msgSend               func(obj ID, cmd SEL, args ...any) ID
	objc_msgSendSuper2_fn      uintptr
	objc_msgSendSuper2         func(super *objc_super, cmd SEL, args ...any) ID
	objc_getClass_fn           func(name string) Class
	objc_getProtocol_fn        func(name string) *Protocol
	objc_allocateProtocol_fn   func(name string) *Protocol
	objc_registerProtocol_fn   func(protocol *Protocol)
	objc_allocateClassPair_fn  func(super Class, name string, extraBytes uintptr) Class
	objc_registerClassPair_fn  func(class Class)
	sel_registerName_fn        func(name string) SEL
	class_getSuperclass_fn     func(class Class) Class
	class_getInstanceVariable_fn func(class Class, name string) Ivar
	class_getInstanceSize_fn   func(class Class) uintptr
	class_addMethod_fn         func(class Class, name SEL, imp IMP, types string) bool
	class_addIvar_fn           func(class Class, name string, size uintptr, alignment uint8, types string) bool
	class_addProtocol_fn       func(class Class, protocol *Protocol) bool
	ivar_getOffset_fn          func(ivar Ivar) uintptr
	ivar_getName_fn            func(ivar Ivar) string
	object_getClass_fn         func(obj ID) Class
	object_getIvar_fn          func(obj ID, ivar Ivar) ID
	object_setIvar_fn          func(obj ID, ivar Ivar, value ID)
	protocol_getName_fn        func(protocol *Protocol) string
	protocol_isEqual_fn        func(p *Protocol, p2 *Protocol) bool
	free_fn                    func(ptr unsafe.Pointer)
	_Block_copy_fn             func(Block) Block
	_Block_release_fn          func(Block)
)

func init() {
	objc, err := purego.Dlopen("/usr/lib/libobjc.A.dylib", purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		panic(fmt.Errorf("objc: %w", err))
	}
	objc_msgSend_fn, err = purego.Dlsym(objc, "objc_msgSend")
	if err != nil {
		panic(fmt.Errorf("objc: %w", err))
	}
	purego.RegisterFunc(&objc_msgSend, objc_msgSend_fn)
	objc_msgSendSuper2_fn, err = purego.Dlsym(objc, "objc_msgSendSuper2")
	if err != nil {
		panic(fmt.Errorf("objc: %w", err))
	}
	purego.RegisterFunc(&objc_msgSendSuper2, objc_msgSendSuper2_fn)
	purego.RegisterLibFunc(&object_getClass_fn, objc, "object_getClass")
	purego.RegisterLibFunc(&objc_getClass_fn, objc, "objc_getClass")
	purego.RegisterLibFunc(&objc_getProtocol_fn, objc, "objc_getProtocol")
	purego.RegisterLibFunc(&objc_allocateProtocol_fn, objc, "objc_allocateProtocol")
	purego.RegisterLibFunc(&objc_registerProtocol_fn, objc, "objc_registerProtocol")
	purego.RegisterLibFunc(&objc_allocateClassPair_fn, objc, "objc_allocateClassPair")
	purego.RegisterLibFunc(&objc_registerClassPair_fn, objc, "objc_registerClassPair")
	purego.RegisterLibFunc(&sel_registerName_fn, objc, "sel_registerName")
	purego.RegisterLibFunc(&class_getSuperclass_fn, objc, "class_getSuperclass")
	purego.RegisterLibFunc(&class_getInstanceVariable_fn, objc, "class_getInstanceVariable")
	purego.RegisterLibFunc(&class_addMethod_fn, objc, "class_addMethod")
	purego.RegisterLibFunc(&class_addIvar_fn, objc, "class_addIvar")
	purego.RegisterLibFunc(&class_addProtocol_fn, objc, "class_addProtocol")
	purego.RegisterLibFunc(&class_getInstanceSize_fn, objc, "class_getInstanceSize")
	purego.RegisterLibFunc(&ivar_getOffset_fn, objc, "ivar_getOffset")
	purego.RegisterLibFunc(&ivar_getName_fn, objc, "ivar_getName")
	purego.RegisterLibFunc(&protocol_getName_fn, objc, "protocol_getName")
	purego.RegisterLibFunc(&protocol_isEqual_fn, objc, "protocol_isEqual")
	purego.RegisterLibFunc(&object_getIvar_fn, objc, "object_getIvar")
	purego.RegisterLibFunc(&object_setIvar_fn, objc, "object_setIvar")
	purego.RegisterLibFunc(&free_fn, purego.RTLD_DEFAULT, "free")
	purego.RegisterLibFunc(&_Block_copy_fn, objc, "_Block_copy")
	purego.RegisterLibFunc(&_Block_release_fn, objc, "_Block_release")
}

// ---------- Core Types ----------

// ID is an opaque pointer to some Objective-C object.
type ID uintptr

// Class returns the class of the object.
func (id ID) Class() Class {
	return object_getClass_fn(id)
}

// Send sends a message to the object.
func (id ID) Send(sel SEL, args ...any) ID {
	return objc_msgSend(id, sel, args...)
}

// GetIvar reads the value of an instance variable in an object.
func (id ID) GetIvar(ivar Ivar) ID {
	return object_getIvar_fn(id, ivar)
}

// SetIvar sets the value of an instance variable in an object.
func (id ID) SetIvar(ivar Ivar, value ID) {
	object_setIvar_fn(id, ivar, value)
}

const maxRegAllocStructSize = 16

// Send is a convenience method for sending messages to objects that can return any type.
// Note: objc_msgSend_stret is not registered in this sysshim. Struct returns >16 bytes
// on amd64 will panic. Validated guests only use pointer/integer returns via ObjC messaging.
func Send[T any](id ID, sel SEL, args ...any) T {
	var zero T
	if reflect.ValueOf(zero).Kind() == reflect.Struct &&
		reflect.ValueOf(zero).Type().Size() > maxRegAllocStructSize {
		panic("objc: struct returns >16 bytes not supported in wasmforge sysshim (no objc_msgSend_stret)")
	}
	var fn func(id ID, sel SEL, args ...any) T
	purego.RegisterFunc(&fn, objc_msgSend_fn)
	return fn(id, sel, args...)
}

// objc_super is the data structure for super message sends.
type objc_super struct {
	receiver   ID
	superClass Class
}

// SendSuper sends a message to the object's superclass.
func (id ID) SendSuper(sel SEL, args ...any) ID {
	super := &objc_super{
		receiver:   id,
		superClass: id.Class(),
	}
	return objc_msgSendSuper2(super, sel, args...)
}

// SendSuper is a convenience method for sending message to object's super that can return any type.
func SendSuper[T any](id ID, sel SEL, args ...any) T {
	var zero T
	if reflect.ValueOf(zero).Kind() == reflect.Struct &&
		reflect.ValueOf(zero).Type().Size() > maxRegAllocStructSize {
		panic("objc: struct returns >16 bytes not supported in wasmforge sysshim (no objc_msgSendSuper2_stret)")
	}
	super := &objc_super{
		receiver:   id,
		superClass: id.Class(),
	}
	var fn func(objcSuper *objc_super, sel SEL, args ...any) T
	purego.RegisterFunc(&fn, objc_msgSendSuper2_fn)
	return fn(super, sel, args...)
}

// SEL is an opaque type that represents a method selector.
type SEL uintptr

// RegisterName registers a method with the Objective-C runtime.
func RegisterName(name string) SEL {
	return sel_registerName_fn(name)
}

// Class is an opaque type that represents an Objective-C class.
type Class uintptr

// GetClass returns the Class object for the named class.
func GetClass(name string) Class {
	return objc_getClass_fn(name)
}

// SuperClass returns the superclass of a class.
func (c Class) SuperClass() Class {
	return class_getSuperclass_fn(c)
}

// AddMethod adds a new method to a class.
func (c Class) AddMethod(name SEL, imp IMP, types string) bool {
	return class_addMethod_fn(c, name, imp, types)
}

// AddProtocol adds a protocol to a class.
func (c Class) AddProtocol(protocol *Protocol) bool {
	return class_addProtocol_fn(c, protocol)
}

// InstanceSize returns the size in bytes of instances of the class.
func (c Class) InstanceSize() uintptr {
	return class_getInstanceSize_fn(c)
}

// InstanceVariable returns an Ivar for the instance variable specified by name.
func (c Class) InstanceVariable(name string) Ivar {
	return class_getInstanceVariable_fn(c, name)
}

// ---------- Ivar ----------

// Ivar is an opaque type that represents an instance variable.
type Ivar uintptr

// Offset returns the offset of the instance variable.
func (i Ivar) Offset() uintptr {
	return ivar_getOffset_fn(i)
}

// Name returns the name of the instance variable.
func (i Ivar) Name() string {
	return ivar_getName_fn(i)
}

// ---------- Protocol ----------

// Protocol is a type that declares methods that can be implemented by any class.
type Protocol [0]func()

// GetProtocol returns the protocol for the given name.
func GetProtocol(name string) *Protocol {
	return objc_getProtocol_fn(name)
}

// AllocateProtocol creates a new protocol in the ObjC runtime.
func AllocateProtocol(name string) *Protocol {
	return objc_allocateProtocol_fn(name)
}

// Register registers the protocol with the runtime.
func (p *Protocol) Register() {
	objc_registerProtocol_fn(p)
}

// Name returns the name of this protocol.
func (p *Protocol) Name() string {
	return protocol_getName_fn(p)
}

// Equals returns true if the two protocols are the same.
func (p *Protocol) Equals(p2 *Protocol) bool {
	return protocol_isEqual_fn(p, p2)
}

// ---------- Property / MethodDescription ----------

// PropertyAttribute contains the null-terminated Name and Value pair.
type PropertyAttribute struct {
	Name, Value *byte
}

// Property is an opaque type for Objective-C property metadata.
type Property uintptr

// MethodDescription holds the name and type definition of a method.
type MethodDescription struct {
	name, types uintptr
}

// Name returns the name of this method.
func (m MethodDescription) Name() string {
	return strings.GoString(m.name)
}

// Types returns the ObjC runtime encoded type description.
func (m MethodDescription) Types() string {
	return strings.GoString(m.types)
}

// IMP is a function pointer that can be called by Objective-C code.
type IMP uintptr

// ---------- IvarAttrib / FieldDef / MethodDef ----------

// IvarAttrib is the attribute for an ivar (affects auto-generated methods).
type IvarAttrib int

const (
	ReadOnly IvarAttrib = 1 << iota
	ReadWrite
)

// FieldDef is a definition of a field to add to an Objective-C class.
type FieldDef struct {
	Name      string
	Type      reflect.Type
	Attribute IvarAttrib
}

// MethodDef represents a Go function and the selector that ObjC uses.
type MethodDef struct {
	Cmd SEL
	Fn  any
}

// ivarRegex checks to make sure the Ivar is correctly formatted.
var ivarRegex = regexp.MustCompile("[a-z_][a-zA-Z0-9_]*")

// ---------- NewIMP ----------

// NewIMP takes a Go function that takes (ID, SEL) as its first two arguments.
// It returns an IMP function pointer.
func NewIMP(fn any) IMP {
	ty := reflect.TypeOf(fn)
	if ty.Kind() != reflect.Func {
		panic("objc: not a function")
	}
	switch {
	case ty.NumIn() < 2:
		fallthrough
	case ty.In(0) != reflect.TypeOf(ID(0)):
		fallthrough
	case ty.In(1) != reflect.TypeOf(SEL(0)):
		panic("objc: NewIMP must take a (id, SEL) as its first two arguments; got " + ty.String())
	}
	return IMP(purego.NewCallback(fn))
}

// ---------- Block ----------

// Block is an opaque pointer to an ObjC block object.
type Block ID

// Copy creates a copy of a block on the Objective-C heap.
func (b Block) Copy() Block {
	return _Block_copy_fn(b)
}

// Release decrements the Block's reference count.
func (b Block) Release() {
	_Block_release_fn(b)
}

// ---------- Block cache (simplified) ----------

const (
	blockBaseClassName = "__NSMallocBlock__"
	blockFlags         = (1 << 25) | (1 << 30) // blockHasCopyDispose | blockHasSignature
)

// blockLayout matches the ObjC Block ABI (Block_literal_1 from clang docs).
type blockLayout struct {
	isa        Class
	flags      uint32
	_          uint32
	invoke     uintptr
	descriptor *blockDescriptor
}

type blockDescriptor struct {
	_         uintptr
	size      uintptr
	_copy     uintptr
	dispose   uintptr
	signature *uint8
}

// blockFunctions keeps Go functions alive and maps blocks to their closures.
var blockFunctions struct {
	mu    sync.Mutex
	funcs map[Block]reflect.Value
}

func init() {
	blockFunctions.funcs = make(map[Block]reflect.Value)
}

// NewBlock takes a Go function that takes a Block as its first argument.
// It returns a Block that can be called by Objective-C code.
// Use Block.Release to free this block when it is no longer in use.
func NewBlock(fn any) Block {
	ty := reflect.TypeOf(fn)
	if ty == nil || ty.Kind() != reflect.Func {
		panic("objc: not a function")
	}
	if ty.NumIn() == 0 || ty.In(0) != reflect.TypeOf(Block(0)) {
		panic(fmt.Sprintf("objc: A Block implementation must take a Block as its first argument; got %v", ty.String()))
	}

	// Create a callback slot for the block's invoke function.
	// The dispatcher routes invocations through the blockFunctions cache.
	cbID, err := darwin.CreateCallback(ty.NumIn())
	if err != nil {
		panic("objc: NewBlock: " + err.Error())
	}

	// Build type signature for the ObjC runtime.
	sig := encodeBlockSignature(ty)

	// Construct the block entirely on the HOST side — ObjC's _Block_copy
	// dereferences pointers inside the layout (descriptor), so the layout
	// must live in host memory, not WASM linear memory.
	blockID, err := darwin.CreateBlock(cbID, sig)
	if err != nil {
		panic("objc: NewBlock CreateBlock: " + err.Error())
	}

	blockAddr, err := darwin.BlockAddr(blockID)
	if err != nil {
		panic("objc: NewBlock BlockAddr: " + err.Error())
	}
	block := Block(blockAddr)

	// Store the function for dispatch.
	blockFunctions.mu.Lock()
	blockFunctions.funcs[block] = reflect.ValueOf(fn)
	blockFunctions.mu.Unlock()

	// Spawn goroutine to service callback invocations.
	go func() {
		for {
			args, waitErr := darwin.WaitCallback(cbID)
			if waitErr != nil {
				return
			}
			// First arg is the block pointer itself.
			reflectArgs := make([]reflect.Value, ty.NumIn())
			for i := 0; i < ty.NumIn(); i++ {
				var arg uintptr
				if i < len(args) {
					arg = args[i]
				}
				inType := ty.In(i)
				switch inType {
				case reflect.TypeOf(Block(0)):
					reflectArgs[i] = reflect.ValueOf(Block(arg))
				default:
					switch inType.Kind() {
					case reflect.Uintptr:
						reflectArgs[i] = reflect.ValueOf(arg)
					case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
						reflectArgs[i] = reflect.ValueOf(arg).Convert(inType)
					case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
						reflectArgs[i] = reflect.ValueOf(int64(arg)).Convert(inType)
					default:
						reflectArgs[i] = reflect.ValueOf(arg).Convert(inType)
					}
				}
			}

			// Look up real function and call.
			blockFunctions.mu.Lock()
			realFn := blockFunctions.funcs[block]
			blockFunctions.mu.Unlock()

			var result uintptr
			if realFn.IsValid() {
				ret := realFn.Call(reflectArgs)
				if len(ret) > 0 {
					switch k := ret[0].Kind(); k {
					case reflect.Uint, reflect.Uint64, reflect.Uint32, reflect.Uint16, reflect.Uint8, reflect.Uintptr:
						result = uintptr(ret[0].Uint())
					case reflect.Int, reflect.Int64, reflect.Int32, reflect.Int16, reflect.Int8:
						result = uintptr(ret[0].Int())
					case reflect.Bool:
						if ret[0].Bool() {
							result = 1
						}
					}
				}
			}

			_ = darwin.ReturnCallback(cbID, result)
		}
	}()

	return block
}

// InvokeBlock is a convenience method for calling the implementation of a block.
func InvokeBlock[T any](block Block, args ...any) (result T, err error) {
	block = block.Copy()
	defer block.Release()

	blockFunctions.mu.Lock()
	fn := blockFunctions.funcs[block]
	blockFunctions.mu.Unlock()
	if !fn.IsValid() {
		return result, fmt.Errorf("objc: block function not found")
	}
	if fn.Type().NumIn() != len(args)+1 {
		return result, fmt.Errorf("objc: block callback expects %d arguments, got %d", fn.Type().NumIn()-1, len(args))
	}

	reflectedArgs := make([]reflect.Value, len(args)+1)
	reflectedArgs[0] = reflect.ValueOf(block)
	for i := range args {
		reflectedArgs[i+1] = reflect.ValueOf(args[i])
	}
	callResult := fn.Call(reflectedArgs)
	var ok bool
	result, ok = callResult[0].Interface().(T)
	if !ok {
		return result, fmt.Errorf("objc: the returned value type %s was not %T", callResult[0].Type().String(), result)
	}
	return result, nil
}

// encodeBlockSignature creates a null-terminated type encoding for a block function.
func encodeBlockSignature(typ reflect.Type) []byte {
	var encoding string
	switch typ.NumOut() {
	case 0:
		encoding = encVoid
	default:
		returnType, err := encodeType(typ.Out(0), false)
		if err != nil {
			encoding = encVoid
		} else {
			encoding = returnType
		}
	}
	encoding += encId // block self argument
	for i := 1; i < typ.NumIn(); i++ {
		argType, err := encodeType(typ.In(i), false)
		if err != nil {
			encoding += encUnsafePtr
		} else {
			encoding += argType
		}
	}
	return append([]byte(encoding), 0)
}

// ---------- Type encoding ----------

const (
	encId          = "@"
	encClass       = "#"
	encSelector    = ":"
	encChar        = "c"
	encUChar       = "C"
	encShort       = "s"
	encUShort      = "S"
	encInt         = "i"
	encUInt        = "I"
	encLong        = "l"
	encULong       = "L"
	encFloat       = "f"
	encDouble      = "d"
	encBool        = "B"
	encVoid        = "v"
	encPtr         = "^"
	encCharPtr     = "*"
	encStructBegin = "{"
	encStructEnd   = "}"
	encUnsafePtr   = "^v"
)

func encodeType(typ reflect.Type, insidePtr bool) (string, error) {
	switch typ {
	case reflect.TypeOf(Class(0)):
		return encClass, nil
	case reflect.TypeOf(ID(0)), reflect.TypeOf(Block(0)):
		return encId, nil
	case reflect.TypeOf(SEL(0)):
		return encSelector, nil
	}

	kind := typ.Kind()
	switch kind {
	case reflect.Bool:
		return encBool, nil
	case reflect.Int:
		return encLong, nil
	case reflect.Int8:
		return encChar, nil
	case reflect.Int16:
		return encShort, nil
	case reflect.Int32:
		return encInt, nil
	case reflect.Int64:
		return encULong, nil // matches upstream purego which incorrectly uses encULong for int64
	case reflect.Uint:
		return encULong, nil
	case reflect.Uint8:
		return encUChar, nil
	case reflect.Uint16:
		return encUShort, nil
	case reflect.Uint32:
		return encUInt, nil
	case reflect.Uint64:
		return encULong, nil
	case reflect.Uintptr:
		return encPtr, nil
	case reflect.Float32:
		return encFloat, nil
	case reflect.Float64:
		return encDouble, nil
	case reflect.Ptr:
		enc, err := encodeType(typ.Elem(), true)
		return encPtr + enc, err
	case reflect.Struct:
		if insidePtr {
			return encStructBegin + typ.Name() + encStructEnd, nil
		}
		encoding := encStructBegin + typ.Name() + "="
		for i := 0; i < typ.NumField(); i++ {
			tmp, err := encodeType(typ.Field(i).Type, false)
			if err != nil {
				return "", err
			}
			encoding += tmp
		}
		return encoding + encStructEnd, nil
	case reflect.UnsafePointer:
		return encUnsafePtr, nil
	case reflect.String:
		return encCharPtr, nil
	}

	return "", errors.New(fmt.Sprintf("unhandled/invalid kind %v typed %v", kind, typ))
}

func encodeFunc(fn any) (string, error) {
	typ := reflect.TypeOf(fn)
	if typ.Kind() != reflect.Func {
		return "", errors.New("not a func")
	}

	encoding := ""
	switch typ.NumOut() {
	case 0:
		encoding += encVoid
	case 1:
		tmp, err := encodeType(typ.Out(0), false)
		if err != nil {
			return "", err
		}
		encoding += tmp
	default:
		return "", errors.New("too many output parameters")
	}

	if typ.NumIn() < 2 {
		return "", errors.New("func doesn't take ID and SEL as its first two parameters")
	}

	encoding += encId
	for i := 1; i < typ.NumIn(); i++ {
		tmp, err := encodeType(typ.In(i), false)
		if err != nil {
			return "", err
		}
		encoding += tmp
	}
	return encoding, nil
}

// ---------- RegisterClass ----------

// RegisterClass creates a new Objective-C class at runtime.
func RegisterClass(name string, superClass Class, protocols []*Protocol, ivars []FieldDef, methods []MethodDef) (Class, error) {
	class := objc_allocateClassPair_fn(superClass, name, 0)
	if class == 0 {
		return 0, fmt.Errorf("objc: failed to create class with name '%s'", name)
	}
	for _, p := range protocols {
		if !class.AddProtocol(p) {
			return 0, fmt.Errorf("objc: couldn't add Protocol %s", protocol_getName_fn(p))
		}
	}
	for idx, def := range methods {
		imp, err := func() (imp IMP, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("objc: failed to create IMP: %s", r)
				}
			}()
			return NewIMP(def.Fn), nil
		}()
		if err != nil {
			return 0, fmt.Errorf("objc: couldn't add Method at index %d: %w", idx, err)
		}
		encoding, err := encodeFunc(def.Fn)
		if err != nil {
			return 0, fmt.Errorf("objc: couldn't add Method at index %d: %w", idx, err)
		}
		if !class.AddMethod(def.Cmd, imp, encoding) {
			return 0, fmt.Errorf("objc: couldn't add Method at index %d", idx)
		}
	}
	for _, instVar := range ivars {
		ivar := instVar
		if !ivarRegex.MatchString(ivar.Name) {
			return 0, fmt.Errorf("objc: Ivar must start with a lowercase letter and only contain ASCII letters and numbers: '%s'", ivar.Name)
		}
		size := ivar.Type.Size()
		alignment := uint8(math.Log2(float64(ivar.Type.Align())))
		enc, err := encodeType(ivar.Type, false)
		if err != nil {
			return 0, fmt.Errorf("objc: couldn't add Ivar %s: %w", ivar.Name, err)
		}
		if !class_addIvar_fn(class, ivar.Name, size, alignment, enc) {
			return 0, fmt.Errorf("objc: couldn't add Ivar %s", ivar.Name)
		}
		offset := class.InstanceVariable(ivar.Name).Offset()
		switch ivar.Attribute {
		case ReadWrite:
			ty := reflect.FuncOf(
				[]reflect.Type{reflect.TypeOf(ID(0)), reflect.TypeOf(SEL(0)), ivar.Type},
				nil, false,
			)
			val := reflect.MakeFunc(ty, func(args []reflect.Value) []reflect.Value {
				id := args[0].Interface().(ID)
				ptr := *(*unsafe.Pointer)(unsafe.Pointer(&id))
				reflect.NewAt(ivar.Type, unsafe.Add(ptr, offset)).Elem().Set(args[2])
				return nil
			}).Interface()
			selector := "set" + string(unicode.ToUpper(rune(ivar.Name[0]))) + ivar.Name[1:] + ":\x00"
			encoding, _ := encodeFunc(val)
			class.AddMethod(RegisterName(selector), NewIMP(val), encoding)
			fallthrough
		case ReadOnly:
			ty := reflect.FuncOf(
				[]reflect.Type{reflect.TypeOf(ID(0)), reflect.TypeOf(SEL(0))},
				[]reflect.Type{ivar.Type}, false,
			)
			val := reflect.MakeFunc(ty, func(args []reflect.Value) []reflect.Value {
				id := args[0].Interface().(ID)
				ptr := *(*unsafe.Pointer)(unsafe.Pointer(&id))
				return []reflect.Value{reflect.NewAt(ivar.Type, unsafe.Add(ptr, offset)).Elem()}
			}).Interface()
			readName := ivar.Name
			if ivar.Type.Kind() == reflect.Bool {
				readName = "is" + string(unicode.ToUpper(rune(ivar.Name[0]))) + ivar.Name[1:]
			}
			encoding, _ := encodeFunc(val)
			class.AddMethod(RegisterName(readName), NewIMP(val), encoding)
		default:
			return 0, fmt.Errorf("objc: unknown Ivar Attribute (%d)", ivar.Attribute)
		}
	}
	objc_registerClassPair_fn(class)
	return class, nil
}
