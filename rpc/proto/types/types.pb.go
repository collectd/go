// Code generated by protoc-gen-go.
// source: types.proto
// DO NOT EDIT!

/*
Package types is a generated protocol buffer package.

It is generated from these files:
	types.proto

It has these top-level messages:
	Identifier
	Value
	ValueList
*/
package types

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf "github.com/golang/protobuf/ptypes/duration"
import google_protobuf1 "github.com/golang/protobuf/ptypes/timestamp"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Identifier struct {
	Host           string `protobuf:"bytes,1,opt,name=host" json:"host,omitempty"`
	Plugin         string `protobuf:"bytes,2,opt,name=plugin" json:"plugin,omitempty"`
	PluginInstance string `protobuf:"bytes,3,opt,name=plugin_instance,json=pluginInstance" json:"plugin_instance,omitempty"`
	Type           string `protobuf:"bytes,4,opt,name=type" json:"type,omitempty"`
	TypeInstance   string `protobuf:"bytes,5,opt,name=type_instance,json=typeInstance" json:"type_instance,omitempty"`
}

func (m *Identifier) Reset()                    { *m = Identifier{} }
func (m *Identifier) String() string            { return proto.CompactTextString(m) }
func (*Identifier) ProtoMessage()               {}
func (*Identifier) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type Value struct {
	// Types that are valid to be assigned to Value:
	//	*Value_Counter
	//	*Value_Gauge
	//	*Value_Derive
	//	*Value_Absolute
	Value isValue_Value `protobuf_oneof:"value"`
}

func (m *Value) Reset()                    { *m = Value{} }
func (m *Value) String() string            { return proto.CompactTextString(m) }
func (*Value) ProtoMessage()               {}
func (*Value) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type isValue_Value interface {
	isValue_Value()
}

type Value_Counter struct {
	Counter uint64 `protobuf:"varint,1,opt,name=counter,oneof"`
}
type Value_Gauge struct {
	Gauge float64 `protobuf:"fixed64,2,opt,name=gauge,oneof"`
}
type Value_Derive struct {
	Derive int64 `protobuf:"varint,3,opt,name=derive,oneof"`
}
type Value_Absolute struct {
	Absolute uint64 `protobuf:"varint,4,opt,name=absolute,oneof"`
}

func (*Value_Counter) isValue_Value()  {}
func (*Value_Gauge) isValue_Value()    {}
func (*Value_Derive) isValue_Value()   {}
func (*Value_Absolute) isValue_Value() {}

func (m *Value) GetValue() isValue_Value {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *Value) GetCounter() uint64 {
	if x, ok := m.GetValue().(*Value_Counter); ok {
		return x.Counter
	}
	return 0
}

func (m *Value) GetGauge() float64 {
	if x, ok := m.GetValue().(*Value_Gauge); ok {
		return x.Gauge
	}
	return 0
}

func (m *Value) GetDerive() int64 {
	if x, ok := m.GetValue().(*Value_Derive); ok {
		return x.Derive
	}
	return 0
}

func (m *Value) GetAbsolute() uint64 {
	if x, ok := m.GetValue().(*Value_Absolute); ok {
		return x.Absolute
	}
	return 0
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Value) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Value_OneofMarshaler, _Value_OneofUnmarshaler, _Value_OneofSizer, []interface{}{
		(*Value_Counter)(nil),
		(*Value_Gauge)(nil),
		(*Value_Derive)(nil),
		(*Value_Absolute)(nil),
	}
}

func _Value_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Value)
	// value
	switch x := m.Value.(type) {
	case *Value_Counter:
		b.EncodeVarint(1<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.Counter))
	case *Value_Gauge:
		b.EncodeVarint(2<<3 | proto.WireFixed64)
		b.EncodeFixed64(math.Float64bits(x.Gauge))
	case *Value_Derive:
		b.EncodeVarint(3<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.Derive))
	case *Value_Absolute:
		b.EncodeVarint(4<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.Absolute))
	case nil:
	default:
		return fmt.Errorf("Value.Value has unexpected type %T", x)
	}
	return nil
}

func _Value_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Value)
	switch tag {
	case 1: // value.counter
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Value = &Value_Counter{x}
		return true, err
	case 2: // value.gauge
		if wire != proto.WireFixed64 {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeFixed64()
		m.Value = &Value_Gauge{math.Float64frombits(x)}
		return true, err
	case 3: // value.derive
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Value = &Value_Derive{int64(x)}
		return true, err
	case 4: // value.absolute
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Value = &Value_Absolute{x}
		return true, err
	default:
		return false, nil
	}
}

func _Value_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Value)
	// value
	switch x := m.Value.(type) {
	case *Value_Counter:
		n += proto.SizeVarint(1<<3 | proto.WireVarint)
		n += proto.SizeVarint(uint64(x.Counter))
	case *Value_Gauge:
		n += proto.SizeVarint(2<<3 | proto.WireFixed64)
		n += 8
	case *Value_Derive:
		n += proto.SizeVarint(3<<3 | proto.WireVarint)
		n += proto.SizeVarint(uint64(x.Derive))
	case *Value_Absolute:
		n += proto.SizeVarint(4<<3 | proto.WireVarint)
		n += proto.SizeVarint(uint64(x.Absolute))
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type ValueList struct {
	Value      []*Value                    `protobuf:"bytes,1,rep,name=value" json:"value,omitempty"`
	Time       *google_protobuf1.Timestamp `protobuf:"bytes,2,opt,name=time" json:"time,omitempty"`
	Interval   *google_protobuf.Duration   `protobuf:"bytes,3,opt,name=interval" json:"interval,omitempty"`
	Identifier *Identifier                 `protobuf:"bytes,4,opt,name=identifier" json:"identifier,omitempty"`
}

func (m *ValueList) Reset()                    { *m = ValueList{} }
func (m *ValueList) String() string            { return proto.CompactTextString(m) }
func (*ValueList) ProtoMessage()               {}
func (*ValueList) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *ValueList) GetValue() []*Value {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *ValueList) GetTime() *google_protobuf1.Timestamp {
	if m != nil {
		return m.Time
	}
	return nil
}

func (m *ValueList) GetInterval() *google_protobuf.Duration {
	if m != nil {
		return m.Interval
	}
	return nil
}

func (m *ValueList) GetIdentifier() *Identifier {
	if m != nil {
		return m.Identifier
	}
	return nil
}

func init() {
	proto.RegisterType((*Identifier)(nil), "collectd.types.Identifier")
	proto.RegisterType((*Value)(nil), "collectd.types.Value")
	proto.RegisterType((*ValueList)(nil), "collectd.types.ValueList")
}

func init() { proto.RegisterFile("types.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 371 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x64, 0x52, 0x4d, 0x4b, 0xc3, 0x40,
	0x10, 0x35, 0xb6, 0xe9, 0xc7, 0x44, 0x2b, 0x2c, 0x28, 0x31, 0x94, 0x2a, 0xf5, 0x60, 0x41, 0xd8,
	0x40, 0xc5, 0x8b, 0xc7, 0xe2, 0xc1, 0x82, 0xa7, 0x20, 0x1e, 0xbc, 0x48, 0x9a, 0x6c, 0xe3, 0x42,
	0x9a, 0x0d, 0xc9, 0xa6, 0x20, 0xf8, 0x4b, 0xfc, 0x6b, 0xfe, 0x19, 0x77, 0x67, 0x93, 0x54, 0xeb,
	0x29, 0x33, 0x6f, 0xde, 0xcc, 0xbc, 0xd9, 0x17, 0x70, 0xe4, 0x47, 0xce, 0x4a, 0x9a, 0x17, 0x42,
	0x0a, 0x32, 0x8a, 0x44, 0x9a, 0xb2, 0x48, 0xc6, 0x14, 0x51, 0x6f, 0x92, 0x08, 0x91, 0xa4, 0xcc,
	0xc7, 0xea, 0xaa, 0x5a, 0xfb, 0x71, 0x55, 0x84, 0x92, 0x8b, 0xcc, 0xf0, 0xbd, 0x8b, 0xfd, 0xba,
	0xe4, 0x1b, 0x56, 0xca, 0x70, 0x93, 0x1b, 0xc2, 0xf4, 0xcb, 0x02, 0x58, 0xc6, 0x2c, 0x93, 0x7c,
	0xcd, 0x59, 0x41, 0x08, 0x74, 0xdf, 0x45, 0x29, 0x5d, 0xeb, 0xd2, 0x9a, 0x0d, 0x03, 0x8c, 0xc9,
	0x19, 0xf4, 0xf2, 0xb4, 0x4a, 0x78, 0xe6, 0x1e, 0x22, 0x5a, 0x67, 0xe4, 0x1a, 0x4e, 0x4c, 0xf4,
	0xc6, 0x33, 0x35, 0x32, 0x8b, 0x98, 0xdb, 0x41, 0xc2, 0xc8, 0xc0, 0xcb, 0x1a, 0xd5, 0x43, 0xb5,
	0x5a, 0xb7, 0x6b, 0x86, 0xea, 0x98, 0x5c, 0xc1, 0xb1, 0xfe, 0xee, 0x5a, 0x6d, 0x2c, 0x1e, 0x69,
	0xb0, 0x69, 0x9c, 0x7e, 0x82, 0xfd, 0x12, 0xa6, 0x15, 0x23, 0x1e, 0xf4, 0x23, 0x51, 0x65, 0x92,
	0x15, 0xa8, 0xac, 0xfb, 0x78, 0x10, 0x34, 0x80, 0x92, 0x67, 0x27, 0x61, 0x95, 0x30, 0x54, 0x67,
	0xa9, 0x8a, 0x49, 0x89, 0x0b, 0xbd, 0x98, 0x15, 0x7c, 0x6b, 0x54, 0x75, 0x54, 0xa1, 0xce, 0xc9,
	0x18, 0x06, 0xe1, 0xaa, 0x14, 0x69, 0x25, 0x8d, 0x26, 0x3d, 0xae, 0x45, 0x16, 0x7d, 0xb0, 0xb7,
	0x7a, 0xe9, 0xf4, 0xdb, 0x82, 0x21, 0xae, 0x7f, 0xe2, 0xea, 0x15, 0x6e, 0x6a, 0x58, 0x09, 0xe8,
	0xcc, 0x9c, 0xf9, 0x29, 0xfd, 0xeb, 0x04, 0x45, 0x66, 0x60, 0x38, 0x84, 0xaa, 0x8b, 0xd5, 0x43,
	0xa3, 0x24, 0x67, 0xee, 0x51, 0xe3, 0x02, 0x6d, 0x5c, 0xa0, 0xcf, 0x8d, 0x0b, 0x01, 0xf2, 0xc8,
	0x1d, 0x0c, 0xb8, 0x3e, 0x46, 0x75, 0xa3, 0x5a, 0x67, 0x7e, 0xfe, 0xaf, 0xe7, 0xa1, 0x76, 0x36,
	0x68, 0xa9, 0xe4, 0x1e, 0x80, 0xb7, 0xde, 0xe1, 0x29, 0x7a, 0xd9, 0x9e, 0xb0, 0x9d, 0xbb, 0xc1,
	0x2f, 0xf6, 0x62, 0xf2, 0x3a, 0x6e, 0x89, 0xa2, 0x48, 0xfc, 0x22, 0x8f, 0xcc, 0x5f, 0xe2, 0x63,
	0xdb, 0xaa, 0x87, 0xc9, 0xed, 0x4f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x35, 0x26, 0xe0, 0x70, 0x7f,
	0x02, 0x00, 0x00,
}