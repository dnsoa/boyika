// Code generated by protoc-gen-go. DO NOT EDIT.
// source: db.proto

package main

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type DB struct {
	Hosts                []*Record `protobuf:"bytes,1,rep,name=hosts,proto3" json:"hosts,omitempty"`
	BlockName            []string  `protobuf:"bytes,2,rep,name=block_name,json=blockName,proto3" json:"block_name,omitempty"`
	BlockIp              []string  `protobuf:"bytes,3,rep,name=block_ip,json=blockIp,proto3" json:"block_ip,omitempty"`
	Forward              []*Finder `protobuf:"bytes,4,rep,name=forward,proto3" json:"forward,omitempty"`
	Doh                  []*Finder `protobuf:"bytes,5,rep,name=doh,proto3" json:"doh,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *DB) Reset()         { *m = DB{} }
func (m *DB) String() string { return proto.CompactTextString(m) }
func (*DB) ProtoMessage()    {}
func (*DB) Descriptor() ([]byte, []int) {
	return fileDescriptor_db_05be1f06b654f47b, []int{0}
}
func (m *DB) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DB.Unmarshal(m, b)
}
func (m *DB) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DB.Marshal(b, m, deterministic)
}
func (dst *DB) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DB.Merge(dst, src)
}
func (m *DB) XXX_Size() int {
	return xxx_messageInfo_DB.Size(m)
}
func (m *DB) XXX_DiscardUnknown() {
	xxx_messageInfo_DB.DiscardUnknown(m)
}

var xxx_messageInfo_DB proto.InternalMessageInfo

func (m *DB) GetHosts() []*Record {
	if m != nil {
		return m.Hosts
	}
	return nil
}

func (m *DB) GetBlockName() []string {
	if m != nil {
		return m.BlockName
	}
	return nil
}

func (m *DB) GetBlockIp() []string {
	if m != nil {
		return m.BlockIp
	}
	return nil
}

func (m *DB) GetForward() []*Finder {
	if m != nil {
		return m.Forward
	}
	return nil
}

func (m *DB) GetDoh() []*Finder {
	if m != nil {
		return m.Doh
	}
	return nil
}

type Finder struct {
	Name                 []string `protobuf:"bytes,1,rep,name=name,proto3" json:"name,omitempty"`
	Domain               []string `protobuf:"bytes,2,rep,name=domain,proto3" json:"domain,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Finder) Reset()         { *m = Finder{} }
func (m *Finder) String() string { return proto.CompactTextString(m) }
func (*Finder) ProtoMessage()    {}
func (*Finder) Descriptor() ([]byte, []int) {
	return fileDescriptor_db_05be1f06b654f47b, []int{1}
}
func (m *Finder) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Finder.Unmarshal(m, b)
}
func (m *Finder) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Finder.Marshal(b, m, deterministic)
}
func (dst *Finder) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Finder.Merge(dst, src)
}
func (m *Finder) XXX_Size() int {
	return xxx_messageInfo_Finder.Size(m)
}
func (m *Finder) XXX_DiscardUnknown() {
	xxx_messageInfo_Finder.DiscardUnknown(m)
}

var xxx_messageInfo_Finder proto.InternalMessageInfo

func (m *Finder) GetName() []string {
	if m != nil {
		return m.Name
	}
	return nil
}

func (m *Finder) GetDomain() []string {
	if m != nil {
		return m.Domain
	}
	return nil
}

type Record struct {
	Pattern              string   `protobuf:"bytes,1,opt,name=pattern,proto3" json:"pattern,omitempty"`
	Data                 string   `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Record) Reset()         { *m = Record{} }
func (m *Record) String() string { return proto.CompactTextString(m) }
func (*Record) ProtoMessage()    {}
func (*Record) Descriptor() ([]byte, []int) {
	return fileDescriptor_db_05be1f06b654f47b, []int{2}
}
func (m *Record) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Record.Unmarshal(m, b)
}
func (m *Record) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Record.Marshal(b, m, deterministic)
}
func (dst *Record) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Record.Merge(dst, src)
}
func (m *Record) XXX_Size() int {
	return xxx_messageInfo_Record.Size(m)
}
func (m *Record) XXX_DiscardUnknown() {
	xxx_messageInfo_Record.DiscardUnknown(m)
}

var xxx_messageInfo_Record proto.InternalMessageInfo

func (m *Record) GetPattern() string {
	if m != nil {
		return m.Pattern
	}
	return ""
}

func (m *Record) GetData() string {
	if m != nil {
		return m.Data
	}
	return ""
}

func init() {
	proto.RegisterType((*DB)(nil), "main.DB")
	proto.RegisterType((*Finder)(nil), "main.Finder")
	proto.RegisterType((*Record)(nil), "main.Record")
}

func init() { proto.RegisterFile("db.proto", fileDescriptor_db_05be1f06b654f47b) }

var fileDescriptor_db_05be1f06b654f47b = []byte{
	// 225 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x90, 0xc1, 0x4a, 0xc4, 0x30,
	0x10, 0x86, 0x49, 0xdb, 0x6d, 0x77, 0x47, 0x4f, 0x73, 0x90, 0xf1, 0xa0, 0x94, 0x1e, 0x64, 0x4f,
	0x3d, 0xa8, 0xf8, 0x00, 0x22, 0x82, 0x17, 0x0f, 0x79, 0x01, 0x49, 0x37, 0x91, 0x2d, 0xda, 0x4c,
	0xc8, 0x06, 0x7c, 0x27, 0x9f, 0x52, 0x32, 0xa9, 0xe0, 0xc1, 0xdb, 0x7c, 0xf3, 0x25, 0x93, 0x3f,
	0x03, 0x5b, 0x3b, 0x8d, 0x21, 0x72, 0x62, 0x6c, 0x16, 0x33, 0xfb, 0xe1, 0x5b, 0x41, 0xf5, 0xf4,
	0x88, 0x03, 0x6c, 0x8e, 0x7c, 0x4a, 0x27, 0x52, 0x7d, 0xbd, 0x3f, 0xbb, 0x3d, 0x1f, 0xb3, 0x1c,
	0xb5, 0x3b, 0x70, 0xb4, 0xba, 0x28, 0xbc, 0x02, 0x98, 0x3e, 0xf9, 0xf0, 0xf1, 0xe6, 0xcd, 0xe2,
	0xa8, 0xea, 0xeb, 0xfd, 0x4e, 0xef, 0xa4, 0xf3, 0x6a, 0x16, 0x87, 0x97, 0xb0, 0x2d, 0x7a, 0x0e,
	0x54, 0x8b, 0xec, 0x84, 0x5f, 0x02, 0xde, 0x40, 0xf7, 0xce, 0xf1, 0xcb, 0x44, 0x4b, 0xcd, 0xdf,
	0xf9, 0xcf, 0xb3, 0xb7, 0x2e, 0xea, 0x5f, 0x89, 0xd7, 0x50, 0x5b, 0x3e, 0xd2, 0xe6, 0x9f, 0x33,
	0x59, 0x0c, 0xf7, 0xd0, 0x16, 0x44, 0x84, 0x46, 0x52, 0x28, 0x79, 0x48, 0x6a, 0xbc, 0x80, 0xd6,
	0x72, 0xbe, 0xb3, 0x66, 0x5b, 0x69, 0x78, 0x80, 0xb6, 0x7c, 0x04, 0x09, 0xba, 0x60, 0x52, 0x72,
	0xd1, 0x93, 0xea, 0x55, 0x4e, 0xb8, 0x62, 0x9e, 0x67, 0x4d, 0x32, 0x54, 0x49, 0x5b, 0xea, 0xa9,
	0x95, 0x3d, 0xdd, 0xfd, 0x04, 0x00, 0x00, 0xff, 0xff, 0x38, 0x30, 0xb0, 0xf1, 0x33, 0x01, 0x00,
	0x00,
}
