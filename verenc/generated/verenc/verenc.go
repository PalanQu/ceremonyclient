package verenc

// #include <verenc.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"unsafe"
)

// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromExternal(b RustBufferI) GoRustBuffer {
	return GoRustBuffer{
		inner: C.RustBuffer{
			capacity: C.uint64_t(b.Capacity()),
			len:      C.uint64_t(b.Len()),
			data:     (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_verenc_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}

func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_verenc_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[E any, U any](converter BufReader[*E], callback func(*C.RustCallStatus) U) (U, *E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[*E], status C.RustCallStatus) *E {
	switch status.code {
	case 0:
		return nil
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer{inner: status.errorBuf})
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{inner: status.errorBuf})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 26
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_verenc_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("verenc: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_chunk_data_for_verenc()
		})
		if checksum != 8132 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_chunk_data_for_verenc: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_combine_chunked_data()
		})
		if checksum != 5526 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_combine_chunked_data: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_new_verenc_proof()
		})
		if checksum != 22642 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_new_verenc_proof: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_new_verenc_proof_encrypt_only()
		})
		if checksum != 2570 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_new_verenc_proof_encrypt_only: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_verenc_compress()
		})
		if checksum != 65383 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_verenc_compress: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_verenc_recover()
		})
		if checksum != 24917 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_verenc_recover: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_verenc_verify()
		})
		if checksum != 28186 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_verenc_verify: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_verenc_checksum_func_verenc_verify_statement()
		})
		if checksum != 17821 {
			// If this happens try cleaning and rebuilding your project
			panic("verenc: uniffi_verenc_checksum_func_verenc_verify_statement: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint8 struct{}

var FfiConverterUint8INSTANCE = FfiConverterUint8{}

func (FfiConverterUint8) Lower(value uint8) C.uint8_t {
	return C.uint8_t(value)
}

func (FfiConverterUint8) Write(writer io.Writer, value uint8) {
	writeUint8(writer, value)
}

func (FfiConverterUint8) Lift(value C.uint8_t) uint8 {
	return uint8(value)
}

func (FfiConverterUint8) Read(reader io.Reader) uint8 {
	return readUint8(reader)
}

type FfiDestroyerUint8 struct{}

func (FfiDestroyerUint8) Destroy(_ uint8) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct{}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterBool struct{}

var FfiConverterBoolINSTANCE = FfiConverterBool{}

func (FfiConverterBool) Lower(value bool) C.int8_t {
	if value {
		return C.int8_t(1)
	}
	return C.int8_t(0)
}

func (FfiConverterBool) Write(writer io.Writer, value bool) {
	if value {
		writeInt8(writer, 1)
	} else {
		writeInt8(writer, 0)
	}
}

func (FfiConverterBool) Lift(value C.int8_t) bool {
	return value != 0
}

func (FfiConverterBool) Read(reader io.Reader) bool {
	return readInt8(reader) != 0
}

type FfiDestroyerBool struct{}

func (FfiDestroyerBool) Destroy(_ bool) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

type CompressedCiphertext struct {
	Ctexts []VerencCiphertext
	Aux    [][]uint8
}

func (r *CompressedCiphertext) Destroy() {
	FfiDestroyerSequenceVerencCiphertext{}.Destroy(r.Ctexts)
	FfiDestroyerSequenceSequenceUint8{}.Destroy(r.Aux)
}

type FfiConverterCompressedCiphertext struct{}

var FfiConverterCompressedCiphertextINSTANCE = FfiConverterCompressedCiphertext{}

func (c FfiConverterCompressedCiphertext) Lift(rb RustBufferI) CompressedCiphertext {
	return LiftFromRustBuffer[CompressedCiphertext](c, rb)
}

func (c FfiConverterCompressedCiphertext) Read(reader io.Reader) CompressedCiphertext {
	return CompressedCiphertext{
		FfiConverterSequenceVerencCiphertextINSTANCE.Read(reader),
		FfiConverterSequenceSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterCompressedCiphertext) Lower(value CompressedCiphertext) C.RustBuffer {
	return LowerIntoRustBuffer[CompressedCiphertext](c, value)
}

func (c FfiConverterCompressedCiphertext) Write(writer io.Writer, value CompressedCiphertext) {
	FfiConverterSequenceVerencCiphertextINSTANCE.Write(writer, value.Ctexts)
	FfiConverterSequenceSequenceUint8INSTANCE.Write(writer, value.Aux)
}

type FfiDestroyerCompressedCiphertext struct{}

func (_ FfiDestroyerCompressedCiphertext) Destroy(value CompressedCiphertext) {
	value.Destroy()
}

type VerencCiphertext struct {
	C1 []uint8
	C2 []uint8
	I  uint64
}

func (r *VerencCiphertext) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.C1)
	FfiDestroyerSequenceUint8{}.Destroy(r.C2)
	FfiDestroyerUint64{}.Destroy(r.I)
}

type FfiConverterVerencCiphertext struct{}

var FfiConverterVerencCiphertextINSTANCE = FfiConverterVerencCiphertext{}

func (c FfiConverterVerencCiphertext) Lift(rb RustBufferI) VerencCiphertext {
	return LiftFromRustBuffer[VerencCiphertext](c, rb)
}

func (c FfiConverterVerencCiphertext) Read(reader io.Reader) VerencCiphertext {
	return VerencCiphertext{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterVerencCiphertext) Lower(value VerencCiphertext) C.RustBuffer {
	return LowerIntoRustBuffer[VerencCiphertext](c, value)
}

func (c FfiConverterVerencCiphertext) Write(writer io.Writer, value VerencCiphertext) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.C1)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.C2)
	FfiConverterUint64INSTANCE.Write(writer, value.I)
}

type FfiDestroyerVerencCiphertext struct{}

func (_ FfiDestroyerVerencCiphertext) Destroy(value VerencCiphertext) {
	value.Destroy()
}

type VerencDecrypt struct {
	BlindingPubkey []uint8
	DecryptionKey  []uint8
	Statement      []uint8
	Ciphertexts    CompressedCiphertext
}

func (r *VerencDecrypt) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.BlindingPubkey)
	FfiDestroyerSequenceUint8{}.Destroy(r.DecryptionKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.Statement)
	FfiDestroyerCompressedCiphertext{}.Destroy(r.Ciphertexts)
}

type FfiConverterVerencDecrypt struct{}

var FfiConverterVerencDecryptINSTANCE = FfiConverterVerencDecrypt{}

func (c FfiConverterVerencDecrypt) Lift(rb RustBufferI) VerencDecrypt {
	return LiftFromRustBuffer[VerencDecrypt](c, rb)
}

func (c FfiConverterVerencDecrypt) Read(reader io.Reader) VerencDecrypt {
	return VerencDecrypt{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterCompressedCiphertextINSTANCE.Read(reader),
	}
}

func (c FfiConverterVerencDecrypt) Lower(value VerencDecrypt) C.RustBuffer {
	return LowerIntoRustBuffer[VerencDecrypt](c, value)
}

func (c FfiConverterVerencDecrypt) Write(writer io.Writer, value VerencDecrypt) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.BlindingPubkey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.DecryptionKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Statement)
	FfiConverterCompressedCiphertextINSTANCE.Write(writer, value.Ciphertexts)
}

type FfiDestroyerVerencDecrypt struct{}

func (_ FfiDestroyerVerencDecrypt) Destroy(value VerencDecrypt) {
	value.Destroy()
}

type VerencProof struct {
	BlindingPubkey []uint8
	EncryptionKey  []uint8
	Statement      []uint8
	Challenge      []uint8
	Polycom        [][]uint8
	Ctexts         []VerencCiphertext
	SharesRands    []VerencShare
}

func (r *VerencProof) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.BlindingPubkey)
	FfiDestroyerSequenceUint8{}.Destroy(r.EncryptionKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.Statement)
	FfiDestroyerSequenceUint8{}.Destroy(r.Challenge)
	FfiDestroyerSequenceSequenceUint8{}.Destroy(r.Polycom)
	FfiDestroyerSequenceVerencCiphertext{}.Destroy(r.Ctexts)
	FfiDestroyerSequenceVerencShare{}.Destroy(r.SharesRands)
}

type FfiConverterVerencProof struct{}

var FfiConverterVerencProofINSTANCE = FfiConverterVerencProof{}

func (c FfiConverterVerencProof) Lift(rb RustBufferI) VerencProof {
	return LiftFromRustBuffer[VerencProof](c, rb)
}

func (c FfiConverterVerencProof) Read(reader io.Reader) VerencProof {
	return VerencProof{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceVerencCiphertextINSTANCE.Read(reader),
		FfiConverterSequenceVerencShareINSTANCE.Read(reader),
	}
}

func (c FfiConverterVerencProof) Lower(value VerencProof) C.RustBuffer {
	return LowerIntoRustBuffer[VerencProof](c, value)
}

func (c FfiConverterVerencProof) Write(writer io.Writer, value VerencProof) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.BlindingPubkey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.EncryptionKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Statement)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Challenge)
	FfiConverterSequenceSequenceUint8INSTANCE.Write(writer, value.Polycom)
	FfiConverterSequenceVerencCiphertextINSTANCE.Write(writer, value.Ctexts)
	FfiConverterSequenceVerencShareINSTANCE.Write(writer, value.SharesRands)
}

type FfiDestroyerVerencProof struct{}

func (_ FfiDestroyerVerencProof) Destroy(value VerencProof) {
	value.Destroy()
}

type VerencProofAndBlindingKey struct {
	BlindingKey    []uint8
	BlindingPubkey []uint8
	DecryptionKey  []uint8
	EncryptionKey  []uint8
	Statement      []uint8
	Challenge      []uint8
	Polycom        [][]uint8
	Ctexts         []VerencCiphertext
	SharesRands    []VerencShare
}

func (r *VerencProofAndBlindingKey) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.BlindingKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.BlindingPubkey)
	FfiDestroyerSequenceUint8{}.Destroy(r.DecryptionKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.EncryptionKey)
	FfiDestroyerSequenceUint8{}.Destroy(r.Statement)
	FfiDestroyerSequenceUint8{}.Destroy(r.Challenge)
	FfiDestroyerSequenceSequenceUint8{}.Destroy(r.Polycom)
	FfiDestroyerSequenceVerencCiphertext{}.Destroy(r.Ctexts)
	FfiDestroyerSequenceVerencShare{}.Destroy(r.SharesRands)
}

type FfiConverterVerencProofAndBlindingKey struct{}

var FfiConverterVerencProofAndBlindingKeyINSTANCE = FfiConverterVerencProofAndBlindingKey{}

func (c FfiConverterVerencProofAndBlindingKey) Lift(rb RustBufferI) VerencProofAndBlindingKey {
	return LiftFromRustBuffer[VerencProofAndBlindingKey](c, rb)
}

func (c FfiConverterVerencProofAndBlindingKey) Read(reader io.Reader) VerencProofAndBlindingKey {
	return VerencProofAndBlindingKey{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceVerencCiphertextINSTANCE.Read(reader),
		FfiConverterSequenceVerencShareINSTANCE.Read(reader),
	}
}

func (c FfiConverterVerencProofAndBlindingKey) Lower(value VerencProofAndBlindingKey) C.RustBuffer {
	return LowerIntoRustBuffer[VerencProofAndBlindingKey](c, value)
}

func (c FfiConverterVerencProofAndBlindingKey) Write(writer io.Writer, value VerencProofAndBlindingKey) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.BlindingKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.BlindingPubkey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.DecryptionKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.EncryptionKey)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Statement)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Challenge)
	FfiConverterSequenceSequenceUint8INSTANCE.Write(writer, value.Polycom)
	FfiConverterSequenceVerencCiphertextINSTANCE.Write(writer, value.Ctexts)
	FfiConverterSequenceVerencShareINSTANCE.Write(writer, value.SharesRands)
}

type FfiDestroyerVerencProofAndBlindingKey struct{}

func (_ FfiDestroyerVerencProofAndBlindingKey) Destroy(value VerencProofAndBlindingKey) {
	value.Destroy()
}

type VerencShare struct {
	S1 []uint8
	S2 []uint8
	I  uint64
}

func (r *VerencShare) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.S1)
	FfiDestroyerSequenceUint8{}.Destroy(r.S2)
	FfiDestroyerUint64{}.Destroy(r.I)
}

type FfiConverterVerencShare struct{}

var FfiConverterVerencShareINSTANCE = FfiConverterVerencShare{}

func (c FfiConverterVerencShare) Lift(rb RustBufferI) VerencShare {
	return LiftFromRustBuffer[VerencShare](c, rb)
}

func (c FfiConverterVerencShare) Read(reader io.Reader) VerencShare {
	return VerencShare{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterVerencShare) Lower(value VerencShare) C.RustBuffer {
	return LowerIntoRustBuffer[VerencShare](c, value)
}

func (c FfiConverterVerencShare) Write(writer io.Writer, value VerencShare) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.S1)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.S2)
	FfiConverterUint64INSTANCE.Write(writer, value.I)
}

type FfiDestroyerVerencShare struct{}

func (_ FfiDestroyerVerencShare) Destroy(value VerencShare) {
	value.Destroy()
}

type FfiConverterSequenceUint8 struct{}

var FfiConverterSequenceUint8INSTANCE = FfiConverterSequenceUint8{}

func (c FfiConverterSequenceUint8) Lift(rb RustBufferI) []uint8 {
	return LiftFromRustBuffer[[]uint8](c, rb)
}

func (c FfiConverterSequenceUint8) Read(reader io.Reader) []uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUint8) Lower(value []uint8) C.RustBuffer {
	return LowerIntoRustBuffer[[]uint8](c, value)
}

func (c FfiConverterSequenceUint8) Write(writer io.Writer, value []uint8) {
	if len(value) > math.MaxInt32 {
		panic("[]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUint8 struct{}

func (FfiDestroyerSequenceUint8) Destroy(sequence []uint8) {
	for _, value := range sequence {
		FfiDestroyerUint8{}.Destroy(value)
	}
}

type FfiConverterSequenceVerencCiphertext struct{}

var FfiConverterSequenceVerencCiphertextINSTANCE = FfiConverterSequenceVerencCiphertext{}

func (c FfiConverterSequenceVerencCiphertext) Lift(rb RustBufferI) []VerencCiphertext {
	return LiftFromRustBuffer[[]VerencCiphertext](c, rb)
}

func (c FfiConverterSequenceVerencCiphertext) Read(reader io.Reader) []VerencCiphertext {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]VerencCiphertext, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterVerencCiphertextINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceVerencCiphertext) Lower(value []VerencCiphertext) C.RustBuffer {
	return LowerIntoRustBuffer[[]VerencCiphertext](c, value)
}

func (c FfiConverterSequenceVerencCiphertext) Write(writer io.Writer, value []VerencCiphertext) {
	if len(value) > math.MaxInt32 {
		panic("[]VerencCiphertext is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterVerencCiphertextINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceVerencCiphertext struct{}

func (FfiDestroyerSequenceVerencCiphertext) Destroy(sequence []VerencCiphertext) {
	for _, value := range sequence {
		FfiDestroyerVerencCiphertext{}.Destroy(value)
	}
}

type FfiConverterSequenceVerencShare struct{}

var FfiConverterSequenceVerencShareINSTANCE = FfiConverterSequenceVerencShare{}

func (c FfiConverterSequenceVerencShare) Lift(rb RustBufferI) []VerencShare {
	return LiftFromRustBuffer[[]VerencShare](c, rb)
}

func (c FfiConverterSequenceVerencShare) Read(reader io.Reader) []VerencShare {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]VerencShare, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterVerencShareINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceVerencShare) Lower(value []VerencShare) C.RustBuffer {
	return LowerIntoRustBuffer[[]VerencShare](c, value)
}

func (c FfiConverterSequenceVerencShare) Write(writer io.Writer, value []VerencShare) {
	if len(value) > math.MaxInt32 {
		panic("[]VerencShare is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterVerencShareINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceVerencShare struct{}

func (FfiDestroyerSequenceVerencShare) Destroy(sequence []VerencShare) {
	for _, value := range sequence {
		FfiDestroyerVerencShare{}.Destroy(value)
	}
}

type FfiConverterSequenceSequenceUint8 struct{}

var FfiConverterSequenceSequenceUint8INSTANCE = FfiConverterSequenceSequenceUint8{}

func (c FfiConverterSequenceSequenceUint8) Lift(rb RustBufferI) [][]uint8 {
	return LiftFromRustBuffer[[][]uint8](c, rb)
}

func (c FfiConverterSequenceSequenceUint8) Read(reader io.Reader) [][]uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([][]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterSequenceUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceSequenceUint8) Lower(value [][]uint8) C.RustBuffer {
	return LowerIntoRustBuffer[[][]uint8](c, value)
}

func (c FfiConverterSequenceSequenceUint8) Write(writer io.Writer, value [][]uint8) {
	if len(value) > math.MaxInt32 {
		panic("[][]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterSequenceUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceSequenceUint8 struct{}

func (FfiDestroyerSequenceSequenceUint8) Destroy(sequence [][]uint8) {
	for _, value := range sequence {
		FfiDestroyerSequenceUint8{}.Destroy(value)
	}
}

func ChunkDataForVerenc(data []uint8) [][]uint8 {
	return FfiConverterSequenceSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_verenc_fn_func_chunk_data_for_verenc(FfiConverterSequenceUint8INSTANCE.Lower(data), _uniffiStatus),
		}
	}))
}

func CombineChunkedData(chunks [][]uint8) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_verenc_fn_func_combine_chunked_data(FfiConverterSequenceSequenceUint8INSTANCE.Lower(chunks), _uniffiStatus),
		}
	}))
}

func NewVerencProof(data []uint8) VerencProofAndBlindingKey {
	return FfiConverterVerencProofAndBlindingKeyINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_verenc_fn_func_new_verenc_proof(FfiConverterSequenceUint8INSTANCE.Lower(data), _uniffiStatus),
		}
	}))
}

func NewVerencProofEncryptOnly(data []uint8, encryptionKeyBytes []uint8) VerencProofAndBlindingKey {
	return FfiConverterVerencProofAndBlindingKeyINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_verenc_fn_func_new_verenc_proof_encrypt_only(FfiConverterSequenceUint8INSTANCE.Lower(data), FfiConverterSequenceUint8INSTANCE.Lower(encryptionKeyBytes), _uniffiStatus),
		}
	}))
}

func VerencCompress(proof VerencProof) CompressedCiphertext {
	return FfiConverterCompressedCiphertextINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_verenc_fn_func_verenc_compress(FfiConverterVerencProofINSTANCE.Lower(proof), _uniffiStatus),
		}
	}))
}

func VerencRecover(recovery VerencDecrypt) []uint8 {
	return FfiConverterSequenceUint8INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_verenc_fn_func_verenc_recover(FfiConverterVerencDecryptINSTANCE.Lower(recovery), _uniffiStatus),
		}
	}))
}

func VerencVerify(proof VerencProof) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_verenc_fn_func_verenc_verify(FfiConverterVerencProofINSTANCE.Lower(proof), _uniffiStatus)
	}))
}

func VerencVerifyStatement(input []uint8, blindingPubkey []uint8, statement []uint8) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_verenc_fn_func_verenc_verify_statement(FfiConverterSequenceUint8INSTANCE.Lower(input), FfiConverterSequenceUint8INSTANCE.Lower(blindingPubkey), FfiConverterSequenceUint8INSTANCE.Lower(statement), _uniffiStatus)
	}))
}
