package lz4

import "core:bytes"
import "core:fmt"
import "core:hash/xxhash"
import "core:io"
import "core:log"
import "core:mem"
import "core:os"
import "core:testing"

MAGIC_VALUE :: 0x184D2204

Frame :: struct {
	descriptor:       Frame_Descriptor,
	blocks:           []Frame_Block,
	content_checksum: u32le,
}

Frame_Descriptor :: struct {
	version:              int,
	block_independence:   bool,
	has_block_checksum:   bool,
	has_content_checksum: bool,
	calculated_checksum:  u8,
	header_checksum:      u8,
	block_max_size:       int,
	content_size:         int,
	dictionary_id:        int,
}

Frame_Block :: struct {
	size:       int,
	data:       []byte,
	checksum:   u32,
	compressed: bool,
}

FrameNextError :: union {
	No_Frame,
	Data_Too_Small,
	Infinite_Frame,
	mem.Allocator_Error,
}

No_Frame :: struct {}

Data_Too_Small :: struct {
	size: int,
}

Infinite_Frame :: struct {
	start: int,
}

frame_next :: proc(
	data: []byte,
	allocator := context.allocator,
	loc := #caller_location,
) -> (
	frame: Frame,
	rest: []byte,
	error: FrameNextError,
) {
	if len(data) < 7 {
		return Frame{}, data, Data_Too_Small{size = len(data)}
	}

	for i := 0; i < len(data); i += 1 {
		if i + 4 > len(data) {
			return Frame{}, data, No_Frame{}
		}

		potential_magic_value := mem.reinterpret_copy(u32le, raw_data(data[i:i + 4]))

		if potential_magic_value != MAGIC_VALUE {
			continue
		}

		// TODO(gonz): convert this to `Reader` instead

		ix := i + 4
		flags := data[ix]
		version := int(flags >> 6)
		block_independence := flags & 0x20 != 0
		has_block_checksum := flags & 0x10 != 0
		has_content_size := flags & 0x08 != 0
		has_content_checksum := flags & 0x04 != 0
		has_dictionary_id := flags & 0x01 != 0

		ix += 1
		bd := data[ix]
		block_max_size := get_block_max_size(bd & 0x70 >> 4)

		ix += 1

		frame.descriptor.version = version
		frame.descriptor.block_independence = block_independence
		frame.descriptor.has_block_checksum = has_block_checksum
		frame.descriptor.has_content_checksum = has_content_checksum
		frame.descriptor.block_max_size = block_max_size

		content_size := has_content_size ? mem.reinterpret_copy(int, raw_data(data[ix:ix + 8])) : 0
		frame.descriptor.content_size = content_size
		if has_content_size {
			ix += 8
		}

		dictionary_id :=
			has_dictionary_id ? mem.reinterpret_copy(i32, raw_data(data[ix:ix + 4])) : 0
		frame.descriptor.dictionary_id = int(dictionary_id)
		if has_dictionary_id {
			ix += 4
		}

		header_checksum := data[ix]
		frame.descriptor.header_checksum = header_checksum

		header_bytes := data[i + 4:ix]
		checksum := u8(xxhash.XXH32(header_bytes, 0) >> 8)
		if checksum != header_checksum {
			log.errorf("Checksum mismatch: %d != %d", checksum, header_checksum)
		}
		frame.descriptor.calculated_checksum = checksum

		ix += 1

		blocks := make([dynamic]Frame_Block, 0, 0, allocator) or_return

		for {
			is_compressed := data[ix] & 0x80 != 0
			block_size := mem.reinterpret_copy(u32le, raw_data(data[ix:ix + 4]))
			if block_size == 0 {
				break
			}

			block_size &= 0x7F_FF_FF_FF
			ix += 4

			block := Frame_Block{}
			block.size = int(block_size)
			block.compressed = is_compressed
			block.data = data[ix:ix + block.size]
			ix += block.size
			if has_block_checksum {
				block.checksum = mem.reinterpret_copy(u32, raw_data(data[ix:ix + 4]))
				assert(
					block.checksum == xxhash.XXH32(block.data, 0),
					fmt.tprintf(
						"Block checksum mismatch: %d != %d",
						block.checksum,
						xxhash.XXH32(block.data, 0),
					),
				)
				ix += 4
			}

			append(&blocks, block) or_return
		}
		frame.blocks = blocks[:]

		end_marker_value := mem.reinterpret_copy(u32le, raw_data(data[ix:ix + 4]))
		assert(
			end_marker_value == 0,
			fmt.tprintf("End marker bytes are not 0: %d", end_marker_value),
		)
		ix += 4

		if has_content_checksum {
			frame.content_checksum = mem.reinterpret_copy(u32le, raw_data(data[ix:ix + 4]))
			ix += 4
		}

		rest = data[ix:]

		return frame, rest, nil
	}

	return Frame{}, nil, No_Frame{}
}

Data_Block :: struct {
	length:       int,
	literals:     []byte,
	offset:       int,
	match_length: int,
}

Decompress_Frame_Error :: union {
	Insufficient_Space_In_Buffer,
	Decompress_Frame_Block_Error,
	io.Error,
	mem.Allocator_Error,
}

Decompress_Frame_Block_Error :: struct {
	block:            Frame_Block,
	data_block_index: int,
	error:            Data_Block_Error,
}

Data_Block_Error :: union {
	Zero_Offset,
	Not_Enough_Literals,
	io.Error,
	mem.Allocator_Error,
}

Zero_Offset :: struct {
	position: int,
}

Not_Enough_Literals :: struct {
	expected: int,
	actual:   int,
}

Insufficient_Space_In_Buffer :: struct {
	expected: int,
	actual:   int,
}

Decompress_Frame_Result :: union {
	[][]byte,
	[]byte,
}

decompress_frame :: proc(
	frame: Frame,
	allocator := context.allocator,
) -> (
	decompressed: Decompress_Frame_Result,
	error: Decompress_Frame_Error,
) {
	// NOTE(gonz): if we have block dependence but only one block in the frame it should be the same
	// as having independent blocks, I assume
	if !frame.descriptor.block_independence && len(frame.blocks) > 1 {
		return decompress_frame_dependently(frame, allocator)
	}

	decompressed_blocks := make([dynamic][]byte, 0, len(frame.blocks), allocator) or_return

	for b in frame.blocks {
		if !b.compressed {
			// NOTE(gonz): uncompressed blocks are copied into newly allocated space so they can be
			// freed the same way as compressed blocks, even though we don't technically necessarily
			// need the allocation to copy them over to the resulting dynamic array
			cloned_data := make([]byte, len(b.data), allocator) or_return
			copy(cloned_data, b.data)
			append(&decompressed_blocks, cloned_data) or_return

			continue
		}

		decompressed_block := decompress_frame_block(
			b,
			frame.descriptor.block_max_size,
			allocator,
		) or_return
		append(&decompressed_blocks, decompressed_block) or_return
	}

	return decompressed_blocks[:], nil
}

decompress_frame_block :: proc(
	fb: Frame_Block,
	max_block_size: int,
	allocator := context.allocator,
) -> (
	decompressed: []byte,
	error: Decompress_Frame_Error,
) {
	b: bytes.Buffer
	bytes.buffer_init_allocator(&b, 0, max_block_size, allocator)
	r: bytes.Reader
	bytes.reader_init(&r, fb.data)

	for {
		db, data_block_read_error := read_data_block(&r, allocator)
		if data_block_read_error == .EOF {
			break
		} else if data_block_read_error != nil {
			return nil,
				Decompress_Frame_Block_Error{
					block = fb,
					data_block_index = len(decompressed),
					error = data_block_read_error,
				}
		}

		bytes.buffer_write(&b, db.literals) or_return

		if db.offset == 0 {
			continue
		}

		if db.offset < db.match_length {
			copy_start := len(b.buf) - db.offset
			copy_bytes := b.buf[copy_start:]
			bytes.buffer_write(&b, copy_bytes) or_return

			remaining := db.match_length - db.offset
			for remaining > 0 {
				bytes.buffer_write_byte(&b, copy_bytes[len(copy_bytes) - 1]) or_return
				remaining -= 1
			}
		} else {
			match_start := len(b.buf) - db.offset
			match_end := match_start + db.match_length
			match_bytes := b.buf[match_start:match_end]
			bytes.buffer_write(&b, match_bytes) or_return
		}
	}

	decompressed = bytes.buffer_to_bytes(&b)

	return decompressed, nil
}

@(test, private = "package")
test_decompress_frame :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger()

	path :: "test-data/plain-01-checksum.lz4"
	file_data, read_ok := os.read_entire_file_from_filename(path)
	if !read_ok {
		panic("Could not read file for test: '" + path + "'")
	}

	plain_text_path :: "test-data/plain-01.txt"
	plain_data, plain_read_ok := os.read_entire_file_from_filename(plain_text_path)
	if !plain_read_ok {
		panic("Could not read file for test: '" + plain_text_path + "'")
	}

	frame, _, frame_error := frame_next(file_data)
	if frame_error != nil {
		panic("Could not read frame")
	}
	assert(len(frame.blocks) == 1)
	decompressed, decompress_error := decompress_frame(frame)
	testing.expect(
		t,
		decompress_error == nil,
		fmt.tprintf("Decompress error is not nil: %v\n", decompress_error),
	)

	switch d in decompressed {
	case []byte:
		testing.expect(
			t,
			bytes.compare(d, plain_data) == 0,
			fmt.tprintf("Decompressed data does not match plain data: '%s'\n", d),
		)
	case [][]byte:
		concatenated := bytes.concatenate(d)
		testing.expect(
			t,
			bytes.compare(concatenated, plain_data) == 0,
			fmt.tprintf("Decompressed data does not match plain data: '%s'\n", concatenated),
		)
	}
}

decompress_frame_dependently :: proc(
	frame: Frame,
	allocator := context.allocator,
) -> (
	decompressed: []byte,
	error: Decompress_Frame_Error,
) {
	log.panicf("Block dependence not currently supported")
}

read_data_block :: proc(
	r: ^bytes.Reader,
	allocator := context.allocator,
) -> (
	block: Data_Block,
	error: Data_Block_Error,
) {
	token_byte := bytes.reader_read_byte(r) or_return
	last_read_length := int(token_byte >> 4)
	block.length = last_read_length
	for last_read_length == 15 || last_read_length == 255 {
		b := bytes.reader_read_byte(r) or_return
		last_read_length = int(b)
		block.length += last_read_length
	}

	if block.length == 0 {
		block.literals = []byte{}
	} else {
		literals := make([]byte, block.length, allocator) or_return

		literal_bytes_read := bytes.reader_read(r, literals) or_return
		if literal_bytes_read != block.length {
			return Data_Block{},
				Not_Enough_Literals{expected = block.length, actual = literal_bytes_read}
		}

		block.literals = literals
	}

	offset_buffer: [2]byte
	_, offset_read := bytes.reader_read(r, offset_buffer[:])
	if offset_read == .EOF {
		// This means we've read the last block, we have only literals and no offset
		return block, nil
	}
	offset := transmute(u16le)offset_buffer
	if offset == 0 {
		return Data_Block{}, Zero_Offset{position = int(r.i)}
	}
	block.offset = int(offset)

	last_read_length = int(token_byte & 0x0f)
	block.match_length = last_read_length
	for last_read_length == 15 || last_read_length == 255 {
		b := bytes.reader_read_byte(r) or_return
		last_read_length = int(b)
		block.match_length += last_read_length
	}
	block.match_length += 4

	return block, nil
}

@(test, private = "package")
test_read_data_block :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger()

	bytes_1_prelude := []byte{0x88}
	offset_bytes_1 := transmute([2]byte)u16le(4)
	bytes_1 := bytes.concatenate(
		[][]byte{bytes_1_prelude, bytes.repeat([]byte{0}, 8), offset_bytes_1[:]},
	)
	r1: bytes.Reader
	bytes.reader_init(&r1, bytes_1)
	block1, err1 := read_data_block(&r1)
	testing.expect_value(t, err1, nil)
	testing.expect_value(t, block1.length, 8)
	testing.expect_value(t, block1.match_length, 12)
	testing.expect_value(t, block1.offset, 4)

	bytes_2_prelude := []byte{0xf4, 0xff, 2}
	offset_bytes_2 := transmute([2]byte)u16le(1)
	bytes_2 := bytes.concatenate(
		[][]byte{bytes_2_prelude, bytes.repeat([]byte{0}, 15 + 255 + 2), offset_bytes_2[:]},
	)
	r2: bytes.Reader
	bytes.reader_init(&r2, bytes_2)
	block2, err2 := read_data_block(&r2)
	testing.expect_value(t, err2, nil)
	testing.expect_value(t, block2.length, 15 + 255 + 2)
	testing.expect_value(t, block2.match_length, 8)
	testing.expect_value(t, block2.offset, 1)

	bytes_3 := []byte{0xf0, 33}
	r3: bytes.Reader
	bytes.reader_init(&r3, bytes_3)
	block3, err3 := read_data_block(&r3)
	testing.expect_value(t, err3, io.Error.EOF)
	testing.expect_value(t, block3.length, 48)

	bytes_4 := []byte{0xf0, 255, 10}
	r4: bytes.Reader
	bytes.reader_init(&r4, bytes_4)
	block4, err4 := read_data_block(&r4)
	testing.expect_value(t, err4, io.Error.EOF)
	testing.expect_value(t, block4.length, 280)

	bytes_5 := []byte{0xf0, 0}
	r5: bytes.Reader
	bytes.reader_init(&r5, bytes_5)
	block5, err5 := read_data_block(&r5)
	testing.expect_value(t, err5, io.Error.EOF)
	testing.expect_value(t, block5.length, 15)
}

frame_serialize :: proc(
	f: Frame,
	allocator := context.allocator,
	loc := #caller_location,
) -> (
	data: []byte,
	error: io.Error,
) {
	b: bytes.Buffer
	bytes.buffer_init_allocator(&b, 0, 0, allocator)

	magic_value_bytes := transmute([4]byte)u32le(MAGIC_VALUE)
	bytes.buffer_write(&b, magic_value_bytes[:]) or_return

	flags := u8(f.descriptor.version << 6)
	if f.descriptor.block_independence {
		flags |= 0x20
	}
	if f.descriptor.has_block_checksum {
		flags |= 0x10
	}
	if f.descriptor.content_size != 0 {
		flags |= 0x08
	}
	if f.descriptor.has_content_checksum {
		flags |= 0x04
	}
	if f.descriptor.dictionary_id != 0 {
		flags |= 0x01
	}
	bytes.buffer_write_byte(&b, flags) or_return

	bd_byte := encode_block_max_size(f.descriptor.block_max_size) << 4
	bytes.buffer_write_byte(&b, bd_byte) or_return

	if f.descriptor.content_size != 0 {
		content_size_bytes := transmute([8]byte)u64le(f.descriptor.content_size)
		bytes.buffer_write(&b, content_size_bytes[:]) or_return
	}

	if f.descriptor.dictionary_id != 0 {
		dictionary_id_bytes := transmute([4]byte)u32le(f.descriptor.dictionary_id)
		bytes.buffer_write(&b, dictionary_id_bytes[:]) or_return
	}

	bytes_so_far := bytes.buffer_to_bytes(&b)
	header_bytes := bytes_so_far[4:]
	hash := xxhash.XXH32(header_bytes, 0)
	// we skip the magic number for the checksum calculation
	header_checksum := u8(hash >> 8)
	assert(
		header_checksum == f.descriptor.header_checksum,
		fmt.tprintf(
			"Checksum mismatch:\n\tCalculated: %#x\n\tFrame object checksum: %#x (called from %v)",
			header_checksum,
			f.descriptor.header_checksum,
			loc,
		),
	)
	bytes.buffer_write_byte(&b, header_checksum) or_return

	write_frame_blocks(&b, f.descriptor.has_block_checksum, f.blocks) or_return

	end_frame_bytes := transmute([4]byte)u32le(0)
	bytes.buffer_write(&b, end_frame_bytes[:]) or_return

	if f.descriptor.has_content_checksum {
		content_checksum_bytes := transmute([4]byte)f.content_checksum
		bytes.buffer_write(&b, content_checksum_bytes[:]) or_return
	}

	return bytes.buffer_to_bytes(&b), nil
}

@(private = "file")
write_frame_blocks :: proc(
	b: ^bytes.Buffer,
	has_checksum: bool,
	blocks: []Frame_Block,
) -> io.Error {
	for block in blocks {
		block_size := block.size
		if !block.compressed {
			block_size |= 0x8000_0000
		}
		block_size_bytes := transmute([4]byte)u32le(block_size)
		bytes.buffer_write(b, block_size_bytes[:]) or_return

		bytes.buffer_write(b, block.data) or_return

		if has_checksum {
			block_checksum_bytes := transmute([4]byte)u32(block.checksum)
			bytes.buffer_write(b, block_checksum_bytes[:]) or_return
		}
	}

	return nil
}

@(test, private = "package")
test_frame_serialize :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger()

	path :: "test-data/plain-01-checksum.lz4"
	file_data, read_ok := os.read_entire_file_from_filename(path)
	if !read_ok {
		panic("Could not read file for test: '" + path + "'")
	}

	frame, rest, frame_error := frame_next(file_data)
	if frame_error != nil {
		panic("Could not read frame")
	}
	if len(rest) != 0 {
		panic("Have remaining data after reading frame")
	}

	serialized, serialize_error := frame_serialize(frame)
	testing.expect(
		t,
		serialize_error == nil,
		fmt.tprintf("Serialize error is not nil: %v\n", serialize_error),
	)

	testing.expect(
		t,
		len(serialized) == len(file_data),
		fmt.tprintf(
			"Serialized data is not the same size as original data: %d != %d\n",
			len(serialized),
			len(file_data),
		),
	)

	if len(serialized) == len(file_data) {
		serialized_frame, serialized_rest, serialized_frame_error := frame_next(serialized)
		testing.expect(
			t,
			serialized_frame_error == nil,
			fmt.tprintf("Serialized frame error is not nil: %v\n", serialized_frame_error),
		)
		testing.expect(
			t,
			len(serialized_rest) == 0,
			fmt.tprintf("Serialized rest is not empty: %#x\n", serialized_rest),
		)

		testing.expect_value(t, serialized_frame.content_checksum, frame.content_checksum)
		testing.expect_value(
			t,
			serialized_frame.descriptor.block_independence,
			frame.descriptor.block_independence,
		)
		testing.expect_value(
			t,
			serialized_frame.descriptor.block_max_size,
			frame.descriptor.block_max_size,
		)
		testing.expect_value(
			t,
			serialized_frame.descriptor.calculated_checksum,
			frame.descriptor.calculated_checksum,
		)
		testing.expect_value(
			t,
			serialized_frame.descriptor.content_size,
			frame.descriptor.content_size,
		)
		testing.expect_value(
			t,
			serialized_frame.descriptor.dictionary_id,
			frame.descriptor.dictionary_id,
		)
		testing.expect_value(
			t,
			serialized_frame.descriptor.has_block_checksum,
			frame.descriptor.has_block_checksum,
		)
		testing.expect_value(
			t,
			serialized_frame.descriptor.has_content_checksum,
			frame.descriptor.has_content_checksum,
		)
		testing.expect_value(
			t,
			serialized_frame.descriptor.header_checksum,
			frame.descriptor.header_checksum,
		)
		testing.expect_value(t, serialized_frame.descriptor.version, frame.descriptor.version)

		testing.expect_value(t, len(serialized_frame.blocks), len(frame.blocks))
		if len(serialized_frame.blocks) == len(frame.blocks) {
			for b, i in frame.blocks {
				sb := serialized_frame.blocks[i]
				testing.expect_value(t, sb.compressed, b.compressed)
				testing.expect_value(t, sb.size, b.size)
				testing.expect_value(t, sb.checksum, b.checksum)
				testing.expect_value(t, bytes.compare(sb.data, b.data), 0)
			}
		}
	}
}

Compress_Error :: union {
	mem.Allocator_Error,
	io.Error,
}

compress :: proc(data: []byte) -> (result: []byte, error: Compress_Error) {
	return nil, nil
}

// @(test, private = "package")
// test_compress :: proc(t: ^testing.T) {
// 	context.logger = log.create_console_logger()
//
// 	path :: "test-data/plain-01.txt"
// 	file_data, read_ok := os.read_entire_file_from_filename(path)
// 	if !read_ok {
// 		panic("Could not read file for test: '" + path + "'")
// 	}
//
// 	compressed, compress_error := compress(file_data)
// 	testing.expect(
// 		t,
// 		compress_error == nil,
// 		fmt.tprintf("Compress error is not nil: %v\n", compress_error),
// 	)
// 	testing.expect(
// 		t,
// 		len(compressed) < len(file_data),
// 		fmt.tprintf(
// 			"Compressed data is not smaller than original: %d >= %d\n",
// 			len(compressed),
// 			len(file_data),
// 		),
// 	)
// 	testing.expect(t, len(compressed) > 0, fmt.tprintf("Compressed data is empty\n"))
//
// 	frame, _, frame_error := frame_next(compressed)
// 	testing.expect(t, frame_error == nil, fmt.tprintf("Frame error is not nil: %v\n", frame_error))
// 	testing.expect(
// 		t,
// 		frame.descriptor.version == 1,
// 		fmt.tprintf("Frame version is not 1: %d\n", frame.descriptor.version),
// 	)
//
// 	decompressed, decompress_error := decompress_frame(frame)
// 	testing.expect(
// 		t,
// 		decompress_error == nil,
// 		fmt.tprintf("Decompress error is not nil: %v\n", decompress_error),
// 	)
// 	switch d in decompressed {
// 	case []byte:
// 		testing.expect(
// 			t,
// 			bytes.compare(d, file_data) == 0,
// 			fmt.tprintf("Decompressed data does not match original data: '%s'\n", d),
// 		)
// 	case [][]byte:
// 		concatenated := bytes.concatenate(d)
// 		testing.expect(
// 			t,
// 			bytes.compare(concatenated, file_data) == 0,
// 			fmt.tprintf("Decompressed data does not match original data: '%s'\n", concatenated),
// 		)
// 	}
// }

get_block_max_size :: proc(byte: byte) -> int {
	switch byte {
	case 0, 1, 2, 3:
		return -1
	case 4:
		return 64 * mem.Kilobyte
	case 5:
		return 256 * mem.Kilobyte
	case 6:
		return mem.Megabyte
	case 7:
		return 4 * mem.Megabyte
	case:
		return -1
	}
}

encode_block_max_size :: proc(size: int) -> byte {
	switch size {
	case 64 * mem.Kilobyte:
		return 4
	case 256 * mem.Kilobyte:
		return 5
	case mem.Megabyte:
		return 6
	case 4 * mem.Megabyte:
		return 7
	case:
		return 0
	}
}

@(test, private = "package")
test_frame_next :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger()
	path :: "test-data/lz4-example.pak"

	file_data, ok := os.read_entire_file_from_filename(path)
	if !ok {
		panic("Could not read file for test: '" + path + "'")
	}
	frames, alloc_error := make([dynamic]Frame, 0, 0)
	if alloc_error != nil {
		panic("Could not allocate frames array")
	}

	for frame, rest, frame_error := frame_next(file_data);
	    frame_error == nil;
	    frame, rest, frame_error = frame_next(rest) {
		_, err := append(&frames, frame)
		if err != nil {
			panic("Could not append frame")
		}
	}

	testing.expect_value(t, len(frames), 12)
}
