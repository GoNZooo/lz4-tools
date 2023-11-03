package lz4

import "core:bytes"
import "core:fmt"
import "core:hash/xxhash"
import "core:io"
import "core:log"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:slice"
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

Frame_Next_Error :: union {
	No_Frame,
	Data_Too_Small,
	Infinite_Frame,
	Read_Frame_Block_Error,
	mem.Allocator_Error,
	io.Error,
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
	error: Frame_Next_Error,
) {
	if len(data) < 7 {
		return Frame{}, data, Data_Too_Small{size = len(data)}
	}

	r: bytes.Reader
	bytes.reader_init(&r, data)

	for i := 0; i < len(data); i += 1 {
		if i + 4 > len(data) {
			return Frame{}, data, No_Frame{}
		}

		magic_value_buffer: [4]byte
		bytes.reader_read(&r, magic_value_buffer[:]) or_return
		potential_magic_value := transmute(u32le)magic_value_buffer

		if potential_magic_value != MAGIC_VALUE {
			continue
		}

		flags := bytes.reader_read_byte(&r) or_return
		version := int(flags >> 6)
		block_independence := flags & 0x20 != 0
		has_block_checksum := flags & 0x10 != 0
		has_content_size := flags & 0x08 != 0
		has_content_checksum := flags & 0x04 != 0
		has_dictionary_id := flags & 0x01 != 0

		bd := bytes.reader_read_byte(&r) or_return
		block_max_size := get_block_max_size((bd & 0x70) >> 4)

		frame.descriptor.version = version
		frame.descriptor.block_independence = block_independence
		frame.descriptor.has_block_checksum = has_block_checksum
		frame.descriptor.has_content_checksum = has_content_checksum
		frame.descriptor.block_max_size = block_max_size

		content_size: int
		if has_content_size {
			content_size_buffer: [8]byte
			bytes.reader_read(&r, content_size_buffer[:]) or_return
			content_size = transmute(int)content_size_buffer
		}
		frame.descriptor.content_size = content_size

		dictionary_id: i32
		if has_dictionary_id {
			dictionary_id_buffer: [4]byte
			bytes.reader_read(&r, dictionary_id_buffer[:]) or_return
			dictionary_id = transmute(i32)dictionary_id_buffer
		}

		header_checksum := bytes.reader_read_byte(&r) or_return
		frame.descriptor.header_checksum = header_checksum

		header_bytes := data[i + 4:r.i - 1]
		checksum := u8(xxhash.XXH32(header_bytes, 0) >> 8)
		if checksum != header_checksum {
			log.errorf("Checksum mismatch: %#x != %#x", checksum, header_checksum)
		}
		frame.descriptor.calculated_checksum = checksum

		frame.blocks = read_frame_blocks(&r, has_block_checksum, allocator) or_return

		if has_content_checksum {
			content_checksum_buffer: [4]byte
			bytes.reader_read(&r, content_checksum_buffer[:]) or_return
			frame.content_checksum = transmute(u32le)content_checksum_buffer
		}

		rest = data[r.i:]

		return frame, rest, nil
	}

	return Frame{}, nil, No_Frame{}
}

Read_Frame_Block_Error :: union {
	io.Error,
	mem.Allocator_Error,
}

@(private = "file")
read_frame_blocks :: proc(
	r: ^bytes.Reader,
	has_checksum: bool,
	allocator := context.allocator,
) -> (
	blocks: []Frame_Block,
	error: Read_Frame_Block_Error,
) {
	frame_blocks := make([dynamic]Frame_Block, 0, 0, allocator) or_return

	for {
		block_size_buffer: [4]byte
		n := bytes.reader_read(r, block_size_buffer[:]) or_return
		assert(n == 4)
		block_size := transmute(u32)block_size_buffer
		compressed := block_size & 0x8000_0000 == 0
		size := block_size & 0x7f_ff_ff_ff
		if size == 0 {
			break
		}

		data := make([]byte, size, allocator) or_return
		n = bytes.reader_read(r, data) or_return
		assert(n == int(size))

		checksum: u32le
		if has_checksum {
			checksum_buffer: [4]byte
			n = bytes.reader_read(r, checksum_buffer[:]) or_return
			assert(n == 4)
			checksum = transmute(u32le)checksum_buffer
		}

		block := Frame_Block {
			size       = int(size),
			data       = data,
			checksum   = u32(checksum),
			compressed = compressed,
		}

		append(&frame_blocks, block) or_return

		possible_end_marker_buffer: [4]byte
		bytes.reader_read(r, possible_end_marker_buffer[:]) or_return
		possible_end_marker := transmute(u32le)possible_end_marker_buffer
		if possible_end_marker == 0 {
			break
		}
	}

	return frame_blocks[:], nil
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

		n := bytes.buffer_write(&b, db.literals) or_return
		assert(n == db.length)

		if db.offset == 0 {
			continue
		}

		if db.offset < db.match_length {
			copy_start := len(b.buf) - db.offset
			copy_bytes := b.buf[copy_start:]
			copy_n := bytes.buffer_write(&b, copy_bytes) or_return

			remaining := db.match_length - db.offset
			for i in 0 ..< remaining {
				bytes.buffer_write_byte(&b, copy_bytes[i % len(copy_bytes)]) or_return
			}
		} else {
			match_start := len(b.buf) - db.offset
			assert(match_start >= 0 && match_start <= len(b.buf), "match_start is out of bounds")
			match_end := match_start + db.match_length
			assert(match_end >= 0 && match_end <= len(b.buf), "match_end is out of bounds")
			match_bytes := b.buf[match_start:match_end]
			match_n := bytes.buffer_write(&b, match_bytes) or_return
			assert(match_n == db.match_length)
		}
	}

	decompressed = bytes.buffer_to_bytes(&b)

	return decompressed, nil
}

@(test, private = "package")
test_decompress_frame :: proc(t: ^testing.T) {
	Test_Case :: struct {
		compressed_path: string,
		plain_text_path: string,
	}

	paths := []string{
		"test-data/plain-01.txt",
		"test-data/lz4-2023-11-01.odin",
		"test-data/odin/core/os/os_windows.odin",
		"test-data/odin/core/os/os_darwin.odin",
		"test-data/odin/core/os/os_linux.odin",
		"test-data/odin/core/os/os_freebsd.odin",
		"test-data/odin/core/os/os_openbsd.odin",
	}

	for path in paths {
		expect_decompress_frame_invariants_to_hold(t, path)
	}

}


expect_decompress_frame_invariants_to_hold :: proc(t: ^testing.T, path: string) {
	context.logger = log.create_console_logger(ident = fmt.tprintf("%s", path))
	compressed_path := fmt.tprintf("%s.lz4", path)

	file_data, read_ok := os.read_entire_file_from_filename(compressed_path)
	if !read_ok {
		fmt.panicf("Could not read file for test: '%s'", compressed_path)
	}

	plain_data, plain_read_ok := os.read_entire_file_from_filename(path)
	if !plain_read_ok {
		fmt.panicf("Could not read file for test: '%s'", path)
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

	compare_result: int
	buffer: []byte
	switch d in decompressed {
	case []byte:
		compare_result = bytes.compare(d, plain_data)
		buffer = d
		testing.expect(
			t,
			compare_result == 0,
			fmt.tprintf("Decompressed data does not match plain data\n"),
		)
	case [][]byte:
		concatenated := bytes.concatenate(d)
		buffer = concatenated
		compare_result = bytes.compare(concatenated, plain_data)
		testing.expect(
			t,
			compare_result == 0,
			fmt.tprintf("Decompressed data does not match plain data\n"),
		)
	}

	if compare_result != 0 {
		plain_length := len(plain_data)
		decompressed_length := len(buffer)
		if plain_length != decompressed_length {
			fmt.panicf(
				"Decompressed data does not match plain data:\n\tLengths do not match: %d != %d\n",
				plain_length,
				decompressed_length,
			)
		}

		for pc, i in plain_data {
			dc := buffer[i]
			if pc != dc {
				decompressed: [50]byte
				plaintext: [50]byte
				copy(decompressed[:], buffer[i - 25:])
				copy(plaintext[:], plain_data[i - 25:])
				fmt.panicf(
					"Mismatch @ %d: %#x != %#x\n\n\tPlain:\n\t '%s'\nDecompressed:\n\t'%s'\n",
					i,
					pc,
					dc,
					plaintext,
					decompressed,
				)
			}
		}
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

@(private = "file")
read_data_block :: proc(
	r: ^bytes.Reader,
	allocator := context.allocator,
) -> (
	block: Data_Block,
	error: Data_Block_Error,
) {
	token_byte := bytes.reader_read_byte(r) or_return
	initial_read := token_byte >> 4
	block.length = int(initial_read)
	last_read_length: byte = 255
	for initial_read == 15 && last_read_length == 255 {
		b := bytes.reader_read_byte(r) or_return
		last_read_length = b
		block.length += int(last_read_length)
	}

	if block.length == 0 {
		block.literals = []byte{}
	} else {
		literals := make([]byte, block.length, allocator) or_return

		literal_bytes_read := bytes.reader_read(r, literals) or_return
		assert(literal_bytes_read == block.length)

		block.literals = literals
	}

	offset_buffer: [2]byte
	offset_bytes_read, offset_read := bytes.reader_read(r, offset_buffer[:])
	if offset_read == .EOF {
		// This means we've read the last block, we have only literals and no offset
		return block, nil
	}
	assert(offset_bytes_read == 2)
	offset := transmute(u16le)offset_buffer
	if offset == 0 {
		return Data_Block{}, Zero_Offset{position = int(r.i)}
	}
	block.offset = int(offset)

	initial_read = token_byte & 0x0f
	block.match_length = int(initial_read)
	last_read_length = 255
	for initial_read == 15 && last_read_length == 255 {
		b := bytes.reader_read_byte(r) or_return
		last_read_length = b
		block.match_length += int(last_read_length)
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

	path :: "test-data/plain-01.txt.lz4"
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
	Compress_Block_Error,
}

Max_Block_Size :: enum {
	Kilobytes_64,
	Kilobytes_256,
	Megabyte,
	Megabytes_4,
}

max_block_size_int_value :: proc(max_block_size: Max_Block_Size) -> int {
	switch max_block_size {
	case .Kilobytes_64:
		return 64 * mem.Kilobyte
	case .Kilobytes_256:
		return 256 * mem.Kilobyte
	case .Megabyte:
		return mem.Megabyte
	case .Megabytes_4:
		return 4 * mem.Megabyte
	}

	panic("Invalid max block size")
}

frame_header_serialize :: proc(
	d: Frame_Descriptor,
	allocator := context.allocator,
) -> (
	data: []byte,
	error: io.Error,
) {
	b: bytes.Buffer
	bytes.buffer_init_allocator(&b, 0, 0, allocator)

	flags := u8(d.version << 6)
	if d.block_independence {
		flags |= 0x20
	}
	if d.has_block_checksum {
		flags |= 0x10
	}
	if d.content_size != 0 {
		flags |= 0x08
	}
	if d.has_content_checksum {
		flags |= 0x04
	}
	if d.dictionary_id != 0 {
		flags |= 0x01
	}
	bytes.buffer_write_byte(&b, flags) or_return

	bd_byte := encode_block_max_size(d.block_max_size) << 4
	bytes.buffer_write_byte(&b, bd_byte) or_return

	if d.content_size != 0 {
		content_size_bytes := transmute([8]byte)u64le(d.content_size)
		bytes.buffer_write(&b, content_size_bytes[:]) or_return
	}

	if d.dictionary_id != 0 {
		dictionary_id_bytes := transmute([4]byte)u32le(d.dictionary_id)
		bytes.buffer_write(&b, dictionary_id_bytes[:]) or_return
	}

	header_bytes := bytes.buffer_to_bytes(&b)

	return header_bytes, nil
}

// Produces a serialized LZ4 frame from the given data.
compress :: proc(
	data: []byte,
	max_block_size: Max_Block_Size = Max_Block_Size.Megabytes_4,
	allocator := context.allocator,
) -> (
	result: []byte,
	error: Compress_Error,
) {
	b: bytes.Buffer
	bytes.buffer_init_allocator(&b, 0, 0, allocator)

	max_block_size_int := max_block_size_int_value(max_block_size)

	frame: Frame
	frame.descriptor.version = 1
	frame.descriptor.block_independence = true
	frame.descriptor.has_block_checksum = true
	frame.descriptor.has_content_checksum = true
	frame.descriptor.block_max_size = max_block_size_int
	frame.descriptor.content_size = len(data)
	frame.descriptor.dictionary_id = 0
	header_bytes := frame_header_serialize(frame.descriptor) or_return
	header_checksum := u8(xxhash.XXH32(header_bytes, 0) >> 8)
	frame.descriptor.header_checksum = header_checksum
	frame.content_checksum = u32le(xxhash.XXH32(data, 0))
	frame.descriptor.calculated_checksum = header_checksum

	number_of_blocks := len(data) / max_block_size_int
	if len(data) % max_block_size_int != 0 {
		number_of_blocks += 1
	}

	blocks := make([dynamic]Frame_Block, 0, number_of_blocks, allocator) or_return

	for i in 0 ..< number_of_blocks {
		start_index := i * max_block_size_int
		end_index := start_index + max_block_size_int
		if end_index > len(data) {
			end_index = len(data)
		}

		block_data := data[start_index:end_index]

		block: Frame_Block
		block.compressed = true
		block.data = compress_block(block_data, allocator) or_return
		block.checksum = xxhash.XXH32(block.data, 0)
		block.size = len(block.data)

		savings := (f64(1) - f64(len(block.data)) / f64(len(block_data))) * 100
		log.debugf(
			"Block #%d savings: %.2f%% (original=%d, compressed=%d)",
			i,
			savings,
			len(block_data),
			len(block.data),
		)

		append(&blocks, block) or_return
	}

	frame.blocks = blocks[:]

	result = frame_serialize(frame, allocator) or_return

	return result, nil
}

Token :: struct {
	match:    Match,
	literals: []byte,
}

Match :: struct {
	index:  int,
	length: int,
}

Compression_Context :: struct {
	sequence_table: map[xxhash.XXH32_hash]Match,
}

compression_context_init :: proc(
	allocator := context.allocator,
) -> (
	ctx: Compression_Context,
	error: mem.Allocator_Error,
) {
	sequence_table := make(map[xxhash.XXH32_hash]Match, 0, allocator) or_return
	ctx.sequence_table = sequence_table

	return ctx, nil
}

Compress_Block_Error :: union {
	mem.Allocator_Error,
	io.Error,
}

compress_block :: proc(
	data: []byte,
	allocator := context.allocator,
) -> (
	result: []byte,
	error: Compress_Block_Error,
) {
	ctx := compression_context_init(allocator) or_return

	b: bytes.Buffer
	bytes.buffer_init_allocator(&b, 0, 0, allocator)
	last_token_index := 0

	for i := 0; i < len(data); {
		if i >= len(data) - 5 {
			literals := data[last_token_index:]
			token_byte := byte(len(literals) << 4)
			bytes.buffer_write_byte(&b, token_byte) or_return

			bytes.buffer_write(&b, literals) or_return

			break
		}

		window_hash := xxhash.XXH32(data[i:i + 4], 0)
		match, have_match := &ctx.sequence_table[window_hash]
		if !have_match ||
		   i - match.index >= 65_536 ||
		   bytes.compare(data[i:i + 4], data[match.index:match.index + 4]) != 0 {
			ctx.sequence_table[window_hash] = Match {
				index  = i,
				length = 4,
			}
			i += 1
			continue
		}

		m := match^
		// TODO(gonz): see if we can move the match index forward here and still retain the same
		// output. This should make it so that we are more likely to hit already cached data(?) and
		// should be faster overall.
		for m.index + m.length < (len(data) - 12) && i + m.length < (len(data) - 12) {
			if data[i + m.length] != data[m.index + m.length] {
				break
			}
			m.length += 1
		}

		literals_length := i - last_token_index
		assert(
			literals_length >= 0,
			fmt.tprintf("literals_length is negative: %d", literals_length),
		)
		literals := data[last_token_index:i]
		match_length := m.length - 4
		assert(match_length >= 0, fmt.tprintf("match_length is negative: %d", match_length))

		token_byte: byte
		if literals_length >= 15 {
			token_byte = 0xf0
		} else {
			token_byte = byte(literals_length << 4)
		}
		literals_length -= 15

		if match_length >= 15 {
			token_byte |= 0x0f
		} else {
			token_byte |= byte(match_length) & 0x0f
		}
		match_length -= 15
		bytes.buffer_write_byte(&b, token_byte) or_return

		for literals_length >= 255 {
			literals_length -= 255
			bytes.buffer_write_byte(&b, 0xff) or_return
		}
		if literals_length >= 0 {
			bytes.buffer_write_byte(&b, byte(literals_length)) or_return
		}

		bytes.buffer_write(&b, literals) or_return

		offset := u16le(i - m.index)
		assert(offset != 0, "Offset is 0")
		assert(
			int(offset) <= i,
			fmt.tprintf("Offset is longer than we've passed through data: %d", offset),
		)
		assert(
			data[i] == data[i - int(offset)],
			fmt.tprintf(
				"data[i] != data[i - int(offset)]: %c != %c (i=%d, offset=%d, m.index=%d)",
				data[i],
				data[i - int(offset)],
				i,
				offset,
				m.index,
			),
		)
		offset_bytes := transmute([2]byte)offset
		bytes.buffer_write(&b, offset_bytes[:]) or_return

		for match_length >= 255 {
			match_length -= 255
			bytes.buffer_write_byte(&b, 0xff) or_return
		}
		if match_length >= 0 {
			bytes.buffer_write_byte(&b, byte(match_length)) or_return
		}

		last_token_index = i + m.length
		i += m.length
	}

	result = bytes.buffer_to_bytes(&b)

	return result, nil
}

@(test, private = "package")
test_compress :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger()

	files := []string{
		"test-data/plain-01.txt",
		"test-data/lz4-2023-11-01.odin",
		"test-data/odin/core/os/os_windows.odin",
		"test-data/odin/core/os/os_darwin.odin",
		"test-data/odin/core/os/os_linux.odin",
		"test-data/odin/core/os/os_freebsd.odin",
		"test-data/odin/core/os/os_openbsd.odin",
	}

	large_files, _ := all_files_in_directory("test-data/large-odin-files")

	all_files := slice.concatenate([][]string{files, large_files})

	count := 0
	for f in all_files {
		expect_compression_invariants_to_hold(t, f)
		count += 1
	}

	log.infof("Compressed %d files", count)
}

@(private = "file")
_all_files_walk_proc :: proc(
	info: os.File_Info,
	in_err: os.Errno,
	user_data: rawptr,
) -> (
	err: os.Errno,
	skip_dir: bool,
) {
	if !info.is_dir {
		files := cast(^[dynamic]string)user_data
		append(files, info.fullpath)
	}

	return err, skip_dir
}

@(private = "file")
all_files_in_directory :: proc(
	path: string,
	allocator := context.allocator,
) -> (
	paths: []string,
	error: mem.Allocator_Error,
) {
	files := make([dynamic]string, 0, 0, allocator) or_return

	walk_result := filepath.walk(path, _all_files_walk_proc, &files)
	if walk_result != os.ERROR_NONE {
		fmt.panicf("Could not walk directory '%s': %v", path, walk_result)
	}

	return files[:], nil
}

expect_compression_invariants_to_hold :: proc(t: ^testing.T, path: string) {
	context.logger = log.create_console_logger(ident = path)
	path := path
	if filepath.is_abs(path) {
		cwd := os.get_current_directory()
		relative_path, relative_path_error := filepath.rel(cwd, path)
		if relative_path_error != nil {
			fmt.panicf("Could not get relative path: %v", relative_path_error)
		}
		path = relative_path
	}
	context.logger = log.create_console_logger(ident = path)

	file_data, read_ok := os.read_entire_file_from_filename(path)
	if !read_ok {
		fmt.panicf("Could not read file for test: '%s'", path)
	}

	compressed, compress_error := compress(file_data)
	testing.expect(
		t,
		compress_error == nil,
		fmt.tprintf("Compress error is not nil: %v\n", compress_error),
	)
	testing.expect(
		t,
		len(compressed) < len(file_data),
		fmt.tprintf(
			"Compressed data is not smaller than original: %d >= %d\n",
			len(compressed),
			len(file_data),
		),
	)
	testing.expect(t, len(compressed) > 0, fmt.tprintf("Compressed data is empty\n"))

	frame, _, frame_error := frame_next(compressed)
	testing.expect(t, frame_error == nil, fmt.tprintf("Frame error is not nil: %v\n", frame_error))
	testing.expect(
		t,
		frame.descriptor.version == 1,
		fmt.tprintf("Frame version is not 1: %d\n", frame.descriptor.version),
	)

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
			bytes.compare(d, file_data) == 0,
			fmt.tprintf("Decompressed data does not match original data: '%s'\n", d),
		)
	case [][]byte:
		concatenated := bytes.concatenate(d)
		content_checksum := xxhash.XXH32(concatenated, 0)
		concatenated_length := len(concatenated)
		testing.expect(
			t,
			concatenated_length == frame.descriptor.content_size,
			fmt.tprintf(
				"Content size mismatch: %d != %d\n",
				concatenated_length,
				frame.descriptor.content_size,
			),
		)

		if concatenated_length != frame.descriptor.content_size {
			concatenated_end: [25]byte
			copy(concatenated_end[:], concatenated[len(concatenated) - 25:])
			file_end: [25]byte
			copy(file_end[:], file_data[len(file_data) - 25:])

			fmt.printf("Concatenated end:\n'''\n%s\n'''\n", concatenated_end)
			fmt.printf("File end:\n'''\n%s\n'''\n", file_end)
		}

		if concatenated_length == frame.descriptor.content_size {
			testing.expect(
				t,
				u32le(content_checksum) == frame.content_checksum,
				fmt.tprintf(
					"Content checksum mismatch: %d != %d\n",
					content_checksum,
					frame.content_checksum,
				),
			)
			compare_result := bytes.compare(concatenated, file_data)
			testing.expect(
				t,
				compare_result == 0,
				fmt.tprintf(
					"Decompressed data does not match original data: '%s'\n",
					concatenated,
				),
			)
		}
	}
}

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
