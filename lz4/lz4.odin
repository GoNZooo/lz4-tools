package lz4

import "core:bytes"
import "core:fmt"
import "core:hash/xxhash"
import "core:io"
import "core:log"
import "core:mem"
import "core:mem/virtual"
import "core:os"
import "core:path/filepath"
import "core:runtime"
import "core:slice"
import "core:strings"
import "core:testing"
import "core:time"

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

No_Magic_Value :: struct {
	bytes: [4]byte,
}

Data_Too_Small :: struct {
	size: int,
}

Infinite_Frame :: struct {
	start: int,
}

Frame_Descriptor_Read_Error :: union {
	No_Magic_Value,
	Data_Too_Small,
}

// Reads a `Frame_Descriptor` from a slice of bytes and returns the rest of the bytes after the
// descriptor has been read.
frame_descriptor_read :: proc(
	data: []byte,
	loc := #caller_location,
) -> (
	fd: Frame_Descriptor,
	rest: []byte,
	error: Frame_Descriptor_Read_Error,
) {
	i := 0
	if len(data) < 2 {
		return Frame_Descriptor{}, data, Data_Too_Small{size = len(data)}
	}

	magic_value_buffer: [4]byte
	copy(magic_value_buffer[:], data[i:i + 4])
	magic_value := transmute(u32le)magic_value_buffer
	if magic_value != MAGIC_VALUE {
		return Frame_Descriptor{}, data, No_Magic_Value{bytes = magic_value_buffer}
	}
	i += 4

	flags := data[i]
	i += 1

	fd.version = int(flags >> 6)
	fd.block_independence = flags & 0x20 != 0
	fd.has_block_checksum = flags & 0x10 != 0
	has_content_size := flags & 0x08 != 0
	fd.has_content_checksum = flags & 0x04 != 0
	has_dictionary_id := flags & 0x01 != 0

	bd := data[i]
	i += 1
	fd.block_max_size = get_block_max_size((bd & 0x70) >> 4)

	if has_content_size {
		if len(data) < i + 8 {
			return Frame_Descriptor{}, data, Data_Too_Small{size = len(data)}
		}

		content_size_buffer: [8]byte
		copy(content_size_buffer[:], data[i:i + 8])
		fd.content_size = cast(int)transmute(u64le)content_size_buffer
		i += 8
	}

	if has_dictionary_id {
		if len(data) < i + 4 {
			return Frame_Descriptor{}, data, Data_Too_Small{size = len(data)}
		}

		dictionary_id_buffer: [4]byte
		copy(dictionary_id_buffer[:], data[i:i + 4])
		fd.dictionary_id = cast(int)transmute(u32le)dictionary_id_buffer
	}

	checksum_bytes := data[4:i]
	calculated_checksum := u8(xxhash.XXH32(checksum_bytes, 0) >> 8)
	fd.calculated_checksum = calculated_checksum
	fd.header_checksum = data[i]
	i += 1
	assert(
		fd.header_checksum == calculated_checksum,
		fmt.tprintf(
			"Checksum mismatch: %#x != %#x (called from %v)",
			fd.header_checksum,
			calculated_checksum,
			loc,
		),
	)

	return fd, data[i:], nil
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
		assert(
			u32(n) == size,
			fmt.tprintf(
				"block data bytes read != size: %d != %d (compressed=%v\thas_checksum=%v\tsize=%d\tblock_size=%d\tsize_bytes=%x)",
				n,
				size,
				compressed,
				has_checksum,
				size,
				block_size,
				block_size_buffer,
			),
		)

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
		r.i -= 4
	}

	return frame_blocks[:], nil
}

Data_Block :: struct {
	length:       int,
	literals:     []byte,
	offset:       int,
	match_length: int,
}

Frame_Decompress_Error :: union {
	Insufficient_Space_In_Buffer,
	Frame_Block_Decompress_Error,
	io.Error,
	mem.Allocator_Error,
}

Frame_Block_Decompress_Error :: struct {
	block:            Frame_Block,
	data_block_index: int,
	error:            Data_Block_Read_Error,
}

Data_Block_Read_Error :: union {
	Zero_Offset,
	Not_Enough_Literals,
	io.Error,
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

Frame_Decompress_Result :: union {
	[][]byte,
	[]byte,
}

Decompress_Error :: union {
	Frame_Descriptor_Read_Error,
	Frame_Block_Read_Error,
	Not_Enough_Literals,
	Insufficient_Space_In_Buffer,
	Zero_Offset,
	Data_Too_Small,
	Content_Checksum_Mismatch,
	Infinite_Frame,
	mem.Allocator_Error,
}

Content_Checksum_Mismatch :: struct {
	expected: u32,
	actual:   u32,
}

decompress :: proc(
	input_data: []byte,
	content_size := 0,
	allocator := context.allocator,
) -> (
	decompressed: []byte,
	rest: []byte,
	error: Decompress_Error,
) {
	data := input_data

	descriptor, after_descriptor := frame_descriptor_read(data) or_return
	decompressed = make(
		[]byte,
		descriptor.content_size == 0 ? content_size : descriptor.content_size,
		allocator,
	) or_return

	data = after_descriptor

	copy_index := 0
	for {
		fb, after_fb, read_error := frame_block_read(data, descriptor.has_block_checksum)
		_, is_end_mark_found := read_error.(End_Mark_Found)
		if is_end_mark_found {
			break
		}
		data = after_fb

		i := 0
		for {
			if i == fb.size {
				break
			}

			if !fb.compressed {
				copy(decompressed[copy_index:], fb.data)
				copy_index += len(fb.data)

				continue
			}

			token_byte := fb.data[i]
			i += 1
			literals_length := int(token_byte >> 4)
			match_length := int(token_byte & 0x0f)
			if literals_length == 15 {
				for {
					s := fb.data[i]
					i += 1
					literals_length += int(s)
					if s != 255 {
						break
					}
				}
			}

			literals := fb.data[i:i + literals_length]
			i += literals_length

			if len(literals) != literals_length {
				return nil,
					nil,
					Not_Enough_Literals{expected = literals_length, actual = len(literals)}
			}

			copy(decompressed[copy_index:], literals)
			copy_index += len(literals)

			if i == len(fb.data) {
				// This means that there is no offset, which is an end marker
				continue
			}

			offset_bytes := [2]byte{fb.data[i], fb.data[i + 1]}
			i += 2
			offset := transmute(u16le)offset_bytes
			if offset == 0 {
				return nil, nil, Zero_Offset{position = i}
			}

			if match_length == 15 {
				for {
					m := fb.data[i]
					i += 1
					match_length += int(m)
					if m != 255 {
						break
					}
				}
			}
			match_length += 4

			copy_start := copy_index - int(offset)
			copy_end := copy_start + match_length
			if copy_end > len(decompressed) {
				return nil,
					nil,
					Insufficient_Space_In_Buffer{expected = copy_end, actual = len(decompressed)}
			}

			if int(offset) < match_length {
				copy_bytes := decompressed[copy_start:copy_index]
				copy(decompressed[copy_index:], copy_bytes)
				copy_index += len(copy_bytes)
				remaining_bytes := match_length - int(offset)
				for i in 0 ..< remaining_bytes {
					decompressed[copy_index + i] = copy_bytes[i % len(copy_bytes)]
				}
				copy_index += remaining_bytes
			} else {
				copy_bytes := decompressed[copy_start:copy_end]
				copy(decompressed[copy_index:], copy_bytes)
				copy_index += match_length
			}

			if i + 4 > len(fb.data) {
				return nil, nil, Data_Too_Small{size = len(fb.data)}
			}
		}
	}

	end_marker_bytes: [4]byte
	copy(end_marker_bytes[:], data[:4])
	end_marker := transmute(u32le)end_marker_bytes
	if end_marker != 0 {
		return nil, nil, Infinite_Frame{start = len(input_data) - len(data)}
	}
	data = data[4:]

	if descriptor.has_content_checksum {
		if len(data) < 4 {
			return nil, nil, Data_Too_Small{size = len(data)}
		}
		content_checksum_buffer: [4]byte
		copy(content_checksum_buffer[:], data[:4])
		content_checksum := transmute(u32le)content_checksum_buffer
		calculated_content_checksum := u32le(xxhash.XXH32(decompressed, 0))

		if content_checksum != calculated_content_checksum {
			return decompressed,
				nil,
				Content_Checksum_Mismatch{
					expected = u32(content_checksum),
					actual = u32(calculated_content_checksum),
				}
		}
	}
	data = data[4:]

	return decompressed, data, nil
}

Frame_Block_Read_Error :: union {
	End_Mark_Found,
	Data_Too_Small,
}

End_Mark_Found :: struct {
	rest: []byte,
}

frame_block_read :: proc(
	data: []byte,
	has_checksum: bool,
) -> (
	fb: Frame_Block,
	rest: []byte,
	error: Frame_Block_Read_Error,
) {
	i := 0

	if len(data) < 4 {
		return Frame_Block{}, nil, Data_Too_Small{size = len(data)}
	}
	block_size_buffer: [4]byte
	copy(block_size_buffer[:], data[i:i + 4])
	i += 4
	block_size := transmute(u32)block_size_buffer
	compressed := block_size & 0x8000_0000 == 0
	size := int(block_size & 0x7f_ff_ff_ff)
	if block_size == 0 {
		return Frame_Block{}, data[i:], End_Mark_Found{rest = data[i:]}
	}

	if len(data) < i + size {
		return Frame_Block{}, nil, Data_Too_Small{size = len(data)}
	}
	block_data := data[i:i + size]
	i += size

	checksum: u32le
	if has_checksum {
		checksum_buffer: [4]byte
		copy(checksum_buffer[:], data[i:i + 4])
		i += 4
		checksum = transmute(u32le)checksum_buffer
	}

	fb = Frame_Block {
		size       = size,
		data       = block_data,
		checksum   = u32(checksum),
		compressed = compressed,
	}

	return fb, data[i:], nil
}

frame_decompress :: proc(
	frame: Frame,
	allocator := context.allocator,
) -> (
	decompressed: Frame_Decompress_Result,
	error: Frame_Decompress_Error,
) {
	// NOTE(gonz): if we have block dependence but only one block in the frame it should be the same
	// as having independent blocks, I assume
	if !frame.descriptor.block_independence && len(frame.blocks) > 1 {
		return frame_decompress_dependently(frame, allocator)
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

		decompressed_block := frame_block_decompress(
			b,
			frame.descriptor.block_max_size,
			allocator,
		) or_return
		append(&decompressed_blocks, decompressed_block) or_return
	}

	return decompressed_blocks[:], nil
}

@(private = "file")
frame_block_decompress :: proc(
	fb: Frame_Block,
	max_block_size: int,
	allocator := context.allocator,
) -> (
	decompressed: []byte,
	error: Frame_Decompress_Error,
) {
	b: bytes.Buffer
	bytes.buffer_init_allocator(&b, 0, max_block_size, allocator)

	block_data := fb.data
	for len(block_data) > 0 {
		db, rest, data_block_read_error := data_block_read(block_data)
		if data_block_read_error != nil {
			return nil,
				Frame_Block_Decompress_Error{
					block = fb,
					data_block_index = len(decompressed),
					error = data_block_read_error,
				}
		}
		block_data = rest

		literals_written := bytes.buffer_write(&b, db.literals) or_return
		assert(
			literals_written == db.length,
			fmt.tprintf("literals_written != db.length: %d != %d", literals_written, db.length),
		)

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
			assert(
				match_start >= 0 && match_start <= len(b.buf),
				fmt.tprintf("match_start is out of bounds: %d", match_start),
			)
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
test_decompress :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger()
	Test_Case :: struct {
		compressed_path: string,
		plain_text_path: string,
	}

	own_paths := []string{"test-data/plain-01.txt.lz4", "test-data/lz4-2023-11-01.odin.lz4"}
	odin_files, odin_files_error := all_files_in_directory("test-data/large-odin-files", "*.lz4")
	if odin_files_error != nil {
		fmt.panicf("Could not read files in directory: %v\n", odin_files_error)
	}
	paths := slice.concatenate([][]string{own_paths, odin_files})
	cwd := os.get_current_directory()

	start_time := time.tick_now()
	for path in paths {
		ok := expect_decompress_invariants_to_hold(t, path, logger = log.nil_logger())
		if !ok {
			log_filename := path
			if filepath.is_abs(path) {
				relative_filename, relative_filename_error := filepath.rel(cwd, path)
				if relative_filename_error != nil {
					fmt.panicf("Could not get relative filename: %v", relative_filename_error)
				}
				log_filename = relative_filename
			}
			log_path := filepath.join([]string{"test-logs", "decompress", log_filename})
			make_all_directories(log_path)
			h, open_error := os.open(
				log_path,
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC,
				mode = 0o644,
			)
			if open_error != os.ERROR_NONE {
				fmt.panicf("Could not open test log file '%s': %v", log_path, os.Errno(open_error))
			}
			expect_decompress_invariants_to_hold(
				t,
				path,
				logger = log.create_file_logger(h, lowest = .Debug),
			)
			os.close(h)

			fmt.panicf("Decompression test failed for '%s', log file is at '%s'", path, log_path)
		}
	}

	diff := time.tick_diff(start_time, time.tick_now())
	log.infof("Decompressed %d files in %d", len(paths), diff)
}

@(test, private = "package")
test_frame_decompress :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger()
	Test_Case :: struct {
		compressed_path: string,
		plain_text_path: string,
	}

	own_paths := []string{"test-data/plain-01.txt.lz4", "test-data/lz4-2023-11-01.odin.lz4"}
	odin_files, odin_files_error := all_files_in_directory("test-data/large-odin-files", "*.lz4")
	if odin_files_error != nil {
		fmt.panicf("Could not read files in directory: %v\n", odin_files_error)
	}
	paths := slice.concatenate([][]string{own_paths, odin_files})
	cwd := os.get_current_directory()

	start_time := time.tick_now()
	for path in paths {
		ok := expect_decompress_frame_invariants_to_hold(t, path, logger = log.nil_logger())
		if !ok {
			log_filename := path
			if filepath.is_abs(path) {
				relative_filename, relative_filename_error := filepath.rel(cwd, path)
				if relative_filename_error != nil {
					fmt.panicf("Could not get relative filename: %v", relative_filename_error)
				}
				log_filename = relative_filename
			}
			log_path := filepath.join([]string{"test-logs", "decompress", log_filename})
			make_all_directories(log_path)
			h, open_error := os.open(
				log_path,
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC,
				mode = 0o644,
			)
			if open_error != os.ERROR_NONE {
				fmt.panicf("Could not open test log file '%s': %v", log_path, os.Errno(open_error))
			}
			expect_decompress_frame_invariants_to_hold(
				t,
				path,
				logger = log.create_file_logger(h, lowest = .Debug),
			)
			os.close(h)
			fmt.panicf("Decompression test failed for '%s', log file is at '%s'", path, log_path)
		}
	}

	diff := time.tick_diff(start_time, time.tick_now())
	log.infof("Decompressed %d files in %d", len(paths), diff)
}

@(private = "file")
_default_determine_logging_proc :: proc(_: string) -> bool {
	return false
}


@(private = "file")
expect_decompress_frame_invariants_to_hold :: proc(
	t: ^testing.T,
	compressed_path: string,
	logger: log.Logger,
) -> bool {
	context.logger = logger

	dir := filepath.dir(compressed_path)
	stem := filepath.stem(compressed_path)
	path := filepath.join({dir, stem})

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
	decompressed, decompress_error := frame_decompress(frame)
	testing.expect(
		t,
		decompress_error == nil,
		fmt.tprintf("Decompress error is not nil: %v\n", decompress_error),
	) or_return

	compare_result: int
	buffer: []byte
	switch d in decompressed {
	case []byte:
		compare_result = bytes.compare(d, plain_data)
		buffer = d
		testing.expect(
			t,
			compare_result == 0,
			fmt.tprintf("Decompressed data does not match plain data in file '%s'\n", path),
		) or_return
	case [][]byte:
		concatenated := bytes.concatenate(d)
		buffer = concatenated
		compare_result = bytes.compare(concatenated, plain_data)
		testing.expect(
			t,
			compare_result == 0,
			fmt.tprintf("Decompressed data does not match plain data in file '%s'\n", path),
		) or_return
	}

	if compare_result != 0 {
		plain_length := len(plain_data)
		decompressed_length := len(buffer)
		if plain_length != decompressed_length {
			fmt.panicf(
				"Decompressed data does not match plain data in file '%s':\n\tLengths do not match: %d != %d\n",
				path,
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

	return true
}

@(private = "file")
expect_decompress_invariants_to_hold :: proc(
	t: ^testing.T,
	compressed_path: string,
	logger: log.Logger,
) -> bool {
	dir := filepath.dir(compressed_path)
	stem := filepath.stem(compressed_path)
	path := filepath.join({dir, stem})
	context.logger = logger

	file_data, read_ok := os.read_entire_file_from_filename(compressed_path)
	if !read_ok {
		fmt.panicf("Could not read file for test: '%s'", compressed_path)
	}

	plain_data, plain_read_ok := os.read_entire_file_from_filename(path)
	if !plain_read_ok {
		fmt.panicf("Could not read file for test: '%s'", path)
	}

	decompressed, rest, decompress_error := decompress(file_data, content_size = len(plain_data))
	testing.expect(
		t,
		decompress_error == nil,
		fmt.tprintf("Decompress error is not nil ('%s'): %v\n", compressed_path, decompress_error),
	) or_return
	testing.expect(t, len(rest) == 0, fmt.tprintf("Rest is not empty: %d\n", len(rest))) or_return

	buffer: []byte

	compare_result := bytes.compare(decompressed, plain_data)
	testing.expect(
		t,
		compare_result == 0,
		fmt.tprintf("Decompressed data does not match plain data in file '%s'\n", path),
	) or_return

	if compare_result != 0 {
		plain_length := len(plain_data)
		decompressed_length := len(decompressed)
		if plain_length != decompressed_length {
			fmt.panicf(
				"Decompressed data does not match plain data in file '%s':\n\tLengths do not match: %d != %d\n",
				path,
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

	return true
}


@(private = "file")
frame_decompress_dependently :: proc(
	frame: Frame,
	allocator := context.allocator,
) -> (
	decompressed: []byte,
	error: Frame_Decompress_Error,
) {
	fmt.panicf("Block dependence not currently supported")
}

data_block_read :: proc(
	data: []byte,
) -> (
	block: Data_Block,
	rest: []byte,
	error: Data_Block_Read_Error,
) {
	i := 0
	token_byte := data[i]
	i += 1
	initial_read := token_byte >> 4
	block.length = int(initial_read)
	last_read_length: byte = 255
	for initial_read == 15 && last_read_length == 255 {
		b := data[i]
		i += 1
		last_read_length = b
		block.length += int(last_read_length)
	}

	literals := data[i:i + block.length]

	assert(len(literals) == block.length)

	block.literals = literals

	i += block.length

	if i == len(data) {
		// This means we've read the last block, we have only literals and no offset
		return block, data[i:], nil
	}
	offset_bytes := [2]byte{data[i], data[i + 1]}
	i += 2
	offset := transmute(u16le)offset_bytes
	if offset == 0 {
		return Data_Block{}, data[i:], Zero_Offset{position = i}
	}
	block.offset = int(offset)

	initial_read = token_byte & 0x0f
	block.match_length = int(initial_read)
	last_read_length = 255
	for initial_read == 15 && last_read_length == 255 {
		b := data[i]
		i += 1
		last_read_length = b
		block.match_length += int(last_read_length)
	}
	block.match_length += 4

	return block, data[i:], nil
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
	// we skip the magic number for the checksum calculation
	header_bytes := bytes_so_far[4:]
	hash := xxhash.XXH32(header_bytes, 0)
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
		size_bytes_written := bytes.buffer_write(b, block_size_bytes[:]) or_return
		assert(
			size_bytes_written == 4,
			fmt.tprintf("size_bytes_written != 4: %d", size_bytes_written),
		)

		data_bytes_written := bytes.buffer_write(b, block.data) or_return
		assert(
			data_bytes_written == block.size,
			fmt.tprintf(
				"data_bytes_written != block.size: %d != %d (len(block.data)=%d)",
				data_bytes_written,
				block.size,
				len(block.data),
			),
		)

		if has_checksum {
			block_checksum_bytes := transmute([4]byte)u32(block.checksum)
			checksum_bytes_written := bytes.buffer_write(b, block_checksum_bytes[:]) or_return
			assert(
				checksum_bytes_written == 4,
				fmt.tprintf("checksum_bytes_written != 4: %d", checksum_bytes_written),
			)
		}
	}

	return nil
}

@(test, private = "package")
test_frame_serialize :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger(lowest = .Info)

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
	max_block_size: Max_Block_Size = Max_Block_Size.Kilobytes_64,
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
		if last_token_index >= (len(data) - 12) {
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
		// NOTE: this should move what is technically the same match further forward in the data
		// which means we have a better chance of sharing cache space with the data we are already
		// processing(?). I have not measured this.
		match.index = i
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

@(private = "file")
make_all_directories :: proc(path: string) {
	dir := filepath.dir(path)
	directories, split_error := strings.split(dir, "/")
	if split_error != nil {
		fmt.panicf("Could not split path '%s': %v", dir, split_error)
	}
	for _, i in directories {
		parts := directories[:i + 1]
		directory := filepath.join(parts)
		make_dir_error := os.make_directory(directory)
		if make_dir_error == os.EEXIST {
			continue
		} else if make_dir_error != os.ERROR_NONE {
			fmt.panicf("Could not make directory '%s': %v", directory, make_dir_error)
		}
	}
}

@(test, private = "package")
test_compress :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger()

	files := []string{"test-data/plain-01.txt", "test-data/lz4-2023-11-01.odin"}

	odin_files, _ := all_files_in_directory("test-data/large-odin-files", pattern = "*.odin")

	all_files := slice.concatenate([][]string{files, odin_files})
	delete(odin_files)

	sizes := []Max_Block_Size{.Kilobytes_64, .Kilobytes_256, .Megabyte, .Megabytes_4}
	cwd := os.get_current_directory()

	for size in sizes {
		count := 0
		start := time.tick_now()
		for f in all_files {
			ok := expect_compression_invariants_to_hold(
				t,
				f,
				max_block_size = size,
				logger = log.nil_logger(),
			)
			if !ok {
				log_filename := f
				if filepath.is_abs(f) {
					relative_filename, relative_filename_error := filepath.rel(cwd, f)
					if relative_filename_error != nil {
						fmt.panicf("Could not get relative filename: %v", relative_filename_error)
					}
					log_filename = relative_filename
				}
				path := filepath.join([]string{"test-logs", "compress", log_filename})
				make_all_directories(path)
				with_extension := strings.concatenate([]string{path, ".log"})
				h, open_error := os.open(
					with_extension,
					flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC,
					mode = 0o644,
				)
				if open_error != os.ERROR_NONE {
					fmt.panicf("Could not open test log file '%s': %v", path, os.Errno(open_error))
				}
				expect_compression_invariants_to_hold(
					t,
					f,
					max_block_size = size,
					logger = log.create_file_logger(h, lowest = .Debug),
				)
				os.close(h)
				fmt.panicf(
					"Compression test failed for '%s', log file is at '%s'",
					f,
					with_extension,
				)
			}

			count += 1
		}
		diff := time.tick_diff(start, time.tick_now())
		diff_float := f64(diff) / f64(time.Second)

		log.infof("Compressed %d files with max block size %v in %.6fs", count, size, diff_float)
	}
}

All_Files_Data :: struct {
	files:            ^[dynamic]string,
	filename_pattern: string,
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
	data := cast(^All_Files_Data)user_data
	is_match, match_error := filepath.match(data.filename_pattern, info.name)
	if match_error != nil {
		log.panicf("Could not match filename: %v", match_error)
	}
	if !info.is_dir && is_match {
		append(data.files, info.fullpath)
	}

	return err, skip_dir
}

@(private = "file")
all_files_in_directory :: proc(
	path: string,
	pattern := "",
	allocator := context.allocator,
	logger: ^log.Logger = nil,
) -> (
	paths: []string,
	error: mem.Allocator_Error,
) {
	data: All_Files_Data
	data.filename_pattern = pattern
	files := make([dynamic]string, 0, 0, allocator) or_return
	data.files = &files
	context.logger = logger == nil ? runtime.default_logger() : logger^

	walk_result := filepath.walk(path, _all_files_walk_proc, &data)
	if walk_result != os.ERROR_NONE {
		fmt.panicf("Could not walk directory '%s': %v", path, walk_result)
	}

	return files[:], nil
}

expect_compression_invariants_to_hold :: proc(
	t: ^testing.T,
	path: string,
	max_block_size: Max_Block_Size,
	logger: log.Logger,
	allocator := context.allocator,
) -> (
	ok: bool,
) {
	context.logger = logger

	file_data, read_ok := os.read_entire_file_from_filename(path, allocator)
	if !read_ok {
		fmt.panicf("Could not read file for test: '%s'", path)
	}

	compression_arena: virtual.Arena
	arena_init_error := virtual.arena_init_static(&compression_arena, 4 * mem.Megabyte)
	if arena_init_error != nil {
		fmt.panicf("Could not initialize compression_arena: %v", arena_init_error)
	}
	compression_allocator := virtual.arena_allocator(&compression_arena)

	compressed, compress_error := compress(
		file_data,
		max_block_size = max_block_size,
		allocator = compression_allocator,
	)
	testing.expect(
		t,
		compress_error == nil,
		fmt.tprintf("Compress error is not nil: %v\n", compress_error),
	) or_return
	testing.expect(
		t,
		len(compressed) < len(file_data),
		fmt.tprintf(
			"Compressed data is not smaller than original: %d >= %d\n",
			len(compressed),
			len(file_data),
		),
	) or_return
	testing.expect(t, len(compressed) > 0, fmt.tprintf("Compressed data is empty\n")) or_return

	decompression_arena: virtual.Arena
	arena_init_error = virtual.arena_init_static(&decompression_arena, 8 * mem.Megabyte)
	if arena_init_error != nil {
		fmt.panicf("Could not initialize decompression_arena: %v", arena_init_error)
	}
	decompression_allocator := virtual.arena_allocator(&decompression_arena)
	decompressed, rest, decompress_error := decompress(
		compressed,
		content_size = len(file_data),
		allocator = decompression_allocator,
	)
	testing.expect(t, len(rest) == 0, fmt.tprintf("Rest is not empty: %#x\n", rest)) or_return
	testing.expect(
		t,
		decompress_error == nil,
		fmt.tprintf("Decompress error is not nil: %v\n", decompress_error),
	) or_return

	concatenated_length := len(decompressed)
	testing.expect(
		t,
		concatenated_length == len(file_data),
		fmt.tprintf("Content size mismatch: %d != %d\n", concatenated_length, len(file_data)),
	) or_return

	if concatenated_length != len(file_data) {
		concatenated_end: [25]byte
		copy(concatenated_end[:], decompressed[len(decompressed) - 25:])
		file_end: [25]byte
		copy(file_end[:], file_data[len(file_data) - 25:])

		fmt.printf("decompressed end:\n'''\n%s\n'''\n", concatenated_end)
		fmt.printf("File end:\n'''\n%s\n'''\n", file_end)
	}

	if concatenated_length == len(file_data) {
		compare_result := bytes.compare(decompressed, file_data)
		testing.expect(
			t,
			compare_result == 0,
			fmt.tprintf("Decompressed data does not match original data: '%s'\n", decompressed),
		) or_return
	}

	virtual.arena_destroy(&compression_arena)

	return true
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
