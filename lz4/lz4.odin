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
	descriptor: Frame_Descriptor,
	blocks:     []Frame_Block,
}

Frame_Descriptor :: struct {
	version:             int,
	block_independence:  bool,
	has_block_checksum:  bool,
	block_max_size:      int,
	content_size:        int,
	dictionary_id:       int,
	header_checksum:     u8,
	calculated_checksum: u8,
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
		// has_content_checksum := flags & 0x04 != 0
		has_dictionary_id := flags & 0x01 != 0

		ix += 1
		bd := data[ix]
		block_max_size := get_block_max_size(bd & 0x70 >> 4)

		ix += 1

		frame.descriptor.version = version
		frame.descriptor.block_independence = block_independence
		frame.descriptor.has_block_checksum = has_block_checksum
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

		frame_end: int
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
				ix += 4
			}

			append(&blocks, block) or_return
		}
		frame.blocks = blocks[:]

		if frame_end == 0 {
			frame_end = bytes.index(data[ix:], []byte{0, 0, 0, 0})
		}
		if frame_end == -1 {
			return Frame{}, data, Infinite_Frame{start = i}
		}

		frame_end += i
		frame_end += 4 // Add the 4 bytes of the magic number
		frame_end += 4 // Add the 4 bytes of the frame end marker

		rest = data[frame_end:]

		return frame, rest, nil
	}

	return Frame{}, nil, No_Frame{}
}

Block :: struct {
	length:       int,
	literals:     []byte,
	offset:       int,
	match_length: int,
}

Block_Error :: union {
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

read_block :: proc(
	r: ^bytes.Reader,
	allocator := context.allocator,
) -> (
	block: Block,
	error: Block_Error,
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
			return Block{},
				Not_Enough_Literals{expected = block.length, actual = literal_bytes_read}
		}

		block.literals = literals
	}

	if token_byte & 0x0f == 0 {

	}

	offset_buffer: [2]byte
	_, offset_read := bytes.reader_read(r, offset_buffer[:])
	if offset_read == .EOF {
		// This means we've read the last block, we have only literals and no offset
		return block, nil
	}
	offset := transmute(u16le)offset_buffer
	if offset == 0 {
		return Block{}, Zero_Offset{position = int(r.i)}
	}
	block.offset = -int(offset)

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
test_read_block :: proc(t: ^testing.T) {
	context.logger = log.create_console_logger()

	bytes_1_prelude := []byte{0x88}
	offset_bytes_1 := transmute([2]byte)u16le(4)
	bytes_1 := bytes.concatenate(
		[][]byte{bytes_1_prelude, bytes.repeat([]byte{0}, 8), offset_bytes_1[:]},
	)
	r1: bytes.Reader
	bytes.reader_init(&r1, bytes_1)
	block1, err1 := read_block(&r1)
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
	block2, err2 := read_block(&r2)
	testing.expect_value(t, err2, nil)
	testing.expect_value(t, block2.length, 15 + 255 + 2)
	testing.expect_value(t, block2.match_length, 8)
	testing.expect_value(t, block2.offset, 1)

	bytes_3 := []byte{0xf0, 33}
	r3: bytes.Reader
	bytes.reader_init(&r3, bytes_3)
	block3, err3 := read_block(&r3)
	testing.expect_value(t, err3, io.Error.EOF)
	testing.expect_value(t, block3.length, 48)

	bytes_4 := []byte{0xf0, 255, 10}
	r4: bytes.Reader
	bytes.reader_init(&r4, bytes_4)
	block4, err4 := read_block(&r4)
	testing.expect_value(t, err4, io.Error.EOF)
	testing.expect_value(t, block4.length, 280)

	bytes_5 := []byte{0xf0, 0}
	r5: bytes.Reader
	bytes.reader_init(&r5, bytes_5)
	block5, err5 := read_block(&r5)
	testing.expect_value(t, err5, io.Error.EOF)
	testing.expect_value(t, block5.length, 15)
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

	for frame, i in frames {
		fmt.printf("[%d] %v\n", i, frame.descriptor)
		fmt.printf("\tBlock count: %d\n", len(frame.blocks))
		for block, j in frame.blocks {
			fmt.printf(
				"\t\t[%d] Size=%d, Compressed=%v, Checksum=%d\n",
				j,
				block.size,
				block.compressed,
				block.checksum,
			)
		}
	}

	testing.expect_value(t, len(frames), 12)
}
