package lz4_blocks

import "core:bytes"
import "core:fmt"
import "core:io"
import "core:os"

import "../lz4"

main :: proc() {
	arguments := os.args[1:]

	if len(arguments) == 0 {
		fmt.println("Usage: lz4-frames <file>")
		os.exit(1)
	}

	file_data, ok := os.read_entire_file_from_filename(arguments[0])
	if !ok {
		fmt.println("Could not read file")
		os.exit(1)
	}

	i := 0
	for frame, rest, frame_error := lz4.frame_next(file_data);
	    frame_error == nil;
	    frame, rest, frame_error = lz4.frame_next(rest) {
		buffer: bytes.Buffer
		bytes.buffer_init_allocator(&buffer, 0, frame.descriptor.block_max_size)

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
			r: bytes.Reader
			bytes.reader_init(&r, block.data)
			position := 0
			bi := 0
			b: lz4.Block
			block_error: lz4.Block_Error
			for ; block_error == nil; b, block_error = lz4.read_block(&r) {
				fmt.printf(
					"\t\t\t[%d] len=%d, lits='%s', offset=%d, matchlength=%d\n",
					bi,
					b.length,
					b.literals,
					b.offset,
					b.match_length,
				)

				literals_written, write_error := bytes.buffer_write(&buffer, b.literals)
				if write_error != nil {
					fmt.printf("Error writing to buffer: %v\n", write_error)
					os.exit(1)
				}

				position += literals_written

				match_start := position + b.offset
				match_end := match_start + b.match_length

				match_bytes_written := 0
				match_write_error: io.Error
				if match_end > len(buffer.buf) {
					match_bytes := buffer.buf[match_start:]
					match_bytes_written, match_write_error = bytes.buffer_write(
						&buffer,
						match_bytes,
					)
					if match_write_error != nil {
						fmt.printf("Error writing to buffer: %v\n", match_write_error)
						os.exit(1)
					}
					position += match_bytes_written

					match_bytes = bytes.repeat(
						[]byte{buffer.buf[position + b.offset]},
						b.match_length - len(match_bytes),
					)
					match_bytes_written, match_write_error = bytes.buffer_write(
						&buffer,
						match_bytes,
					)
				} else {
					match_bytes := buffer.buf[match_start:match_end]
					match_bytes_written, match_write_error = bytes.buffer_write(
						&buffer,
						match_bytes,
					)
				}
				if match_write_error != nil {
					fmt.printf("Error writing to buffer: %v\n", match_write_error)
					os.exit(1)
				}
				position += match_bytes_written

				bi += 1
			}
		}
		i += 1

		fmt.printf("Decompressed: '%s'\n", buffer.buf)
	}
}
