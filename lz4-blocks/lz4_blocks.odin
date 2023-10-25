package lz4_blocks

import "core:bytes"
import "core:fmt"
import "core:os"

import "../lz4"

main :: proc() {
	arguments := os.args[1:]

	if len(arguments) == 0 {
		fmt.printf("Usage: %s <file>", os.args[0])
		os.exit(1)
	}

	file_data, ok := os.read_entire_file_from_filename(arguments[0])
	if !ok {
		fmt.println("Could not read file")
		os.exit(1)
	}

	for frame, rest, frame_error := lz4.frame_next(file_data);
	    frame_error == nil;
	    frame, rest, frame_error = lz4.frame_next(rest) {
		buffer: bytes.Buffer
		bytes.buffer_init_allocator(&buffer, 0, frame.descriptor.block_max_size)

		decompressed, decompression_error := lz4.decompress_frame(frame)
		if decompression_error != nil {
			fmt.printf("Error decompressing frame: %v\n", decompression_error)
			os.exit(1)
		}

		switch d in decompressed {
		case []byte:
			fmt.printf("Decompressed:\n'''\n%s\n'''\n", d)
		case [][]byte:
			concatenated := bytes.concatenate(d)
			fmt.printf("Decompressed:\n'''\n%s\n'''\n", concatenated)
		}
	}
}
