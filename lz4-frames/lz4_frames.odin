package lz4_frames

import "core:fmt"
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
		i += 1
	}
}
