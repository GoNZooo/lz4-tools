package ui

import "core:log"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:strings"

import "dependencies:imgui"

import "../../lz4"

File_Picker :: struct {
	root:  string,
	state: File_Picker_State,
}

File_Picker_State :: union {
	Hidden,
	Shown,
}

Hidden :: struct {}

Shown :: struct {
	files: [dynamic]File_Info,
}

File_Info :: union {
	Directory,
	File,
}

File :: struct {
	path: string,
}

Directory :: struct {
	path: string,
}

Write :: struct {
	literals:      []byte,
	literals_data: []byte,
	match:         []byte,
	match_data:    []byte,
}

Draw_Proc :: #type proc(
	ctx: ^imgui.Context,
	mem_alloc: imgui.MemAllocFunc,
	mem_free: imgui.MemFreeFunc,
	user_data: rawptr,
	state: ^State,
)

State :: struct {
	filename_buffer:      []byte,
	frame_descriptor:     lz4.Frame_Descriptor,
	remaining_data:       []byte,
	current_frame_block:  lz4.Frame_Block,
	block:                lz4.Data_Block,
	writes:               [dynamic]Write,
	output:               []byte,
	remaining_block_data: []byte,
	current_directory:    string,
	file_picker_open:     bool,
	file_picker:          File_Picker,
	copy_index:           int,
}

@(export)
draw :: proc(
	ctx: ^imgui.Context,
	mem_alloc: imgui.MemAllocFunc,
	mem_free: imgui.MemFreeFunc,
	user_data: rawptr,
	state: ^State,
) {
	@(static)
	i := 0
	i += 1

	imgui.SetCurrentContext(ctx)
	imgui.SetAllocatorFunctions(mem_alloc, mem_free, user_data)

	viewport := imgui.GetMainViewport()
	imgui.SetNextWindowPos({0, 0}, .Appearing)
	imgui.SetNextWindowSize(viewport.Size, .Appearing)

	if imgui.Begin("Decompression", nil, {.NoResize, .NoCollapse, .NoMove, .MenuBar}) {
		imgui.SetWindowFontScale(2.0)

		if imgui.BeginMenuBar() {
			if imgui.BeginMenu("File") {
				if imgui.MenuItem("Open") {
					file_picker_initialize(&state.file_picker, state.current_directory)
					state.file_picker_open = true
				}
				imgui.EndMenu()
			}

			imgui.EndMenuBar()
		}

		if imgui.InputText(
			   "Filename",
			   transmute(cstring)&state.filename_buffer[0],
			   len(state.filename_buffer),
			   {.EnterReturnsTrue},
		   ) {
			if imgui.IsKeyPressed(.Enter) {
				state.frame_descriptor, state.remaining_data = load_file(
					string(state.filename_buffer),
				)
			}
		}
		imgui.SameLine()
		available := imgui.GetContentRegionAvail()
		cursor_x := imgui.GetCursorPosX()
		imgui.SetCursorPosX(cursor_x + available.x / 2)
		if imgui.Button("Load") {
			state.frame_descriptor, state.remaining_data = load_file(string(state.filename_buffer))
		}
		imgui.Text("Unprocessed bytes in file: %d", len(state.remaining_data))

		if imgui.Button("Load more") {
			if state.current_frame_block.size == 0 {
				frame_block_read_error: lz4.Frame_Block_Read_Error
				state.current_frame_block, _, frame_block_read_error = lz4.frame_block_read(
					state.remaining_data,
					state.frame_descriptor.has_block_checksum,
				)
				state.output = make(
					[]byte,
					state.frame_descriptor.content_size == 0 \
					? 64 * mem.Kilobyte \
					: state.frame_descriptor.content_size,
				)
				if frame_block_read_error != nil {
					log.errorf("Error reading frame block: %v", frame_block_read_error)
				}
				state.remaining_block_data = state.current_frame_block.data
			}

			data_block_read_error: lz4.Data_Block_Read_Error
			state.block, state.remaining_block_data, data_block_read_error = lz4.data_block_read(
				state.remaining_block_data,
			)

			// extract to output
			copy(state.output[state.copy_index:], state.block.literals)
			state.copy_index += len(state.block.literals)

			copy_bytes: []byte
			if state.block.offset < state.block.match_length {
				copy_start := state.copy_index - state.block.offset
				copy_bytes = state.output[copy_start:state.copy_index]

				copy(state.output[state.copy_index:], copy_bytes)
				state.copy_index += len(copy_bytes)

				remaining := state.block.match_length - len(copy_bytes)
				for i in 0 ..< remaining {
					state.output[state.copy_index + i] = copy_bytes[i % len(copy_bytes)]
				}
				state.copy_index += remaining
			} else {
				copy_start := state.copy_index - state.block.offset
				copy_end := copy_start + state.block.match_length
				copy_bytes = state.output[copy_start:copy_end]
				copy(state.output[state.copy_index:], copy_bytes)
				state.copy_index += state.block.match_length
			}

			append(&state.writes, Write{literals = state.block.literals, match = copy_bytes})
		}

		if state.frame_descriptor.version == 1 {
			draw_panel(
				draw_proc = draw_frame_descriptor,
				data = &state.frame_descriptor,
				padding = 20,
				color = {128, 128, 128, 255},
				rounding = 10,
				thickness = 1,
			)
			imgui.SameLine()
			draw_panel(
				draw_proc = draw_frame_descriptor,
				data = &state.frame_descriptor,
				padding = 20,
				color = {128, 128, 128, 255},
				rounding = 10,
				thickness = 1,
			)
		}

		for write in state.writes {
			for line in strings.split(string(write.literals), "\n") {
				imgui.Text(strings.clone_to_cstring(line))
			}
			imgui.SameLineEx(0, 0)
			for line in strings.split(string(write.match), "\n") {
				imgui.TextColored({1, 0, 1, 1}, strings.clone_to_cstring(line))
			}
			imgui.SameLineEx(0, 0)
		}

		imgui.End()
	}

	if state.file_picker_open {
		imgui.OpenPopup("OpenFile", {})
	}

	if imgui.BeginPopupModal("OpenFile", &state.file_picker_open, {}) {
		defer imgui.EndPopup()

		switch s in &state.file_picker.state {
		case Hidden:
		// nothing
		case Shown:
			for file in s.files {
				path: string
				switch f in file {
				case File:
					imgui.PushStyleColorImVec4(imgui.Col.Text, {1, 0, 0, 1})
					path = f.path
				case Directory:
					imgui.PushStyleColorImVec4(imgui.Col.Text, {0, 1, 0, 1})
					path = f.path
				}
				file_cs, allocation_error := strings.clone_to_cstring(path)
				if allocation_error != nil {
					log.errorf("error allocating filename cstring: %v", allocation_error)
				}
				if imgui.Selectable(file_cs) {
					_, is_directory := file.(Directory)
					if is_directory {
						file_picker_initialize(&state.file_picker, path)
					} else {
						copy(state.filename_buffer, path)
						state.frame_descriptor, state.remaining_data = load_file(path)

						clear(&state.writes)
						state.copy_index = 0
						state.current_frame_block = lz4.Frame_Block{}
						state.remaining_block_data = nil

						state.file_picker_open = false
					}
				}
				imgui.PopStyleColor()
			}
		}
	}
}

load_file :: proc(filename: string) -> (fd: lz4.Frame_Descriptor, remaining_data: []byte) {
	log.debugf("filename: '%s'", filename)
	if !os.exists(filename) {
		log.errorf("File '%s%' does not exist", filename)

		return lz4.Frame_Descriptor{}, nil
	}

	file_data, ok := os.read_entire_file_from_filename(filename)
	if !ok {
		log.errorf("error reading file")
	}

	frame_descriptor, rest, fd_read_error := lz4.frame_descriptor_read(file_data)
	if fd_read_error != nil {
		log.errorf("Error reading frame descriptor: %v", fd_read_error)
	}

	return frame_descriptor, rest
}

draw_panel :: proc(
	draw_proc: proc(data: rawptr),
	data: rawptr,
	padding: f32,
	color: [4]byte,
	rounding: f32,
	thickness: f32,
) {
	imgui.BeginGroup()

	imgui.Dummy({0, padding})
	imgui.Dummy({padding, 0})
	imgui.SameLineEx(0, 0)

	imgui.BeginGroup()

	draw_proc(data)

	imgui.EndGroup()
	draw_list := imgui.GetWindowDrawList()
	min := imgui.GetItemRectMin()
	max := imgui.GetItemRectMax()
	imgui.DrawList_AddRectEx(
		draw_list,
		p_min = min - padding,
		p_max = max + padding,
		col = transmute(u32)color,
		rounding = 10,
		thickness = 1,
		flags = {},
	)
	imgui.Dummy({0, padding})
	imgui.EndGroup()
	imgui.SameLineEx(0, 0)
	imgui.Dummy({padding, 0})
}

draw_frame_descriptor :: proc(data: rawptr) {
	frame_descriptor := transmute(^lz4.Frame_Descriptor)data

	imgui.Text("Version: %d", frame_descriptor.version)
	imgui.Checkbox("Block Independence", &frame_descriptor.block_independence)
	imgui.Checkbox("Block Checksum", &frame_descriptor.has_block_checksum)
	imgui.Checkbox("Content Checksum", &frame_descriptor.has_content_checksum)
	imgui.Text("Calculated Checksum: %x", frame_descriptor.calculated_checksum)
	imgui.Text("Header Checksum: %x", frame_descriptor.header_checksum)
	imgui.Text("Block Max Size: %d", frame_descriptor.block_max_size)
	imgui.Text("Content Size: %d", frame_descriptor.content_size)
	imgui.Text("Dictionary ID: %d", frame_descriptor.dictionary_id)
}

@(private = "file")
_file_picker_walk_proc :: proc(
	info: os.File_Info,
	in_err: os.Errno,
	user_data: rawptr,
) -> (
	err: os.Errno,
	skip_dir: bool,
) {
	data := transmute(^File_Picker)user_data
	switch s in &data.state {
	case Hidden:
		files := make([dynamic]File_Info, 0, 0)

		data.state = Shown {
			files = files,
		}
	case Shown:
		file_info: File_Info
		if info.is_dir {
			file_info = Directory {
				path = info.fullpath,
			}
		} else {
			file_info = File {
				path = info.fullpath,
			}
		}

		append(&s.files, file_info)
	}

	return os.ERROR_NONE, info.is_dir && info.fullpath != data.root
}

file_picker_initialize :: proc(fp: ^File_Picker, root: string) {
	fp.state = Hidden{}
	fp.root = root
	filepath.walk(root, walk_proc = _file_picker_walk_proc, user_data = fp)
}
