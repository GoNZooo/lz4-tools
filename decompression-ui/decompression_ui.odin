package decompression_ui

// This is an example of using the bindings with GLFW and OpenGL 3.
// For a more complete example with comments, see:
// https://github.com/ocornut/imgui/blob/docking/examples/example_glfw_opengl3/main.cpp

// import "core:fmt"
import "core:log"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:strings"

import imgui "dependencies:imgui"
import "dependencies:imgui/imgui_impl_glfw"
import "dependencies:imgui/imgui_impl_opengl3"

import gl "vendor:OpenGL"
import "vendor:glfw"

import "../lz4"

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

Write :: struct {
	literals:      []byte,
	literals_data: []byte,
	match:         []byte,
	match_data:    []byte,
}

main :: proc() {
	context.logger = log.create_console_logger()

	assert(bool(glfw.Init()))
	defer glfw.Terminate()

	glfw.WindowHint(glfw.CONTEXT_VERSION_MAJOR, 3)
	glfw.WindowHint(glfw.CONTEXT_VERSION_MINOR, 2)
	glfw.WindowHint(glfw.OPENGL_PROFILE, glfw.OPENGL_CORE_PROFILE)
	glfw.WindowHint(glfw.OPENGL_FORWARD_COMPAT, 1) // i32(true)

	window := glfw.CreateWindow(1920, 1080, "LZ4 Decompression UI", nil, nil)
	assert(window != nil)
	defer glfw.DestroyWindow(window)

	glfw.MakeContextCurrent(window)
	glfw.SwapInterval(1) // vsync

	gl.load_up_to(3, 2, proc(p: rawptr, name: cstring) {
		(cast(^rawptr)p)^ = glfw.GetProcAddress(name)
	})

	imgui.CHECKVERSION()
	imgui.CreateContext(nil)
	defer imgui.DestroyContext(nil)
	io := imgui.GetIO()
	io.ConfigFlags += {.NavEnableKeyboard, .NavEnableGamepad}
	when imgui.IMGUI_BRANCH == "docking" {
		io.ConfigFlags += {.DockingEnable}
		// io.ConfigFlags += {.ViewportsEnable}

		style := imgui.GetStyle()
		style.WindowRounding = 0
		style.Colors[imgui.Col.WindowBg].w = 1
	}

	imgui.StyleColorsDark(nil)

	imgui_impl_glfw.InitForOpenGL(window, true)
	defer imgui_impl_glfw.Shutdown()
	imgui_impl_opengl3.Init("#version 150")
	defer imgui_impl_opengl3.Shutdown()

	filename_buffer: [256]byte
	frame_descriptor: lz4.Frame_Descriptor
	current_directory := os.get_current_directory()
	file_picker: File_Picker
	remaining_data: []byte

	output: []byte

	for !glfw.WindowShouldClose(window) {
		glfw.PollEvents()

		imgui_impl_opengl3.NewFrame()
		imgui_impl_glfw.NewFrame()
		imgui.NewFrame()

		// ui code

		viewport := imgui.GetMainViewport()
		imgui.SetNextWindowPos({0, 0}, .Appearing)
		imgui.SetNextWindowSize(viewport.Size, .Appearing)

		@(static)
		file_picker_open := false
		@(static)
		writes: [dynamic]Write
		@(static)
		copy_index := 0
		@(static)
		current_frame_block: lz4.Frame_Block
		@(static)
		block: lz4.Data_Block
		@(static)
		remaining_block_data: []byte

		if imgui.Begin("Decompression", nil, {.NoResize, .NoCollapse, .NoMove, .MenuBar}) {
			imgui.SetWindowFontScale(2.0)

			if imgui.BeginMenuBar() {
				if imgui.BeginMenu("File") {
					if imgui.MenuItem("Open") {
						file_picker_initialize(&file_picker, current_directory)
						file_picker_open = true
					}
					imgui.EndMenu()
				}

				imgui.EndMenuBar()
			}

			if imgui.InputText(
				   "Filename",
				   transmute(cstring)&filename_buffer,
				   len(filename_buffer),
				   {.EnterReturnsTrue},
			   ) {
				if imgui.IsKeyPressed(.Enter) {
					frame_descriptor, remaining_data = load_file(string(filename_buffer[:]))
				}
			}
			imgui.SameLine()
			available := imgui.GetContentRegionAvail()
			cursor_x := imgui.GetCursorPosX()
			imgui.SetCursorPosX(cursor_x + available.x / 2)
			if imgui.Button("Load") {
				frame_descriptor, remaining_data = load_file(string(filename_buffer[:]))
			}
			imgui.Text("Unprocessed bytes in file: %d", len(remaining_data))

			if imgui.Button("Load more") {
				if current_frame_block.size == 0 {
					frame_block_read_error: lz4.Frame_Block_Read_Error
					current_frame_block, _, frame_block_read_error = lz4.frame_block_read(
						remaining_data,
						frame_descriptor.has_block_checksum,
					)
					output = make(
						[]byte,
						frame_descriptor.content_size == 0 \
						? 64 * mem.Kilobyte \
						: frame_descriptor.content_size,
					)
					if frame_block_read_error != nil {
						log.errorf("Error reading frame block: %v", frame_block_read_error)
					}
					remaining_block_data = current_frame_block.data
				}

				data_block_read_error: lz4.Data_Block_Read_Error
				block, remaining_block_data, data_block_read_error = lz4.data_block_read(
					remaining_block_data,
				)

				// extract to output
				copy(output[copy_index:], block.literals)
				copy_index += len(block.literals)

				copy_bytes: []byte
				if block.offset < block.match_length {
					copy_start := copy_index - block.offset
					copy_bytes = output[copy_start:copy_index]

					copy(output[copy_index:], copy_bytes)
					copy_index += len(copy_bytes)

					remaining := block.match_length - len(copy_bytes)
					for i in 0 ..< remaining {
						output[copy_index + i] = copy_bytes[i % len(copy_bytes)]
					}
					copy_index += remaining
				} else {
					copy_start := copy_index - block.offset
					copy_end := copy_start + block.match_length
					copy_bytes = output[copy_start:copy_end]
					copy(output[copy_index:], copy_bytes)
					copy_index += block.match_length
				}

				append(&writes, Write{literals = block.literals, match = copy_bytes})
			}

			if frame_descriptor.version == 1 {
				draw_panel(
					draw_proc = draw_frame_descriptor,
					data = &frame_descriptor,
					padding = 20,
					color = {128, 128, 128, 255},
					rounding = 10,
					thickness = 1,
				)
			}

			for write in writes {
				for line in strings.split(string(write.literals), "\n") {
					imgui.Text(strings.clone_to_cstring(line))
				}
				imgui.SameLineEx(0, 0)
				for line in strings.split(string(write.match), "\n") {
					imgui.TextColored({1, 0, 0, 1}, strings.clone_to_cstring(line))
				}
				imgui.SameLineEx(0, 0)
			}

			imgui.End()
		}

		if file_picker_open {
			imgui.OpenPopup("OpenFile", {})
		}

		if imgui.BeginPopupModal("OpenFile", &file_picker_open, {}) {
			defer imgui.EndPopup()

			switch s in &file_picker.state {
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
							file_picker_initialize(&file_picker, path)
						} else {
							copy(filename_buffer[:], path)
							frame_descriptor, remaining_data = load_file(path)

							clear(&writes)
							copy_index = 0
							current_frame_block = lz4.Frame_Block{}
							remaining_block_data = nil

							file_picker_open = false
						}
					}
					imgui.PopStyleColor()
				}
			}
		}

		// end of ui code

		imgui.Render()
		display_w, display_h := glfw.GetFramebufferSize(window)
		gl.Viewport(0, 0, display_w, display_h)
		gl.ClearColor(0, 0, 0, 1)
		gl.Clear(gl.COLOR_BUFFER_BIT)
		imgui_impl_opengl3.RenderDrawData(imgui.GetDrawData())

		when imgui.IMGUI_BRANCH == "docking" {
			backup_current_window := glfw.GetCurrentContext()
			imgui.UpdatePlatformWindows()
			imgui.RenderPlatformWindowsDefault()
			glfw.MakeContextCurrent(backup_current_window)
		}

		glfw.SwapBuffers(window)
	}
}