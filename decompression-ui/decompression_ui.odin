package decompression_ui

// This is an example of using the bindings with GLFW and OpenGL 3.
// For a more complete example with comments, see:
// https://github.com/ocornut/imgui/blob/docking/examples/example_glfw_opengl3/main.cpp

// import "core:fmt"
import "core:dynlib"
import "core:log"
import "core:os"
import "core:time"

import imgui "dependencies:imgui"
import "dependencies:imgui/imgui_impl_glfw"
import "dependencies:imgui/imgui_impl_opengl3"

import gl "vendor:OpenGL"
import "vendor:glfw"

Draw_Proc :: #type proc(
	ctx: ^imgui.Context,
	mem_alloc: imgui.MemAllocFunc,
	mem_free: imgui.MemFreeFunc,
	user_data: rawptr,
)

load_draw_procedure :: proc(
	draw_lib: ^dynlib.Library,
	draw_proc: Draw_Proc,
	last_version: ^time.Time,
) -> Draw_Proc {
	file_info, errno := os.stat("bin/ui.so")
	if errno != os.ERROR_NONE {
		log.errorf("Failed to stat ui.so: %v", errno)

		return draw_proc
	}

	if file_info.size == 0 {
		log.errorf("ui.so is empty")

		return draw_proc
	}

	diff := time.diff(last_version^, file_info.modification_time)
	if draw_proc != nil && diff == 0 {
		return draw_proc
	}

	if draw_lib^ != nil {
		log.debugf("Unloading 'ui.so'")
		unloaded := dynlib.unload_library(draw_lib^)
		if !unloaded {
			error := os.dlerror()
			log.errorf("Failed to unload 'ui.so': %s", error)

			return draw_proc
		}
	}

	library, loaded := dynlib.load_library("bin/ui.so")
	if !loaded {
		error := os.dlerror()
		log.errorf("Failed to load 'ui.so': %s", error)

		return draw_proc
	}

	draw_address, found := dynlib.symbol_address(library, "draw")
	if !found {
		log.errorf("Failed to find 'draw' symbol in 'ui.so'")

		return draw_proc
	}

	log.debugf("Loaded 'ui.so':draw(): %p", draw_address)

	draw_lib^ = library
	last_version^ = file_info.modification_time

	return cast(Draw_Proc)draw_address
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

	imgui_context := imgui.GetCurrentContext()
	mem_alloc: imgui.MemAllocFunc
	mem_free: imgui.MemFreeFunc
	user_data: rawptr
	imgui.GetAllocatorFunctions(&mem_alloc, &mem_free, &user_data)
	draw: Draw_Proc
	draw_library: dynlib.Library
	last_draw_version: time.Time

	for !glfw.WindowShouldClose(window) {
		draw = load_draw_procedure(&draw_library, draw, &last_draw_version)
		glfw.PollEvents()

		imgui_impl_opengl3.NewFrame()
		imgui_impl_glfw.NewFrame()
		imgui.NewFrame()

		draw(imgui_context, mem_alloc, mem_free, user_data)

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
