/// List of available hostcalls.
extern "C" {
    // General purpose hostcalls
    pub fn register_future(closure: *mut FnMut() -> i32) -> i32;
    pub fn register_on_message(phase: i32, closure: *mut FnMut(i32) -> i32) -> i32;
    pub fn debug(ptr: i32, len: i32);

    // Provided I/O operations
    pub fn timer_poll(timer: i32) -> i32;
    pub fn timer_create(ms: i32) -> i32;
    pub fn forward_create(
        request: i32,
        upstream_ptr: *const u8,
        upstream_len: u16,
        msg_ptr: *const u8,
        msg_len: u16,
    ) -> i32;
    pub fn forward_poll(task_id: i32, msg_ptr: *mut u8, msg_max_len: u16) -> i32;

    // Hostcalls related to request
    pub fn request_query_name(request: i32, ptr: *mut u8, max_len: i32) -> i32;
    pub fn request_query_type(request: i32) -> u16;
    pub fn request_local_addr(request: i32, ptr: *mut u8, max_len: i32) -> i32;
    pub fn request_set_response(request: i32, ptr: *const u8, len: i32) -> i32;
}

// Privileged hostcalls
pub mod privileged {
    extern "C" {
        pub fn local_socket_open(path: *const u8, path_len: i32) -> i32;
        pub fn local_socket_send(fd: i32, buf: *const u8, len: i32) -> i32;
        pub fn local_socket_recv(fd: i32, buf: *mut u8, max_len: i32) -> i32;
        pub fn local_socket_close(fd: i32) -> i32;
    }
}
