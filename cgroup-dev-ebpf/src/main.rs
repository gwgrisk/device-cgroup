#![no_std]
#![no_main]

use aya_bpf::{helpers::bpf_get_current_cgroup_id, macros::cgroup_device, programs::DeviceContext};
use aya_log_ebpf::info;

#[cgroup_device(name = "cgroup_dev")]
pub fn cgroup_dev(ctx: DeviceContext) -> i32 {
    match try_cgroup_dev(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// Only allow cgroup to talk to /dev/{null,zero,urandom}
fn try_cgroup_dev(ctx: DeviceContext) -> Result<i32, i32> {
    let access = unsafe { *ctx.device };

    info!(
        &ctx,
        "device ({}:{}) accessed from cgroup: {}",
        access.major,
        access.minor,
        unsafe { bpf_get_current_cgroup_id() }
    );

    // if access.major != 10 {
    //     return Ok(0);
    // }

    /* Devices 1:3 is /dev/null, 1:5 is /dev/zero, 1:9 /dev/urandom */
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
