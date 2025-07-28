use core::arch::asm;
use log::info;
use test::ShouldPanic;

use crate::{
    cpu::percpu::current_ghcb,
    locking::{LockGuard, SpinLock},
    platform::SVSM_PLATFORM,
    serial::SerialPort,
    sev::ghcb::GHCBIOSize,
    testutils::has_qemu_testdev,
};

#[macro_export]
macro_rules! assert_eq_warn {
    ($left:expr, $right:expr) => {
        {
            let left = $left;
            let right = $right;
            if left != right {
                log::warn!(
                    "Assertion warning failed at {}:{}:{}:\nassertion `left == right` failed\n left: {left:?}\n right: {right:?}",
                    file!(),
                    line!(),
                    column!(),
                );
            }
        }
    };
}
pub use assert_eq_warn;

static SERIAL_PORT: SpinLock<Option<SerialPort<'_>>> = SpinLock::new(None);
static TEST_SKIPPED: SpinLock<Option<&'static str>> = SpinLock::new(None);

/// Tell the runner to skip the current test.
///
/// The test function should return immediately after calling this function.
/// For a convenient way to do this, see the `skip_if!` macro.
pub fn skip(message: &'static str) {
    *TEST_SKIPPED.lock() = Some(message);
}

/// Skips the current test if the given condition is true.
///
/// This is a convenience macro that calls `testing::skip()` and returns
/// from the test function.
#[macro_export]
macro_rules! skip_if {
    ($cond:expr, $msg:expr) => {
        if $cond {
            $crate::testing::skip($msg);
            return;
        }
    };
}
pub use skip_if;

/// Byte used to tell the host the request we need for the test.
/// These values must be aligned with `test_io()` in scripts/test-in-svsm.sh
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum IORequest {
    NOP = 0x00,
    /// get SEV-SNP pre-calculated launch measurement (48 bytes) from the host
    GetLaunchMeasurement = 0x01,
    /// Virtio-blk tests: Get Sha256 hash of the svsm state disk image
    GetStateImageSha256 = 0x02,
}

/// Return the serial port to communicate with the host for a given request
/// used in a test. The request (first byte) is sent by this function, so the
/// caller can start using the serial port according to the request implemented
/// in `test_io()` in scripts/test-in-svsm.sh
pub fn svsm_test_io() -> LockGuard<'static, Option<SerialPort<'static>>> {
    let mut sp = SERIAL_PORT.lock();
    if sp.is_none() {
        let io_port = SVSM_PLATFORM.get_io_port();
        let serial_port = SerialPort::new(io_port, 0x2e8 /*COM4*/);
        *sp = Some(serial_port);
        serial_port.init();
    }

    sp
}

pub fn svsm_test_runner(test_cases: &[&test::TestDescAndFn]) {
    let total_tests = test_cases.len();
    info!("running {} tests", total_tests);
    let mut passed = 0;
    let mut ignored = 0;
    let mut skipped = 0;

    for mut test_case in test_cases.iter().copied().copied() {
        if test_case.desc.should_panic == ShouldPanic::Yes {
            test_case.desc.ignore = true;
            test_case
                .desc
                .ignore_message
                .get_or_insert("#[should_panic] not supported");
        }

        if test_case.desc.ignore {
            if let Some(message) = test_case.desc.ignore_message {
                info!("test {} ... ignored, {message}", test_case.desc.name.0);
            } else {
                info!("test {} ... ignored", test_case.desc.name.0);
            }
            ignored += 1;
            continue;
        }

        *TEST_SKIPPED.lock() = None;

        (test_case.testfn.0)();

        if let Some(message) = TEST_SKIPPED.lock().take() {
            info!("test {} ... skipped, {message}", test_case.desc.name.0);
            skipped += 1;
        } else {
            info!("test {} ... ok", test_case.desc.name.0);
            passed += 1;
        }
    }

    info!(
        "test result: {} passed; {} ignored; {} skipped",
        passed, ignored, skipped
    );

    exit();
}

fn exit() -> ! {
    if has_qemu_testdev() {
        const QEMU_EXIT_PORT: u16 = 0xf4;
        current_ghcb()
            .ioio_out(QEMU_EXIT_PORT, GHCBIOSize::Size32, 0)
            .unwrap();
    }
    // SAFETY: HLT instruction does not affect memory.
    unsafe {
        asm!("hlt");
    }
    unreachable!();
}
