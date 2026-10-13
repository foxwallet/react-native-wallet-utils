// Copyright 2021-2021 FoxWallet.

extern "C" {
    fn __android_log_print(log: i32, app: *const u8, fmt: *const u8, msg: *const u8);
}

pub fn a_log(mut msg: String) {
    msg.push('\0');
    unsafe {
        __android_log_print(
            4, // ANDROID_LOG_INFO
            "native-activity\0".as_ptr(),
            "%s\0".as_ptr(),
            msg.as_ptr(),
        );
    }
}

#[macro_export]
macro_rules! alog {
    ($($arg:tt)*) => {{
        #[cfg(target_os = "android")]
        {
            $crate::a_log(format!($($arg)*));
        }

        #[cfg(not(target_os = "android"))]
        {
            println!("{}", format!($($arg)*));
        }
    }};
}
