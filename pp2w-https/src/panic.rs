//! common custom [`panic!`] macro.

#[macro_export]
macro_rules! panic {
    ($rep:expr) => {
        ::defmt::error!("{}", $rep.error);
        ::defmt::error!("stacktrace:");
        $rep.trace.iter().for_each(|loc| error!("  {}", loc));
        if $rep.more {
            ::defmt::error!("  (rest of stacktrace omitted)");
        }

        // basically `panic!` but without dirtying the logs
        ::cortex_m::asm::udf();
    };
}
