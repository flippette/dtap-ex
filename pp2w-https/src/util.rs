//! various utilities.

use core::ops::AsyncFnMut;

/// retry an `async` function up to some number of times.
///
/// this function only returns [`Err`] if the passed-in function returns [`Err`]
/// `max_tries` times.
pub async fn with_retries<T, E>(
    mut f: impl AsyncFnMut() -> Result<T, E>,
    retries: usize,
) -> Result<T, E> {
    let mut nth = 0;

    loop {
        match f().await {
            Ok(val) => break Ok(val),
            Err(err) if nth == retries - 1 => break Err(err),
            _ => nth += 1,
        }
    }
}
