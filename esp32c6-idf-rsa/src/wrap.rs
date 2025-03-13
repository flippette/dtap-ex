//! Safe-r wrapper around FFI interfaces.

use sealed::sealed;
use std::{
    ffi,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

/// Safe-r wrapper around FFI interfaces.
pub struct Wrapped<T> {
    data: T,
    free: unsafe extern "C" fn(*mut T),
}

/// Convenient trait to turn a C-style error code into a [`Result`].
#[sealed]
pub trait ErrorCode<E>: Sized + Eq {
    fn into_result(
        self,
        ok: Self,
        err: impl FnOnce(Self) -> E,
    ) -> Result<(), E>;
}

impl<T> Wrapped<T> {
    /// Create a [`Wrapper`] with the provided `init` and `free` functions.
    ///
    /// # Safety
    ///
    /// - Both `init` and `free` must be infallible functions.
    /// - `init` must be okay to call on an _uninit_ pointer to T.
    /// - `free` must be okay to call on an _init_ pointer to T.
    pub unsafe fn new(
        init: unsafe extern "C" fn(*mut T),
        free: unsafe extern "C" fn(*mut T),
    ) -> Self {
        let mut data = MaybeUninit::uninit();

        // SAFETY: the user guarantees this function is okay to call with a
        //         valid ptr to T.
        unsafe {
            init(data.as_mut_ptr());
        }

        Self {
            data: unsafe { data.assume_init() },
            free,
        }
    }
}

impl<T> Deref for Wrapped<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.data
    }
}

impl<T> DerefMut for Wrapped<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T> Drop for Wrapped<T> {
    fn drop(&mut self) {
        // SAFETY: it is unsafe to create a Wrapped, so the user promises that
        //         it is safe to call free with a valid T.
        unsafe { (self.free)(&raw mut self.data) }
    }
}

#[sealed]
impl<E> ErrorCode<E> for ffi::c_int {
    fn into_result(
        self,
        ok: Self,
        err: impl FnOnce(Self) -> E,
    ) -> Result<(), E> {
        if self == ok { Ok(()) } else { Err(err(self)) }
    }
}
