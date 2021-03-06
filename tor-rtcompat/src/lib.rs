//! Compatibility between different async runtimes for Arti
//!
//! # Overview
//!
//! Rust's support for asynchronous programming is powerful, but still
//! a bit immature: there are multiple powerful runtimes you can use,
//! but they do not expose a consistent set of interfaces.
//!
//! The [`futures`] API abstracts much of the differences among these
//! runtime libraries, but there are still areas where no standard API
//! yet exists, including:
//!  - Network programming.
//!  - Time and delays.
//!  - Launching new tasks
//!  - Blocking until a task is finished.
//!
//! Additionally, the `AsyncRead` and `AsyncWrite` traits provide by
//! [`futures`] are not the same as those provided by `tokio`, and
//! require compatibility wrappers to use. (We re-export those of
//! [`tokio_util`].
//!
//! To solve these problems, the `tor-rtcompat` crate provides a set
//! of traits that represent a runtime's ability to perform these
//! tasks, along with implementations for these traits for the `tokio`
//! and `async-std` runtimes.  In the future we hope to add support
//! for other runtimes as needed.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! As such, it does not currently include (or
//! plan to include) any functionality beyond what Arti needs to
//! implement Tor.
//!
//! We hope that in the future this crate can be replaced (or mostly
//! replaced) with standardized and general-purpose versions of the
//! traits it provides.
//!
//! # Using `tor-rtcompat`
//!
//! The `tor-rtcompat` crate provide several traits that that
//! encapsulate different runtime capabilities.
//!
//!  * A runtime is a [`SpawnBlocking`] if it can block on a future.
//!  * A runtime if a [`SleepProvider`] if it can make timer futures that
//!    become Ready after a given interval of time.
//!  * A runtime is a [`TcpProvider`] if it can make and receive TCP
//!    connections
//!  * A runtime is a [`TlsProvider`] if it can make TLS connections.
//!
//! For convenience, the [`Runtime`] trait derives from all the traits
//! above, plus [`futures::task::Spawn`] and [`Send`].
//!
//! You can get a [`Runtime`] in several ways:
//!
//!   * If you already have an asynchronous backend (for example, one
//!     that you built with tokio, or by running with
//!     `#[tokio::main]`, you can wrap it as a [`Runtime`] with
//!     [`current_user_runtime()`].
//!
//!   * If you want to construct a default runtime that you won't be
//!     using for anything besides Arti, you can use [`create_runtime()`].
//!
//!   * If you want to explicitly construct a runtime with a specific
//!     backend, you can do so with `create_async_std_runtime` or
//!     [`create_tokio_runtime`].  Or if you have already constructed a
//!     tokio runtime that you want to use, you can wrap it as a
//!     [`Runtime`] explicitly with [`TokioRuntimeHandle`].
//!
//! # Cargo features
//!
//! `tokio` -- (Default) Build with Tokio support.
//!
//! `async-std` -- Build with async_std support.
//!
//! # Design FAQ
//!
//! ## Why support `async_std`?
//!
//! Although Tokio currently a more popular and widely supported
//! asynchronous runtime than `async_std` is, we believe that it's
//! critical to build Arti against multiple runtimes.
//!
//! By supporting multiple runtimes, we avoid making tokio-specific
//! assumptions in our code, which we hope will make it easier to port
//! to other environments (like WASM) in the future.
//!
//! ## Why a `Runtime` trait, and not a set of functions?
//!
//! We could simplify this code significantly by removing most of the
//! traits it exposes, and instead just exposing a single
//! implementation.  For example, instead of exposing a
//! [`SpawnBlocking`] trait to represent blocking until a task is
//! done, we could just provide a single global `block_on` function.
//!
//! That simplification would come at a cost, however.  First of all,
//! it would make it harder for us to use Rust's "feature" system
//! correctly.  Current features are supposed to be _additive only_,
//! but if had a single global runtime, then support for diffferent
//! backends would be _mutually exclusive_.  (That is, you couldn't
//! have both the tokio and async-std features building at the same
//! time.)
//!
//! Secondly, much of our testing in the rest of Arti relies on the
//! ability to replace [`Runtime`]s.  By treating a runtime as an
//! object, we can override a runtime's view of time, or of the
//! network, in order to test asynchronous code effectively.
//! (See the [`tor-rtmock`] crate for examples.)

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::unseparated_literal_suffix)]

use std::io::{Error as IoError, ErrorKind, Result as IoResult};

pub(crate) mod impls;
pub mod task;

mod timer;
mod traits;

#[cfg(test)]
mod test;

#[cfg(not(any(feature = "async-std", feature = "tokio")))]
compile_error!("Sorry: At least one of the tor-rtcompat/async-std and tor-rtcompat/tokio features must be specified.");

pub use traits::{
    CertifiedConn, Runtime, SleepProvider, SpawnBlocking, TcpListener, TcpProvider, TlsProvider,
};

pub use timer::{SleepProviderExt, Timeout, TimeoutError};

/// Traits used to describe TLS connections and objects that can
/// create them.
pub mod tls {
    pub use crate::traits::{CertifiedConn, TlsConnector};
}

#[cfg(feature = "async-std")]
pub use impls::async_std::create_runtime as create_async_std_runtime;
#[cfg(feature = "tokio")]
pub use impls::tokio::create_runtime as create_tokio_runtime;
#[cfg(feature = "tokio")]
pub use impls::tokio::TokioRuntimeHandle;

/// The default runtime type that we return from [`create_runtime()`] or
/// [`test_with_runtime()`]
#[cfg(feature = "tokio")]
type DefaultRuntime = async_executors::TokioTp;

/// The default runtime type that we return from [`create_runtime()`] or
/// [`test_with_runtime()`]
#[cfg(all(feature = "async-std", not(feature = "tokio")))]
type DefaultRuntime = async_executors::AsyncStd;

/// Try to return an instance of the currently running [`Runtime`].
///
/// # Limitations
///
/// If the `tor-rtcompat` crate was compiled with `tokio` support,
/// this function will never return an `async_std` runtime.
///
/// # Usage note
///
/// We should never call this from inside other Arti crates, or from
/// library crates that want to supporet multiple runtimes!  This
/// function is for Arti _users_ who want to wrap some existing Tokio
/// or Async_std runtime as a [`Runtime`].  It is not for library
/// crates that want to work with multiple runtimes.
///
/// Once you have a runtime returned by this function, you should
/// just create more handles to it via [`Clone`].
pub fn current_user_runtime() -> IoResult<impl Runtime> {
    #[cfg(feature = "tokio")]
    {
        let handle = tokio_crate::runtime::Handle::try_current()
            .map_err(|e| IoError::new(ErrorKind::Other, e))?;
        Ok(TokioRuntimeHandle::new(handle))
    }
    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    {
        // In async_std, the runtime is a global singleton.
        Ok(create_async_std_runtime())
    }
    #[cfg(not(any(feature = "async-std", feature = "tokio")))]
    {
        // This isn't reachable, since the crate won't actually compile
        // unless some runtime is enabled.
        panic!("tor-rtcompat was built with no supported runtimes.")
    }
}

/// Return a new instance of the default [`Runtime`].
///
/// Generally you should call this function only once, and then use
/// [`Clone::clone()`] to create additional references to that
/// runtime.
///
/// Tokio users may want to avoid this function and instead make a
/// runtime using [`current_user_runtime()`] or
/// [`TokioRuntimeHandle::new()`]: this function always _builds_ a
/// runtime, and if you already have a runtime, that isn't what you
/// want with Tokio.
///
/// If you need more fine-grained control over a runtime, you can
/// create it using an appropriate builder type or function.
pub fn create_runtime() -> IoResult<impl Runtime> {
    create_default_runtime()
}

/// Helper: create and return a default runtime type.
///
/// This function is separate from `create_runtime()` because of its
/// separate return type: we hide the actual type with
/// `create_runtime()` to avoid writing code that relies on any
/// particular runtimes.
#[allow(clippy::unnecessary_wraps)]
fn create_default_runtime() -> IoResult<DefaultRuntime> {
    #[cfg(feature = "tokio")]
    {
        create_tokio_runtime()
    }
    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    {
        Ok(create_async_std_runtime())
    }
    #[cfg(not(any(feature = "async-std", feature = "tokio")))]
    {
        // This isn't reachable, since the crate won't actually compile
        // unless some runtime is enabled.
        panic!("tor-rtcompat was built with no supported runtimes.")
    }
}

/// Run a given asynchronous function, which takes a runtime as an argument,
/// using the default runtime.
///
/// This is intended for writing test cases that need a runtime.
///
/// # Example
///
/// ```
/// # use std::time::Duration;
/// use tor_rtcompat::SleepProviderExt;
///
/// // Run a simple test using a timeout.
/// tor_rtcompat::test_with_runtime(|runtime| async move {
///    async fn one_plus_two() -> u32 { 1 + 2 }
///    let future = runtime.timeout(Duration::from_secs(5), one_plus_two());
///    assert_eq!(future.await, Ok(3));
/// });
/// ```
#[allow(clippy::clone_on_copy)]
pub fn test_with_runtime<P, F, O>(func: P) -> O
where
    P: FnOnce(DefaultRuntime) -> F,
    F: futures::Future<Output = O>,
{
    let runtime = create_default_runtime().unwrap();
    runtime.block_on(func(runtime.clone()))
}
