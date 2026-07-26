//! SnapPipe transport extensions.
//!
//! Houses the [`tunnel`] module which provides TCP-over-QUIC tunneling on
//! top of the existing relay QUIC stack. The tunnel feature reuses the
//! ticket handshake (`crate::session`) and trust/rate-limit machinery
//! (`crate::trust`, `crate::rate_limit`) without duplicating them.

pub mod tunnel;
