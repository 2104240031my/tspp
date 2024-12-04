use crate::net::error::TsppError;
use crate::net::error::TsppErrorCode;
use crate::net::tspp::TsppCipherSuite;
use crate::net::tspp::TsppHelloPhaseState;
use crate::net::tspp::TsppSocket;
use crate::net::tspp::TsppRole;
use crate::net::tspp::TsppVersion;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::ToSocketAddrs;

const BUF_LEN: usize = 65556; // 65536 + 4 + 16

pub struct TsppProtectedTcpStream {
    tcp: TcpStream,
    tspp: TsppSocket
}

pub struct TsppProtectedTcpListener {
    tcp: TcpListener,
    tspp_version: TsppVersion,
    tspp_cipher_suite: TsppCipherSuite,
    tspp_au_privkey: Vec<u8>
}

impl TsppProtectedTcpStream {

    pub fn connect<A: ToSocketAddrs>(addr: A, tspp_version: TsppVersion, tspp_cipher_suite: TsppCipherSuite,
        tspp_au_privkey: &[u8]) -> Result<Self, TsppError> {

        let mut v: Self = Self{
            tcp: TcpStream::connect(addr).map_err(tcp_err)?,
            tspp: TsppSocket::new(
                tspp_version,
                tspp_cipher_suite,
                TsppRole::ActiveOpener,
                tspp_au_privkey
            )?
        };

        let mut buf: [u8; BUF_LEN] = [0; BUF_LEN];

        let s: usize = v.tspp.hello_phase_send(&mut buf[..]).map_err(|e| v.on_tspp_err(e))?.0;
        v.tcp.write_all(&buf[..s]).map_err(tcp_err)?;

        for _ in 0..2 {
            loop {
                let mut r: usize = v.tcp.peek(&mut buf[..]).map_err(tcp_err)?;
                r = v.tspp.hello_phase_recv(&mut buf[..r]).map_err(|e| v.on_tspp_err(e))?.0;
                if r != 0 {
                    v.tcp.read_exact(&mut buf[..r]).map_err(tcp_err)?;
                    break;
                }
            }
        }

        let s: usize = hello_phase_done(v.tspp.hello_phase_send(&mut buf[..]).map_err(|e| v.on_tspp_err(e))?)?;
        v.tcp.write_all(&buf[..s]).map_err(tcp_err)?;

        return Ok(v);

    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TsppError> {
        let mut tspp_buf: [u8; BUF_LEN] = [0; BUF_LEN];
        return loop {
            let mut r: usize = self.tcp.peek(&mut tspp_buf[..]).map_err(tcp_err)?;
            let w: usize;
            (r, w) = self.tspp.recv(&tspp_buf[..r], buf)?; // don't through on_tspp_err() for ByeFragmentRecvd error
            if r != 0 {
                self.tcp.read_exact(&mut tspp_buf[..r]).map_err(tcp_err)?;
                break Ok(w);
            }
        };
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, TsppError> {
        let mut tspp_buf: [u8; BUF_LEN] = [0; BUF_LEN];
        let (r, w): (usize, usize) = self.tspp.send(buf, &mut tspp_buf[..])?;
        self.tcp.write_all(&tspp_buf[..w]).map_err(tcp_err)?;
        return Ok(r);
    }

    pub fn shutdown(&mut self, shutdown: Shutdown) -> Result<(), TsppError> {
        let mut buf: [u8; BUF_LEN] = [0; BUF_LEN];
        let s: usize = self.tspp.send_bye(&mut buf[..]).map_err(|e| self.on_tspp_err(e))?;
        self.tcp.write_all(&buf[..s]).map_err(tcp_err)?;
        self.tcp.shutdown(shutdown).map_err(tcp_err)?;
        return Ok(());
    }

    fn on_tspp_err(&mut self, err: TsppError) -> TsppError {
        return if let Err(_) = self.tcp.shutdown(Shutdown::Both) { err } else { err };
    }

}

impl TsppProtectedTcpListener {

    pub fn bind<A: ToSocketAddrs>(addr: A, tspp_version: TsppVersion, tspp_cipher_suite: TsppCipherSuite,
        tspp_au_privkey: &[u8]) -> Result<Self, TsppError> {
        return Ok(Self{
            tcp: TcpListener::bind(addr).map_err(tcp_err)?,
            tspp_version: tspp_version,
            tspp_cipher_suite: tspp_cipher_suite,
            tspp_au_privkey: tspp_au_privkey.to_vec()
        });
    }

    pub fn accept(&self) -> Result<TsppProtectedTcpStream, TsppError> {

        let mut v: TsppProtectedTcpStream = TsppProtectedTcpStream{
            tcp: self.tcp.accept().map_err(tcp_err)?.0,
            tspp: TsppSocket::new(
                self.tspp_version,
                self.tspp_cipher_suite,
                TsppRole::PassiveOpener,
                &self.tspp_au_privkey
            )?,
        };

        let mut buf: [u8; BUF_LEN] = [0; BUF_LEN];

        loop {
            let mut r: usize = v.tcp.peek(&mut buf[..]).map_err(tcp_err)?;
            r = v.tspp.hello_phase_recv(&mut buf[..r]).map_err(|e| v.on_tspp_err(e))?.0;
            if r != 0 {
                v.tcp.read_exact(&mut buf[..r]).map_err(tcp_err)?;
                break;
            }
        }

        for _ in 0..2 {
            let s: usize = v.tspp.hello_phase_send(&mut buf[..]).map_err(|e| v.on_tspp_err(e))?.0;
            v.tcp.write_all(&buf[..s]).map_err(tcp_err)?;
        }

        loop {
            let mut r: usize = v.tcp.peek(&mut buf[..]).map_err(tcp_err)?;
            r = hello_phase_done(v.tspp.hello_phase_recv(&mut buf[..r]).map_err(|e| v.on_tspp_err(e))?)?;
            if r != 0 {
                v.tcp.read_exact(&mut buf[..r]).map_err(tcp_err)?;
                break;
            }
        }

        return Ok(v);

    }

}

fn hello_phase_done(v: (usize, TsppHelloPhaseState)) -> Result<usize, TsppError> {
    return if v.1 == TsppHelloPhaseState::Done { Ok(v.0) } else { Err(TsppError::new(TsppErrorCode::Unknown)) };
}

fn tcp_err(_: Error) -> TsppError {
    return TsppError::new(TsppErrorCode::TransportProtocolError);
}