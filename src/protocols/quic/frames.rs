//! QUIC frame parsing and mutation
//!
//! This module implements parsing and mutation of QUIC frames (RFC 9000).
//! Frame-level fuzzing is critical for discovering:
//! - Protocol state machine vulnerabilities
//! - Flow control bypasses
//! - Resource exhaustion attacks
//! - Frame handling bugs

use std::io::{Cursor, Read};

/// QUIC frame types as defined in RFC 9000
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream = 0x08, // 0x08-0x0f with flags
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreamsBidi = 0x12,
    MaxStreamsUni = 0x13,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlockedBidi = 0x16,
    StreamsBlockedUni = 0x17,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionCloseQuic = 0x1c,
    ConnectionCloseApp = 0x1d,
    HandshakeDone = 0x1e,
}

impl FrameType {
    /// Parse frame type from byte
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Padding),
            0x01 => Some(Self::Ping),
            0x02 => Some(Self::Ack),
            0x03 => Some(Self::AckEcn),
            0x04 => Some(Self::ResetStream),
            0x05 => Some(Self::StopSending),
            0x06 => Some(Self::Crypto),
            0x07 => Some(Self::NewToken),
            0x08..=0x0f => Some(Self::Stream),
            0x10 => Some(Self::MaxData),
            0x11 => Some(Self::MaxStreamData),
            0x12 => Some(Self::MaxStreamsBidi),
            0x13 => Some(Self::MaxStreamsUni),
            0x14 => Some(Self::DataBlocked),
            0x15 => Some(Self::StreamDataBlocked),
            0x16 => Some(Self::StreamsBlockedBidi),
            0x17 => Some(Self::StreamsBlockedUni),
            0x18 => Some(Self::NewConnectionId),
            0x19 => Some(Self::RetireConnectionId),
            0x1a => Some(Self::PathChallenge),
            0x1b => Some(Self::PathResponse),
            0x1c => Some(Self::ConnectionCloseQuic),
            0x1d => Some(Self::ConnectionCloseApp),
            0x1e => Some(Self::HandshakeDone),
            _ => None,
        }
    }
}

/// Parsed QUIC frame
#[derive(Debug, Clone)]
pub enum QuicFrame {
    Padding { length: usize },
    Ping,
    Ack {
        largest_ack: u64,
        ack_delay: u64,
        ack_ranges: Vec<(u64, u64)>,
    },
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: u64,
        error_code: u64,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    NewToken {
        token: Vec<u8>,
    },
    Stream {
        stream_id: u64,
        offset: u64,
        fin: bool,
        data: Vec<u8>,
    },
    MaxData {
        max_data: u64,
    },
    MaxStreamData {
        stream_id: u64,
        max_stream_data: u64,
    },
    MaxStreams {
        max_streams: u64,
        bidirectional: bool,
    },
    DataBlocked {
        limit: u64,
    },
    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },
    StreamsBlocked {
        limit: u64,
        bidirectional: bool,
    },
    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        connection_id: Vec<u8>,
        stateless_reset_token: [u8; 16],
    },
    RetireConnectionId {
        sequence: u64,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>,
        reason: Vec<u8>,
    },
    HandshakeDone,
    Unknown {
        frame_type: u8,
        data: Vec<u8>,
    },
}

/// QUIC varint parser
fn parse_varint(cursor: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut buf = [0u8; 1];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| "Failed to read varint first byte")?;

    let first_byte = buf[0];
    let prefix = first_byte >> 6;

    match prefix {
        0 => Ok(first_byte as u64),
        1 => {
            let mut buf = [0u8; 1];
            cursor
                .read_exact(&mut buf)
                .map_err(|_| "Failed to read varint")?;
            Ok((((first_byte & 0x3f) as u64) << 8) | (buf[0] as u64))
        }
        2 => {
            let mut buf = [0u8; 3];
            cursor
                .read_exact(&mut buf)
                .map_err(|_| "Failed to read varint")?;
            Ok((((first_byte & 0x3f) as u64) << 24)
                | ((buf[0] as u64) << 16)
                | ((buf[1] as u64) << 8)
                | (buf[2] as u64))
        }
        3 => {
            let mut buf = [0u8; 7];
            cursor
                .read_exact(&mut buf)
                .map_err(|_| "Failed to read varint")?;
            Ok((((first_byte & 0x3f) as u64) << 56)
                | ((buf[0] as u64) << 48)
                | ((buf[1] as u64) << 40)
                | ((buf[2] as u64) << 32)
                | ((buf[3] as u64) << 24)
                | ((buf[4] as u64) << 16)
                | ((buf[5] as u64) << 8)
                | (buf[6] as u64))
        }
        _ => unreachable!(),
    }
}

/// Encode varint to bytes
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else if value < 16384 {
        vec![0x40 | ((value >> 8) as u8), (value & 0xff) as u8]
    } else if value < 1073741824 {
        vec![
            0x80 | ((value >> 24) as u8),
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]
    } else {
        vec![
            0xc0 | ((value >> 56) as u8),
            ((value >> 48) & 0xff) as u8,
            ((value >> 40) & 0xff) as u8,
            ((value >> 32) & 0xff) as u8,
            ((value >> 24) & 0xff) as u8,
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]
    }
}

impl QuicFrame {
    /// Parse a single QUIC frame from bytes
    pub fn parse(data: &[u8]) -> Result<(Self, usize), String> {
        let mut cursor = Cursor::new(data);
        let mut type_buf = [0u8; 1];
        cursor
            .read_exact(&mut type_buf)
            .map_err(|_| "Failed to read frame type")?;

        let frame_type_byte = type_buf[0];
        let frame_type = FrameType::from_u8(frame_type_byte)
            .ok_or_else(|| format!("Unknown frame type: 0x{:02x}", frame_type_byte))?;

        let start_pos = cursor.position() as usize;

        let frame = match frame_type {
            FrameType::Padding => {
                // Count consecutive padding bytes
                let mut count = 1;
                while cursor.position() < data.len() as u64 {
                    let mut buf = [0u8; 1];
                    if cursor.read_exact(&mut buf).is_err() || buf[0] != 0x00 {
                        break;
                    }
                    count += 1;
                }
                QuicFrame::Padding { length: count }
            }
            FrameType::Ping => QuicFrame::Ping,
            FrameType::Crypto => {
                let offset = parse_varint(&mut cursor)?;
                let length = parse_varint(&mut cursor)?;
                let mut data_buf = vec![0u8; length as usize];
                cursor
                    .read_exact(&mut data_buf)
                    .map_err(|_| "Failed to read CRYPTO data")?;
                QuicFrame::Crypto {
                    offset,
                    data: data_buf,
                }
            }
            FrameType::Stream => {
                let flags = frame_type_byte & 0x07;
                let has_offset = (flags & 0x04) != 0;
                let has_length = (flags & 0x02) != 0;
                let fin = (flags & 0x01) != 0;

                let stream_id = parse_varint(&mut cursor)?;
                let offset = if has_offset {
                    parse_varint(&mut cursor)?
                } else {
                    0
                };

                let data = if has_length {
                    let length = parse_varint(&mut cursor)?;
                    let mut data_buf = vec![0u8; length as usize];
                    cursor
                        .read_exact(&mut data_buf)
                        .map_err(|_| "Failed to read STREAM data")?;
                    data_buf
                } else {
                    // Read remaining data
                    let pos = cursor.position() as usize;
                    data[pos..].to_vec()
                };

                QuicFrame::Stream {
                    stream_id,
                    offset,
                    fin,
                    data,
                }
            }
            FrameType::MaxData => {
                let max_data = parse_varint(&mut cursor)?;
                QuicFrame::MaxData { max_data }
            }
            FrameType::MaxStreamData => {
                let stream_id = parse_varint(&mut cursor)?;
                let max_stream_data = parse_varint(&mut cursor)?;
                QuicFrame::MaxStreamData {
                    stream_id,
                    max_stream_data,
                }
            }
            FrameType::MaxStreamsBidi => {
                let max_streams = parse_varint(&mut cursor)?;
                QuicFrame::MaxStreams {
                    max_streams,
                    bidirectional: true,
                }
            }
            FrameType::MaxStreamsUni => {
                let max_streams = parse_varint(&mut cursor)?;
                QuicFrame::MaxStreams {
                    max_streams,
                    bidirectional: false,
                }
            }
            FrameType::ResetStream => {
                let stream_id = parse_varint(&mut cursor)?;
                let error_code = parse_varint(&mut cursor)?;
                let final_size = parse_varint(&mut cursor)?;
                QuicFrame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                }
            }
            FrameType::StopSending => {
                let stream_id = parse_varint(&mut cursor)?;
                let error_code = parse_varint(&mut cursor)?;
                QuicFrame::StopSending {
                    stream_id,
                    error_code,
                }
            }
            FrameType::PathChallenge => {
                let mut data = [0u8; 8];
                cursor
                    .read_exact(&mut data)
                    .map_err(|_| "Failed to read PATH_CHALLENGE data")?;
                QuicFrame::PathChallenge { data }
            }
            FrameType::PathResponse => {
                let mut data = [0u8; 8];
                cursor
                    .read_exact(&mut data)
                    .map_err(|_| "Failed to read PATH_RESPONSE data")?;
                QuicFrame::PathResponse { data }
            }
            FrameType::ConnectionCloseQuic | FrameType::ConnectionCloseApp => {
                let error_code = parse_varint(&mut cursor)?;
                let frame_type = if matches!(frame_type, FrameType::ConnectionCloseQuic) {
                    Some(parse_varint(&mut cursor)?)
                } else {
                    None
                };
                let reason_len = parse_varint(&mut cursor)?;
                let mut reason = vec![0u8; reason_len as usize];
                cursor
                    .read_exact(&mut reason)
                    .map_err(|_| "Failed to read CONNECTION_CLOSE reason")?;
                QuicFrame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                }
            }
            FrameType::HandshakeDone => QuicFrame::HandshakeDone,
            _ => {
                // Unknown frame - read remaining data
                let pos = cursor.position() as usize;
                QuicFrame::Unknown {
                    frame_type: frame_type_byte,
                    data: data[pos..].to_vec(),
                }
            }
        };

        let bytes_consumed = cursor.position() as usize;
        Ok((frame, bytes_consumed))
    }

    /// Serialize frame to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        match self {
            QuicFrame::Padding { length } => {
                result.extend_from_slice(&vec![0x00; *length]);
            }
            QuicFrame::Ping => {
                result.push(0x01);
            }
            QuicFrame::Crypto { offset, data } => {
                result.push(0x06);
                result.extend_from_slice(&encode_varint(*offset));
                result.extend_from_slice(&encode_varint(data.len() as u64));
                result.extend_from_slice(data);
            }
            QuicFrame::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => {
                let mut type_byte = 0x08;
                if *offset > 0 {
                    type_byte |= 0x04;
                }
                type_byte |= 0x02; // Always include length
                if *fin {
                    type_byte |= 0x01;
                }

                result.push(type_byte);
                result.extend_from_slice(&encode_varint(*stream_id));
                if *offset > 0 {
                    result.extend_from_slice(&encode_varint(*offset));
                }
                result.extend_from_slice(&encode_varint(data.len() as u64));
                result.extend_from_slice(data);
            }
            QuicFrame::MaxData { max_data } => {
                result.push(0x10);
                result.extend_from_slice(&encode_varint(*max_data));
            }
            QuicFrame::MaxStreamData {
                stream_id,
                max_stream_data,
            } => {
                result.push(0x11);
                result.extend_from_slice(&encode_varint(*stream_id));
                result.extend_from_slice(&encode_varint(*max_stream_data));
            }
            QuicFrame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                if frame_type.is_some() {
                    result.push(0x1c);
                } else {
                    result.push(0x1d);
                }
                result.extend_from_slice(&encode_varint(*error_code));
                if let Some(ft) = frame_type {
                    result.extend_from_slice(&encode_varint(*ft));
                }
                result.extend_from_slice(&encode_varint(reason.len() as u64));
                result.extend_from_slice(reason);
            }
            QuicFrame::HandshakeDone => {
                result.push(0x1e);
            }
            QuicFrame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                result.push(0x04);
                result.extend_from_slice(&encode_varint(*stream_id));
                result.extend_from_slice(&encode_varint(*error_code));
                result.extend_from_slice(&encode_varint(*final_size));
            }
            QuicFrame::PathChallenge { data } => {
                result.push(0x1a);
                result.extend_from_slice(data);
            }
            QuicFrame::PathResponse { data } => {
                result.push(0x1b);
                result.extend_from_slice(data);
            }
            _ => {
                // For other frame types, just output the type byte
                // Full implementation would handle all frame types
            }
        }

        result
    }
}

/// Frame mutator for CVE-targeted QUIC fuzzing
pub struct FrameMutator;

impl FrameMutator {
    /// Mutate a QUIC frame to trigger potential vulnerabilities
    ///
    /// Targets CVE classes:
    /// - Flow control bypasses (CWE-770)
    /// - Stream state confusion (CWE-362)
    /// - Integer overflows in frame parsing (CWE-190)
    /// - Resource exhaustion (CWE-400)
    /// - Protocol state machine violations
    pub fn mutate_frame(frame: &QuicFrame) -> Vec<QuicFrame> {
        let mut mutations = Vec::new();

        match frame {
            QuicFrame::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => {
                // CVE Pattern 1: Invalid stream IDs (negative, max value, bidirectional/unidirectional confusion)
                mutations.push(QuicFrame::Stream {
                    stream_id: u64::MAX,
                    offset: *offset,
                    fin: *fin,
                    data: data.clone(),
                });
                mutations.push(QuicFrame::Stream {
                    stream_id: 0,
                    offset: *offset,
                    fin: *fin,
                    data: data.clone(),
                });

                // CVE Pattern 2: Oversized offsets (integer overflow)
                mutations.push(QuicFrame::Stream {
                    stream_id: *stream_id,
                    offset: u64::MAX,
                    fin: *fin,
                    data: data.clone(),
                });

                // CVE Pattern 3: Oversized data (buffer overflow)
                mutations.push(QuicFrame::Stream {
                    stream_id: *stream_id,
                    offset: *offset,
                    fin: *fin,
                    data: vec![0xAA; 1024 * 1024], // 1MB payload
                });

                // CVE Pattern 4: FIN flag manipulation (send data after FIN)
                mutations.push(QuicFrame::Stream {
                    stream_id: *stream_id,
                    offset: *offset + data.len() as u64,
                    fin: true,
                    data: vec![0xFF; 100],
                });

                // CVE Pattern 5: Negative offset via wrapping
                mutations.push(QuicFrame::Stream {
                    stream_id: *stream_id,
                    offset: u64::MAX - 100,
                    fin: *fin,
                    data: vec![0x00; 200],
                });
            }

            QuicFrame::MaxData { max_data } => {
                // CVE Pattern 6: Flow control bypass (set max_data to zero)
                mutations.push(QuicFrame::MaxData { max_data: 0 });

                // CVE Pattern 7: Extremely large values (resource exhaustion)
                mutations.push(QuicFrame::MaxData {
                    max_data: u64::MAX,
                });

                // CVE Pattern 8: Decrease max_data (protocol violation)
                if *max_data > 1000 {
                    mutations.push(QuicFrame::MaxData {
                        max_data: max_data / 2,
                    });
                }
            }

            QuicFrame::MaxStreamData {
                stream_id,
                max_stream_data,
            } => {
                // CVE Pattern 9: Invalid stream ID with flow control
                mutations.push(QuicFrame::MaxStreamData {
                    stream_id: u64::MAX,
                    max_stream_data: *max_stream_data,
                });

                // CVE Pattern 10: Zero stream data limit
                mutations.push(QuicFrame::MaxStreamData {
                    stream_id: *stream_id,
                    max_stream_data: 0,
                });

                // CVE Pattern 11: Extremely large limit
                mutations.push(QuicFrame::MaxStreamData {
                    stream_id: *stream_id,
                    max_stream_data: u64::MAX,
                });
            }

            QuicFrame::Crypto { offset, data } => {
                // CVE Pattern 12: Crypto frame offset manipulation
                mutations.push(QuicFrame::Crypto {
                    offset: u64::MAX,
                    data: data.clone(),
                });

                // CVE Pattern 13: Oversized crypto data
                mutations.push(QuicFrame::Crypto {
                    offset: *offset,
                    data: vec![0x00; 100000],
                });

                // CVE Pattern 14: Malformed TLS handshake
                mutations.push(QuicFrame::Crypto {
                    offset: *offset,
                    data: vec![0xFF; 100],
                });
            }

            QuicFrame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                // CVE Pattern 15: Reset with wrong final size
                mutations.push(QuicFrame::ResetStream {
                    stream_id: *stream_id,
                    error_code: *error_code,
                    final_size: u64::MAX,
                });

                // CVE Pattern 16: Reset non-existent stream
                mutations.push(QuicFrame::ResetStream {
                    stream_id: u64::MAX,
                    error_code: *error_code,
                    final_size: *final_size,
                });

                // CVE Pattern 17: Multiple error codes
                for code in [0, 1, u64::MAX] {
                    mutations.push(QuicFrame::ResetStream {
                        stream_id: *stream_id,
                        error_code: code,
                        final_size: *final_size,
                    });
                }
            }

            QuicFrame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                // CVE Pattern 18: Oversized close reason
                mutations.push(QuicFrame::ConnectionClose {
                    error_code: *error_code,
                    frame_type: *frame_type,
                    reason: vec![0x41; 100000], // 100KB reason
                });

                // CVE Pattern 19: NULL bytes in reason
                mutations.push(QuicFrame::ConnectionClose {
                    error_code: *error_code,
                    frame_type: *frame_type,
                    reason: vec![0x00; 100],
                });

                // CVE Pattern 20: Invalid error codes
                for code in [0, 1, 0xFF, u64::MAX] {
                    mutations.push(QuicFrame::ConnectionClose {
                        error_code: code,
                        frame_type: *frame_type,
                        reason: reason.clone(),
                    });
                }
            }

            QuicFrame::PathChallenge { data } => {
                // CVE Pattern 21: Malformed PATH_CHALLENGE
                mutations.push(QuicFrame::PathChallenge {
                    data: [0x00; 8],
                });
                mutations.push(QuicFrame::PathChallenge {
                    data: [0xFF; 8],
                });
            }

            QuicFrame::PathResponse { data } => {
                // CVE Pattern 22: Wrong PATH_RESPONSE data
                mutations.push(QuicFrame::PathResponse {
                    data: [0x00; 8],
                });
                mutations.push(QuicFrame::PathResponse {
                    data: [0xFF; 8],
                });
            }

            _ => {
                // For other frames, create basic mutations
            }
        }

        mutations
    }

    /// Create frames that violate QUIC protocol state machine
    ///
    /// These frames are invalid in certain connection states and can
    /// trigger state machine bugs
    pub fn generate_invalid_sequence() -> Vec<QuicFrame> {
        vec![
            // Send HANDSHAKE_DONE before handshake completes
            QuicFrame::HandshakeDone,
            // Send data before connection established
            QuicFrame::Stream {
                stream_id: 4,
                offset: 0,
                fin: false,
                data: vec![0xAA; 100],
            },
            // Send CRYPTO after handshake done
            QuicFrame::Crypto {
                offset: 0,
                data: vec![0x01, 0x00, 0x00, 0x10], // Malformed TLS
            },
            // Multiple CONNECTION_CLOSE frames
            QuicFrame::ConnectionClose {
                error_code: 0,
                frame_type: None,
                reason: vec![],
            },
            QuicFrame::ConnectionClose {
                error_code: 1,
                frame_type: None,
                reason: b"double close".to_vec(),
            },
        ]
    }

    /// Generate frames targeting flow control vulnerabilities
    pub fn generate_flow_control_attacks() -> Vec<QuicFrame> {
        vec![
            // Try to send more data than allowed
            QuicFrame::Stream {
                stream_id: 0,
                offset: 0,
                fin: false,
                data: vec![0xAA; 100000],
            },
            // Set max_data to zero then try to send data
            QuicFrame::MaxData { max_data: 0 },
            QuicFrame::Stream {
                stream_id: 0,
                offset: 0,
                fin: false,
                data: vec![0xBB; 1000],
            },
            // Create many streams to exhaust resources
            QuicFrame::MaxStreams {
                max_streams: u64::MAX,
                bidirectional: true,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ping_frame() {
        let data = vec![0x01];
        let (frame, size) = QuicFrame::parse(&data).unwrap();
        assert!(matches!(frame, QuicFrame::Ping));
        assert_eq!(size, 1);
    }

    #[test]
    fn test_parse_padding_frame() {
        let data = vec![0x00, 0x00, 0x00];
        let (frame, size) = QuicFrame::parse(&data).unwrap();
        assert!(matches!(frame, QuicFrame::Padding { length: 3 }));
        assert_eq!(size, 3);
    }

    #[test]
    fn test_parse_crypto_frame() {
        let data = vec![
            0x06, // CRYPTO frame type
            0x00, // offset = 0
            0x04, // length = 4
            0x01, 0x02, 0x03, 0x04, // data
        ];
        let (frame, size) = QuicFrame::parse(&data).unwrap();
        match frame {
            QuicFrame::Crypto { offset, data: d } => {
                assert_eq!(offset, 0);
                assert_eq!(d, vec![0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected CRYPTO frame"),
        }
        assert_eq!(size, 7);
    }

    #[test]
    fn test_parse_stream_frame() {
        let data = vec![
            0x0e, // STREAM frame with offset, length, no FIN (0x08 | 0x04 | 0x02)
            0x04, // stream_id = 4
            0x10, // offset = 16
            0x05, // length = 5
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, // data
        ];
        let (frame, _) = QuicFrame::parse(&data).unwrap();
        match frame {
            QuicFrame::Stream {
                stream_id,
                offset,
                fin,
                data: d,
            } => {
                assert_eq!(stream_id, 4);
                assert_eq!(offset, 16);
                assert!(!fin);
                assert_eq!(d, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
            }
            _ => panic!("Expected STREAM frame"),
        }
    }

    #[test]
    fn test_serialize_ping() {
        let frame = QuicFrame::Ping;
        let bytes = frame.serialize();
        assert_eq!(bytes, vec![0x01]);
    }

    #[test]
    fn test_serialize_crypto() {
        let frame = QuicFrame::Crypto {
            offset: 0,
            data: vec![0x01, 0x02, 0x03],
        };
        let bytes = frame.serialize();
        assert_eq!(bytes, vec![0x06, 0x00, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_varint() {
        assert_eq!(encode_varint(0), vec![0x00]);
        assert_eq!(encode_varint(63), vec![0x3f]);
        assert_eq!(encode_varint(64), vec![0x40, 0x40]);
        assert_eq!(encode_varint(16383), vec![0x7f, 0xff]);
    }

    #[test]
    fn test_roundtrip_stream_frame() {
        let original = QuicFrame::Stream {
            stream_id: 10,
            offset: 100,
            fin: true,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let serialized = original.serialize();
        let (parsed, _) = QuicFrame::parse(&serialized).unwrap();

        match parsed {
            QuicFrame::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => {
                assert_eq!(stream_id, 10);
                assert_eq!(offset, 100);
                assert!(fin);
                assert_eq!(data, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            _ => panic!("Expected STREAM frame"),
        }
    }

    #[test]
    fn test_frame_mutator_stream() {
        let frame = QuicFrame::Stream {
            stream_id: 4,
            offset: 0,
            fin: false,
            data: vec![1, 2, 3],
        };

        let mutations = FrameMutator::mutate_frame(&frame);
        assert!(!mutations.is_empty());

        // Should generate multiple mutations
        assert!(mutations.len() >= 5);
    }

    #[test]
    fn test_frame_mutator_max_data() {
        let frame = QuicFrame::MaxData { max_data: 10000 };

        let mutations = FrameMutator::mutate_frame(&frame);
        assert!(!mutations.is_empty());

        // Should include zero, max, and decreased value
        assert!(mutations.len() >= 2);
    }

    #[test]
    fn test_invalid_sequence_generation() {
        let sequence = FrameMutator::generate_invalid_sequence();
        assert!(!sequence.is_empty());

        // Should contain multiple frames
        assert!(sequence.len() >= 3);
    }

    #[test]
    fn test_flow_control_attacks() {
        let attacks = FrameMutator::generate_flow_control_attacks();
        assert!(!attacks.is_empty());

        // Should contain various flow control attack patterns
        assert!(attacks.len() >= 3);
    }

    #[test]
    fn test_mutated_frames_serialize() {
        let frame = QuicFrame::Stream {
            stream_id: 0,
            offset: 0,
            fin: false,
            data: vec![0xAA; 10],
        };

        let mutations = FrameMutator::mutate_frame(&frame);

        // Ensure all mutations can be serialized
        for mutated in mutations {
            let _serialized = mutated.serialize();
            // Should not panic
        }
    }
}
