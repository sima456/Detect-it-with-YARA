// Yara rule file for network traffic analysis

rule detect_bad_tcp_flags {
    condition:
        tcp.flags contains {FIN, URG, PSH} or tcp.flags contains {FIN, SYN} or tcp.flags contains {SYN, RST}
}

rule detect_nxdomains {
    condition:
        dns.qtype == 0x20
}

rule detect_mz_header {
    condition:
        uint16(0) == 0x5A4D and uint16(uint32(0x3C)) == 0x0000
}

rule detect_pe_file {
    condition:
        pe.is_pe()
}

rule detect_rar_file {
    condition:
        uint8(0) == 0x52 and uint8(1) == 0x61 and uint8(2) == 0x72 and uint8(3) == 0x21 and uint8(4) == 0x1A and uint8(5) == 0x07 and uint8(6) == 0x00
}

rule detect_bad_extensions {
    condition:
        extension == "bat" or extension == "vbs" or extension == "ps1"
}

rule detect_dns_tunneling {
    condition:
        (dns.qtype == 46 and dns.qclass == 1) or (dns.qtype == 48 and dns.qclass == 1)
}

rule detect_large_dns_query {
    condition:
        dns.length > 300
}

rule detect_large_dns_response {
    condition:
        dns.resp_length > 300
}

rule detect_base64_encoded_data {
    condition:
        base64
}

rule detect_xor_encoded_data {
    condition:
        xor(0x41)
}

rule detect_files_with_specific_strings {
    condition:
        any of them
}

rule detect_entropy {
    condition:
        uint8(entropy(0, filesize)) >= 6.0
}

rule detect_packer_signature {
    condition:
        pe.is_packed() and pe.signature_name() contains "UPX"
}

rule detect_debug_info {
    condition:
        pe.has_debug() and pe.debug_signature contains "Microsoft"
}

rule detect_tls_cert_hashes {
    condition:
        tls.cert_subject_sha256 == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

rule detect_yara_signature {
    meta:
        author = "Ish"
        description = "Detects files that contain the Yara signature 'suspicious_yara_signature'"
    strings:
        $suspicious_yara_signature = "suspicious_yara_signature"
    condition:
        $suspicious_yara_signature in (pe.sections[*].entropy(7.0..), pe.exports[*], pe.imports[*])
}

rule detect_byte_sequence {
    condition:
        uint8(0) == 0x4D and uint8(1) == 0x5A and
        uint8(0x3C) == 0x45 and uint8(0x3D) == 0x4C and uint8(0x3E) == 0x46
}
