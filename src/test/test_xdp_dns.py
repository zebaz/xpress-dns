import unittest

from bcc import BPF, libbcc
import ctypes
from scapy.all import *

#Struct representing the dns_query struct in common.h
class DNS_QUERY(ctypes.Structure):
    _fields_ = [("record_type", ctypes.c_uint16),
                ("class", ctypes.c_uint16),
                ("name", ctypes.c_char * 512)]

#Struct representing the a_record struct in common.h
class A_RECORD(ctypes.Structure):
    _fields_ = [("ip_addr", ctypes.c_uint32),
                ("ttl", ctypes.c_uint32)]


class DnsTestCase(unittest.TestCase):
    bpf = None
    func = None

    SKB_OUT_SIZE = 1514 #MTU 1500 + 14 eth size

    def _xdp_test_run(self, given_packet, expected_packet, expected_return, repeat=1):
        size = len(given_packet)
        given_packet = ctypes.create_string_buffer(raw(given_packet), size)
        packet_output = ctypes.create_string_buffer(self.SKB_OUT_SIZE)
        packet_output_size = ctypes.c_uint32()
        retval = ctypes.c_uint32()
        duration = ctypes.c_uint32()

        ret = libbcc.lib.bpf_prog_test_run(self.func.fd,
                                           repeat,
                                           ctypes.byref(given_packet),
                                           size,
                                           ctypes.byref(packet_output),
                                           ctypes.byref(packet_output_size),
                                           ctypes.byref(retval),
                                           ctypes.byref(duration))
        self.assertEqual(ret, 0)

        self.assertEqual(retval.value, expected_return)
        if expected_packet:
            self.assertEqual(data_out[:size_out.value], raw(expected_packet))

    def setUp(self):
        self.bpf = BPF(src_file=b"xdp_dns_kern.c")
        self.func = self.bpf.load_func(b"xdp_dns", BPF.XDP)

    def test_dns_no_match(self):
        packet_in =  Ether() / IP(dst="1.1.1.1") / UDP() / DNS(rd=1, qd=DNSQR(qname="foo.bar"))
        self._xdp_test_run(packet_in, None, BPF.XDP_PASS)

    def test_dns_match(self):
        packet_in =  Ether() / IP(dst="1.1.1.1") / UDP() / DNS(rd=1, qd=DNSQR(qname="foo.bar"))
#        q = DNS_QUERY(ctypes.c_uint16(1), ctypes.c_uint16(1), ctypes.create_string_buffer(b"foo.bar", 512))
        name = "foo.bar" + ("\0" * 505)
        q = DNS_QUERY(ctypes.c_uint16(1), ctypes.c_uint16(1), str.encode(name))
        a = A_RECORD(ctypes.c_uint32(1), ctypes.c_uint32(120))

        self.bpf["xdns_a_records"][q] = a
        self._xdp_test_run(packet_in, None, BPF.XDP_TX)


if __name__ == '__main__':
    unittest.main()
