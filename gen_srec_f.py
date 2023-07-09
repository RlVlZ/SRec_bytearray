from secrets import token_hex
from test_bytearray import SRec

def gen_srec_str(type: str, address: int, data_len: int):
    addr_len = SRec.ADDR_LEN[type[1]]
    hex_addr_format = f"{{0:0>{addr_len*2}X}}"
    hex_addr = hex_addr_format.format(address)
    data_str = token_hex(data_len)
    count = '{0:0>2X}'.format(addr_len + data_len + 1)
    cks = 'AA'
    srec = SRec.read_srec(type + count + hex_addr + data_str + cks)
    srec.update_cks()
    return srec.to_string()

def gen_sector_str(type: str, start_addr : int, data_len : int, nr_srec: int):
    sector_str =''
    for i in range(nr_srec):
        sector_str += gen_srec_str(type, start_addr + data_len*i, data_len) + '\n'
    return sector_str

def gen_header_str():
    pass

def gen_footer_str():
    pass
    