from binascii import hexlify
from collections import namedtuple
from bisect import bisect_right

from timeit import default_timer as timer

Coord = namedtuple('Coord', ['srec_idx', 'data_idx'])

class SRecError(Exception):
    pass

class SRec():
    ADDR_LEN = {
        '0':2,     #header s-record
        '1':2,     #data   s-record
        '2':3,     #data   s-record
        '3':4,     #data   s-record
        '5':2,     #count  s-record
        '7':4,     #footer s-record
        '8':3,     #footer s-record
        '9':2      #footer s-record
        }
    
    def __init__(self):
        self.type = ''
        self.count = bytearray
        self.address = bytearray()
        self.data = bytearray()
        self.cks = bytearray
    
    def read_srec(srecord:str):
        srecord = srecord.strip()
        srec = SRec()
        srec.type = srecord[1]
        if srec.type in SRec.ADDR_LEN:
            try:
                srec.count = bytearray.fromhex(srecord[2:4])
                srec.address = bytearray.fromhex(srecord[4 : 4 + srec.addr_len()])
                srec.data = bytearray.fromhex(srecord[4 + srec.addr_len() :-2])
                srec.cks = bytearray.fromhex(srecord[-2:])
            except ValueError as e:
                print("Error raised on following srec:")
                print(srecord)
                print(e)
        else:
            raise SRecError(f"Unknown SRec type : {srec.type}")
        return srec
    
    def addr_len(self):
        '''return the size of address field in char'''
        return SRec.ADDR_LEN[self.type]*2
    
    def check_data_len(self):
        return self.count[0] == len(self.address + self.data + self.cks)
    
    def __getitem__(self, position:int):
        return self.data[position]
    
    def __setitem__(self, position: int, value: int):
        self.data[position] = value
    
    def compute_cks(self):
        _cks = sum(self.count + self.address + self.data)
        _cks &= 0xFF
        _cks ^= 0xFF
        return bytearray([_cks])

    def update_cks(self):
        self.cks = self.compute_cks()

    def __str__(self):
        return self.to_string()
    
    def get_int_addr(self):
        return int.from_bytes(self.address, byteorder='big')
    
    def __repr__(self):
        _ret_str = 'S'
        _ret_str += self.type + ' '
        _ret_str += hexlify(self.count).decode('utf-8') + ' '
        _ret_str += hexlify(self.address).decode('utf-8') + ' '
        _ret_str += hexlify(self.data).decode('utf-8') + ' '
        _ret_str += hexlify(self.cks).decode('utf-8')
        return _ret_str.upper() 
    
    def to_string(self):
        _ret_str = 'S'
        _ret_str += self.type
        _ret_str += hexlify(self.count).decode('utf-8')
        _ret_str += hexlify(self.address).decode('utf-8')
        _ret_str += hexlify(self.data).decode('utf-8')
        _ret_str += hexlify(self.cks).decode('utf-8')
        return _ret_str.upper() 

class SRecSectorExcept(Exception):
    pass

class SRecSector:
    def __init__(self, address: int):
        self.start_address = address
        self.size = 0
        self.addresses = []
        self.srecs= []
        self.bytes = bytearray()
    
    def continuous(self, address: int):
        return address == self.start_address + self.size
    
    def __contains__(self, obj):
        if type(obj) == int:
            return self.start_address <= obj <= self.start_address + self.size 
        elif type(obj) == SRec:
            return self.start_address <= obj.get_int_addr() <= self.start_address + self.size  
    
    def add_srec(self, srec: SRec):
        int_addr = srec.get_int_addr()
        if not self.continuous(int_addr):
            raise SRecSectorExcept("Adress is not continous with sector")
        else:
            self.addresses.append(int_addr)
            self.srecs.append(srec)
            for byte in srec.data:
                self.bytes.append(byte)
            self.size += len(srec.data)
    
    def get_coord(self, position) -> Coord:
        if position not in self:
            raise SRecSectorExcept("given address is not in the sector")
        else:
            srec_idx = bisect_right(self.addresses, position) - 1
            data_idx = position - self.addresses[srec_idx]
            return Coord(srec_idx=srec_idx, data_idx=data_idx)
    
    def __getitem__(self, position):
        if position in self:
            return self.srecs[self.get_coord(position).srec_idx]
    
    def __setitem__(self, position, value: bytearray):
        if position not in self:
            raise SRecSectorExcept("given address is not in the sector")
        if (position + len(value)) not in self:
            raise SRecSectorExcept("given value overflows sector")
        else:
            byte_idx = position - self.start_address
            self.bytes[byte_idx : byte_idx + len(value)] = value
            _coord = self.get_coord(position)
            while value:
                self.srecs[_coord.srec_idx][_coord.data_idx] = value.pop(0)
                position += 1
                _coord = self.get_coord(position)
    
    def __iter__(self):
        return (srec for srec in self.srecs)
    
    def remap(self, new_start_address: int):
        _offset = self.start_address - new_start_address
        self.start_address = new_start_address
        self.addresses = [address + _offset for address in self.addresses]
        for srec in self.srecs:
            # ? working ?
            srec.address = bytearray.fromhex(hex(srec.get_int_addr() + _offset))
    
    def get_info(self) -> str:
        return f"starts at address 0x{hexlify(self.srecs[0].address)}, finishes at address 0x{hexlify(self.srecs[-1].address)}"


class SRecFile:
    def __init__(self):
        self.headers = []
        self.footers = []
        self.sectors = []
    
    def add_data_srec(self, srec: SRec) -> None:
        if len(self.sectors) != 0:
            for sector in self.sectors:
                if sector.continuous(srec.get_int_addr()):
                    sector.add_srec(srec)
                    break
            else:
                self.sectors.append(SRecSector(srec.get_int_addr()))
                self.sectors[-1].add_srec(srec)
        else:
            self.sectors.append(SRecSector(srec.get_int_addr()))
            self.sectors[-1].add_srec(srec)
        
    
    def read_file(self, file_name: str):
        start = timer()
        with open(file_name, 'r') as f:
            _srec_strings = f.readlines()
        for string in _srec_strings:
            srec = SRec.read_srec(string)
            if srec.type == '0':
                self.headers.append(srec)
            elif srec.type in ['7', '8', '9']:
                self.footers.append(srec)
            else:
                self.add_data_srec(srec)
        end = timer()
        print(f"Importation of file took {end - start} seconds")
    
    def sectors_infos(self):
        info_str = ''
        for i, sector in enumerate(self.sectors):
            info_str += f"Sector{i}: {sector.get_info()}\n"
        return info_str



srec_f = SRecFile()
srec_f.read_file("test_file.s19")
print(srec_f.sectors_infos())
