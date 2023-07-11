import string

from binascii import hexlify
from collections import namedtuple
from bisect import bisect_right

from timeit import default_timer as timer

WORD_LEN = 4    # word len in bytes

Coord = namedtuple('Coord', ['srec_idx', 'data_idx'])

#===============#
# SRecors class #
#===============#

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
        self.update_cks()
    
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

#======================#
# SRecord sector class #
#======================#

class SRecSectorExcept(Exception):
    pass

class SRecSector:
    def __init__(self, address: int):
        self.start_address = address
        self.size = 0
        self.addresses = []
        self.srecs= []
        self.bytes = bytearray()
    

    def get_start_addr(self) -> int:
        return self.start_address


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
    
    def __getitem__(self, position: int):
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
        self.addresses = [address - _offset for address in self.addresses]
        for srec in self.srecs:
            # ? working ?
            srec.address = bytearray.fromhex(hex(srec.get_int_addr() - _offset)[2:])
            srec.update_cks()
    

    def get_info(self) -> str:
        _first_addr = hexlify(self.srecs[0].address).decode('utf-8')
        _last_addr = hex(self.srecs[-1].get_int_addr() + self.srecs[-1].count[0])
        return f"starts at address 0x{_first_addr}, finishes at address {_last_addr}"

#====================#
# SRecord file class #
#====================#

class SRecFileError(Exception):
    pass

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
            elif srec.type in '789':
                self.footers.append(srec)
            else:
                self.add_data_srec(srec)
        end = timer()
        print(f"Importation of file took {end - start} seconds")
    
    def __contains__(self, address):
        for sector in self.sectors:
            if address in sector:
                return True
        else:
            return False

    
    def sectors_infos(self):
        info_str = ''
        for i, sector in enumerate(self.sectors):
            info_str += f"Sector{i}: {sector.get_info()}\n"
        return info_str
    

    def patch(self, address, value):
        for sector in self.sectors:
            if address in sector:
                sector[address] = value
                break
        else:
            raise SRecFileError("address given not in file datas")
    
    def remap_sector(self, sector_idx, new_address):
        self.sectors[sector_idx].remap(new_address)

    def get_data(self, address: int, len: int) -> bytearray:
        for sector in self.sectors:
            if address in sector:
                position = sector.start_address - address
                return sector.bytes[position: position + len]
        else:
            raise SRecFileError("address given not in file datas")


#========================#
# SRecord Files Commands #
#========================#

class SRecCmd:
    def __init__(self, srec_f : SRecFile, cible, value):
        self.srec_f = srec_f
        self.cible = cible
        self.value = value

    def execute(self):
        pass

    def undo(self):
        pass

class SRecFPatchCmd(SRecCmd):
    def __init__(self, srec_f: SRecFile, cible: int, value: bytearray):
        super.__init__(srec_f, cible, value)
        self.init_state = srec_f.get_data[cible, len(value)]
    
    def execute(self):
        self.srec_f.patch(self.cible, self.value)

    def undo(self):
        self.srec_f.patch(self.cible, self.init_state)

class SRecFRemapCmd(SRecCmd):
    def __init__(self, srec_f: SRecFile, cible: int, value: int):
        super.__init__(srec_f, cible, value)
        self.old_address = srec_f.sectors[cible].get_start_addr()
    
    def execute(self):
        self.srec_f.remap_sector(self.cible, self.value)
    
    def undo(self):
        self.srec_f.remap_sector(self.cible, self.old_address)


#===============================#
# SRecord Files Command Invoker #
#===============================#

class SRecFileInvoker:
    def __init__(self):
        self.history = []

    def execute(self, command: SRecCmd):
        command.execute()
        self.history.append(command)
    
    def undo_last(self):
        self.history.pop().undo()


#======================#
# SRecord File Handler #
#======================#

class SRecFileHandlerError:
    pass

class SRecFileHandler:
    def __init__(self, srec_f: SRecFile):
        self.file_name = ''
        self.file_path = ''
        self.srec_f = srec_f
        self.client = SRecFileInvoker()
        self.scopes = []
        self.tags = []
    
    def address_converter(self):
        pass
    
    def value_converter(self):
        pass

    def add_scope(self):
        pass

    def add_tag(self):
        pass

    def display_scope(self):
        pass

    def hex_dump(self, address: int, addr_size, nb_words):

        def space_frmt(bytes:str) -> str:
            space_str = ' '.join([bytes[i:i+2] for i in range(0, len(bytes), 2)])
            return space_str
        
        def get_word(data: bytearray) -> list[str]:
            return [hexlify(data[i: i+WORD_LEN]).decode('utf-8') for i in range(0, len(data), WORD_LEN)]

        if address in srec_f and (address + nb_words*WORD_LEN) in srec_f:
            printables = set(string.printable) - set(string.whitespace)
            addr_field = f"{{0:0>{addr_size}X}}".format(address)
            data = self.srec_f.get_data(address, nb_words*WORD_LEN)
            ascii_field = ''

            for byte in data:
                if chr(byte) in printables:
                    ascii_field += chr(byte)
                else:
                    ascii_field += '.'

            data_field = get_word(data)
            data_field = [space_frmt(word) for word in data_field]

            return addr_field + ':  ' + '   '.join(data_field).upper() + '  | ' + ascii_field + ' | '

        else:
            raise SRecFileHandlerError("Adress not in file")

