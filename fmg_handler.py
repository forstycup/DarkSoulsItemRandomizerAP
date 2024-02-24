import struct
import sys

class Entry:
    def __init__(self, id = None, text = None):
        self.id = id
        self.text = text

class Group:
    def __init__(self, offsetIndex = None, firstID = None, lastID = None):
        self.offsetIndex = offsetIndex
        self.firstID = firstID
        self.lastID = lastID

class FMGHandler:
    def __init__(self, messages: list[Entry] = None):
        if messages == None:
            messages = []
        self.messages = messages
    
    @classmethod
    def load_from_file_content(cls, file_content):
        master_offset = 0
        
        (unk00, bigEndian, version, unk03, fileSize, unk08, unk09, unk0A, unk0B, 
         groupCount, stringCount, stringOffsetsOffset) = struct.unpack_from("<BBBBIBBBBIII", file_content, offset=master_offset)
        
        master_offset = 0x1C  # set offset to length of the header.
        
        entries = []
        
        for i in range(groupCount):
            (offsetIndex, firstID, lastID) = struct.unpack_from("<III", file_content, offset=master_offset)           
            master_offset += struct.calcsize("<III")
            
            entries = []
            for j in range(lastID - firstID + 1):
                extracted = ''
                offset = 0
                
                curByte: bytes = struct.unpack_from("<B", file_content, offsetIndex + offset)
                while curByte != b'\x00':
                    extracted = extracted + curByte
                    offset += 1
                    (curByte,) = struct.unpack_from("<B", file_content, offsetIndex + offset)

                id = firstID + j
                entries.append(Entry(id, extracted.decode('shift-jis')))
                offset += 1

        return entries
             
    def export_as_binary(self):
        header_offset = 0x1C
        groupCount = 0

        self.messages.sort(key = lambda message: message.id)

        groups: list[Group] = []
        for i in range(self.messages):
            firstId = self.messages[i].id
            while i < (self.messages.count - 1) and self.messages[i+1].id == self.messages[i].id + 1:
                i += 1
            
            lastId = self.messages[i].id
            groups.append(Group(0, firstId, lastId))

        groupCount = groups.count
        groupsOffset = groupCount * struct.calcsize("<III")

        strings_offset = header_offset + groupsOffset
        packed_strings = b""
        packed_groups = b""

        groupIndex = 0
        current_string_offset = strings_offset
        for message in self.messages:
            if groupIndex < groupCount and message.id == groups[groupIndex].firstID:
                packed_groups += struct.pack("@III", current_string_offset, groups[groupIndex].firstID, groups[groupIndex].lastID)
            encodedMessage = message.text.encode('shift-jis') + b"\x00"
            packed_strings += encodedMessage
            current_string_offset += len(encodedMessage)

        fileLength = header_offset + groupsOffset + current_string_offset

        # unk00, bigEndian, version, unk03, fileSize, unk08, unk09, unk0A, unk0B, groupCount, stringCount, stringOffsetsOffset
        header = struct.pack("@BBBBIBBBBIIII", 0, 1, 1, 0, fileLength, 1, 0, 0, 0, groupCount, self.messages.count, strings_offset, 0)
        
        return header + packed_groups + packed_strings