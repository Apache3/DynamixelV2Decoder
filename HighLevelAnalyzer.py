# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import Enum

HEADER_DATA = [bytes.fromhex('ff'), bytes.fromhex('ff'), bytes.fromhex('fd'), bytes.fromhex('00')]


class DxlState(Enum):
    HEADER = 0
    ADDRESS = 1
    LEN = 2
    COMMAND = 3
    RAM_ADDR = 4
    ERR_CODE = 5
    VALUE = 6
    CRC = 7


class DxlCommand(Enum):
    PING = bytes.fromhex('01')
    READ = bytes.fromhex('02')
    WRITE = bytes.fromhex('03')
    REG_WRITE = bytes.fromhex('04')
    ACTION = bytes.fromhex('05')
    FACTORY_RESET = bytes.fromhex('06')
    REBOOT = bytes.fromhex('08')
    CLEAR = bytes.fromhex('10')
    STATUS = bytes.fromhex('55')
    SYNC_READ = bytes.fromhex('82')
    SYNC_WRITE = bytes.fromhex('83')
    BULK_READ = bytes.fromhex('92')
    BULK_WRITE = bytes.fromhex('93')


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
        }
    }

    def __init__(self):
        self.state = DxlState.HEADER
        self.frame_counter = 0
        self.start_frame_timestamp = 0
        self.bytes_buffer = bytearray()
        self.frame_total_len = 0
        self.frame_len = 0
        self.frame_value = 0
        self.frame_command = DxlCommand.PING
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

    def parse_frames(self, frame: AnalyzerFrame, frame_len):
        ret = False
        data = frame.data['data']
        if self.frame_counter == 0:
            self.bytes_buffer.clear()
            self.start_frame_timestamp = frame.start_time

        self.frame_counter += 1
        self.bytes_buffer.extend(data)
        if self.frame_total_len != 0:
            self.frame_len += 1
        if self.frame_counter == frame_len:
            self.frame_value = int.from_bytes(self.bytes_buffer, byteorder="little")
            self.frame_counter = 0
            ret = True

        return ret

    def decode(self, frame: AnalyzerFrame):
        data = frame.data['data']

        if self.frame_total_len != 0 and self.frame_len >= self.frame_total_len:
            self.state = DxlState.HEADER
            self.frame_counter = 0
            self.bytes_buffer.clear()
            self.frame_total_len = 0
            self.frame_len = 0
            return AnalyzerFrame('Frame Error', frame.start_time
                                         , frame.end_time)

        if self.state == DxlState.HEADER:

            if data == HEADER_DATA[self.frame_counter]:
                if self.parse_frames(frame, 4):
                    self.state = DxlState.ADDRESS
                    return AnalyzerFrame('Header', self.start_frame_timestamp
                                         , frame.end_time)
            elif self.frame_counter != 0:
                self.frame_len = 1
                self.frame_total_len = 1
                return

        elif self.state == DxlState.ADDRESS:
            self.state = DxlState.LEN
            return AnalyzerFrame('Address', frame.start_time
                                 , frame.end_time, {'' : data})

        elif self.state == DxlState.LEN:
            if self.parse_frames(frame, 2):
                self.frame_total_len = self.frame_value
                analyzer_frame = AnalyzerFrame('Len',
                                               self.start_frame_timestamp,
                                               frame.end_time,
                                               {'int': self.frame_value})
                self.state = DxlState.COMMAND
                return analyzer_frame

        elif self.state == DxlState.COMMAND:
            self.parse_frames(frame, 1)
            self.frame_command = DxlCommand(data)
            name = ''
            if data == DxlCommand.PING.value:
                name = 'Ping'
                self.state = DxlState.CRC
            elif data == DxlCommand.READ.value:
                name = 'Read'
                self.state = DxlState.RAM_ADDR
            elif data == DxlCommand.WRITE.value:
                name = 'Write'
                self.state = DxlState.RAM_ADDR
            elif data == DxlCommand.REG_WRITE.value:
                name = 'Reg Write'
                self.state = DxlState.RAM_ADDR
            elif data == DxlCommand.ACTION.value:
                name = 'Action'
                self.state = DxlState.RAM_ADDR
            elif data == DxlCommand.FACTORY_RESET.value:
                name = 'Factory Reset'
                self.state = DxlState.CRC
            elif data == DxlCommand.REBOOT.value:
                name = 'Reboot '
                self.state = DxlState.CRC
            elif data == DxlCommand.CLEAR.value:
                name = 'Clear'
                self.state = DxlState.CRC
            elif data == DxlCommand.STATUS.value:
                name = 'Status'
                self.state = DxlState.ERR_CODE
            elif data == DxlCommand.SYNC_READ.value:
                name = 'Sync Read'
                self.state = DxlState.RAM_ADDR
            elif data == DxlCommand.SYNC_WRITE.value:
                name = 'Sync Write'
                self.state = DxlState.RAM_ADDR
            elif data == DxlCommand.BULK_READ.value:
                name = 'Bulk Read'
                self.state = DxlState.RAM_ADDR
            elif data == DxlCommand.BULK_WRITE.value:
                name = 'Bulk Write'
                self.state = DxlState.RAM_ADDR
            else:
                name = 'Command'
                self.state = DxlState.VALUE
            analyzer_frame = AnalyzerFrame(name, frame.start_time
                                           , frame.end_time)
            return analyzer_frame

        elif self.state == DxlState.RAM_ADDR:
            if self.parse_frames(frame, 2):
                analyzer_frame = AnalyzerFrame('Ram addr', self.start_frame_timestamp
                                               , frame.end_time, {'int': self.frame_value})
                self.state = DxlState.VALUE
                return analyzer_frame

        elif self.state == DxlState.ERR_CODE:
            self.parse_frames(frame, 1)
            if self.frame_len == (self.frame_total_len - 2):
                self.state = DxlState.CRC
            else :
                self.state = DxlState.VALUE
            return AnalyzerFrame('Code', frame.start_time
                                 , frame.end_time, {'': self.frame_value})

        elif self.state == DxlState.VALUE:
            nb_frames = min(2, self.frame_total_len - (self.frame_len + 2 - self.frame_counter))
            
            if self.parse_frames(frame, nb_frames):
                analyzer_frame = AnalyzerFrame('Value', self.start_frame_timestamp
                                               , frame.end_time, {'int': self.frame_value})
                if self.frame_len == (self.frame_total_len - 2):
                    self.state = DxlState.CRC
                return analyzer_frame

        elif self.state == DxlState.CRC:
            if self.parse_frames(frame, 2):
                analyzer_frame = AnalyzerFrame('CRC', self.start_frame_timestamp
                                               , frame.end_time, {'int': self.bytes_buffer[::-1].hex()})

                self.state = DxlState.HEADER
                self.frame_total_len = 0
                self.frame_len = 0
                return analyzer_frame

        return

