from __future__ import annotations
from typing import Optional, Any
from atexit import register

from queue import Queue
from time import sleep
from threading import Thread
from smartcard.System import readers

THREAD_BLOCK_TIME: float = 0.1
APPLET_AID: str = '010203040506'

class APDUQueue:
    # declare variables
    _apdu_queue: Queue[APDU] = Queue()
    _quit: bool = False
    _connection: Any = None
    
    # singleton pattern creation
    _instance: Optional[APDUQueue] = None
    def __new__(cls) -> APDUQueue:
        if cls._instance is None:
            cls._instance = super(APDUQueue, cls).__new__(cls)
            cls._instance._init()
            register(cls._instance._exit)
        return cls._instance

    # singleton initialiser
    def _init(self) -> None:
        # connect to the first avaliable card
        the_readers: list = readers()
        self._connection = the_readers[0].createConnection()
        self._connection.connect()

        # start APDU queue processing thread
        Thread(target=self._process_apdu, daemon=True).start()

    # singleton destructor
    def _exit(self) -> None:
        self._quit = True
        self._connection.disconnect()

    def _process_apdu(self) -> None:
        while not self._quit:
            # check if queue is empty
            if self._apdu_queue.qsize() == 0: sleep(THREAD_BLOCK_TIME)

            # get next apdu
            apdu: APDU = self._apdu_queue.get()

            # send apdu and get response
            data, sw1, sw2 = self._connection.transmit(apdu.get_command_apdu_bytes())
            data.append(sw1);data.append(sw2)

            # set response bytes and mark processing complete
            apdu.set_response_apdu_bytes(data)
            apdu.mark_processing_complete()

    def enqueue_apdu(self, apdu: APDU) -> None:
        self._apdu_queue.put(apdu)

class APDU:
    _command_apdu_bytes: list[int] = []
    _response_apdu_bytes: list[int] = []
    _processed: bool = False

    def __init__(self, command_apdu_bytes: list[int]) -> None:
        # get send APDU bytes
        self._command_apdu_bytes = command_apdu_bytes

        # add self to apdu queue
        APDUQueue().enqueue_apdu(self)

        # begin thread blocking until this command is processed
        self._thread_block()

    def _thread_block(self) -> None:
        while not self._processed:
            sleep(THREAD_BLOCK_TIME)

    def get_command_apdu_bytes(self) -> list[int]:
        return self._command_apdu_bytes

    def get_response_apdu_bytes(self) -> list[int]:
        return self._response_apdu_bytes

    def get_response_data(self) -> list[int]:
        return self._response_apdu_bytes[:-2]

    def get_response_sw(self) -> list[int]:
        return self._response_apdu_bytes[-2:]

    def set_response_apdu_bytes(self, response_apdu_bytes: list[int]) -> None:
        self._response_apdu_bytes = response_apdu_bytes

    def mark_processing_complete(self) -> None:
        self._processed = True

    @staticmethod
    def get_apdu_bytes_from_string(apdu_string: str) -> list[int]:
        return [int(apdu_string[i:i+2], 16) for i in range(0, len(apdu_string), 2)]
    
    @staticmethod
    def get_apdu_string_from_bytes(apdu_bytes: list[int]) -> str:
        return ''.join([hex(i).lstrip('0x').upper().zfill(2) for i in apdu_bytes])

    @staticmethod
    def select_applet() -> bool:
        aid_prefix: str = hex(len(APPLET_AID)//2).lstrip('0x').upper().zfill(2)
        select_apdu: str = f'00A40400{aid_prefix}{APPLET_AID}7F'

        # send applet selection
        apdu: APDU = APDU(APDU.get_apdu_bytes_from_string(select_apdu))
        response: str = APDU.get_apdu_string_from_bytes(apdu.get_response_apdu_bytes())

        if response == '9000': return True
        return False