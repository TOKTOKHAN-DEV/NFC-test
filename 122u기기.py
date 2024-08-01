

from smartcard.System import readers
from smartcard.util import toHexString

def read_acr122u():
    try:
        # 리더기 목록 가져오기
        reader_list = readers()
        if len(reader_list) == 0:
            print("카드 없을때")
            return

        # 첫 번째 리더기 사용
        reader = reader_list[0]
        print(f"Using reader: {reader}")

        connection = reader.createConnection()

        try:
            connection.connect()
            print("연결됨.")
        except Exception as e:
            print(f"연결 실패: {e}")
            return

        # 카드의 UID를 읽기 위한 명령어
        get_uid_command = [0xFF, 0xCA, 0x00, 0x00, 0x00]
        response, sw1, sw2 = connection.transmit(get_uid_command)

        print(f"Response: {response}, SW1: {sw1}, SW2: {sw2}")
        if sw1 == 0x90 and sw2 == 0x00:
            uid = toHexString(response)
            print(f"Card UID: {uid}")
        else:
            print(f"Failed to read UID: SW1={sw1} SW2={sw2}")

    except Exception as e:
        print(f"Error: {e}")
"""
Response: [4, 88, 50, 146, 126, 117, 128], SW1: 144, SW2: 0
Card UID: 04 58 32 92 7E 75 80


Response: [4, 68, 138, 114, 193, 19, 144], SW1: 144, SW2: 0
Card UID: 04 44 8A 72 C1 13 90
"""
if __name__ == "__main__":
    read_acr122u()
