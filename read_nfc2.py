import ndef
import binascii
import nfc
import usb.core
import usb.util
import usb.backend.libusb1


def get_manufacturer_info(tag):
    uid = tag.identifier
    manufacturer = "Unknown"
    if uid[0] == 0x04:
        manufacturer = "NXP Semiconductors (likely)"
    elif uid[0] == 0x05:
        manufacturer = "Broadcom (likely)"
    return manufacturer


def on_connect(tag):
    print("태그가 감지되었습니다!")
    print("ID:", tag.identifier.hex().upper())

    if hasattr(tag, 'ndef') and tag.ndef:
        print("NDEF 메시지가 감지되었습니다!")
        for record in tag.ndef.records:
            print("레코드 타입:", record.type)
            print("레코드 데이터:", record.data)
    else:
        print("NDEF 메시지가 없습니다.")

    # Originality Signature Verification
    # skip

    # ISO SELECT NDEF Application using DF Name
    select_ndef_apdu = bytes.fromhex('00A4040C07D2760000850101')

    # 태그에 명령 전송
    select_ndef_apdu_response = tag.transceive(select_ndef_apdu)
    print(f'Selected NDEF application: {select_ndef_apdu_response.hex()}')

    # Get File Settings
    get_setting_apdu = bytes.fromhex('90F50000010200')
    get_setting_apdu_response = tag.transceive(get_setting_apdu)
    print(f'get_setting_response: {get_setting_apdu_response.hex()}')

    # Get version
    get_version_apdu = bytes.fromhex('9060000000')
    get_version_res = tag.transceive(get_version_apdu)
    print(f'get_version_response: {get_version_res.hex()}')

    # Change NDEF FILE Settings -> wrong
    change_file_setting_apdu = bytes.fromhex('905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400')
    change_file_setting_response = tag.transceive(change_file_setting_apdu)
    print(f'change_file_setting_response: {change_file_setting_response.hex()}')

    # AuthenticateEV2First with key 0x00 -> good
    # first 1
    authenticate_apdu = bytes.fromhex('9071000002000000')
    authenticate_apdu_response = tag.transceive(authenticate_apdu)
    print(f'authenticate_apdu response: {authenticate_apdu_response.hex()}')

    # second 2
    authenticate_apdu_2 = bytes.fromhex('90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00')
    authenticate_apdu_response_2 = tag.transceive(authenticate_apdu_2)
    print(f'authenticate_apdu_response_2: {authenticate_apdu_response_2.hex()}')

    # Change NDEF FILE Settings -> wrong
    change_file_setting_apdu = bytes.fromhex('905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400')
    change_file_setting_response = tag.transceive(change_file_setting_apdu)
    print(f'change_file_setting_response: {change_file_setting_response.hex()}')




    # AuthenticateAESNonFirst with key 0x00
    authenticate_with_3ey_apdu = bytes.fromhex('90770000010000')
    authenticate_3key_apdu_response = tag.transceive(authenticate_with_3ey_apdu)
    print(f'authenticate_apdu response: {authenticate_3key_apdu_response.hex()}')

    # second
    authenticate_with_3ey_second_apdu = bytes.fromhex('90AF000020BE7D45753F2CAB85F34BC60CE58B940763FE969658A532DF6D95EA2773F6E99100')
    authenticate_3key_second_apdu_response = tag.transceive(authenticate_with_3ey_second_apdu)
    print(f'authenticate_apdu response: {authenticate_3key_second_apdu_response.hex()}')

    #
    # # Prepare NDEF message
    # ndef_file_content_format = 'https://choose.url.com/ntag424?e=00000000000000000000000000000000&c=0000000000000000'
    # ndef_file_content_hex = "63686F6F73652E75726C2E636F6D2F6E7461673432343F653D303030303030303030303030303030303030303030303030303030303030303026633D30303030303030303030303030303030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    # ndef_length = "0051"
    # ndef_header = "D1014D5504"
    # ndef_message = ndef_length + ndef_header + ndef_file_content_hex
    # print(f'ndef_message: {ndef_message}')


    #  Write to CC - using Cmd.WriteData, CommMode.PLAIN
    comm_mode_plain_option = "00D6000053"
    write_comm_mode_plain_apdu = bytes.fromhex('908D000019010E0000120000FF0506E1050080828300000000000000000000')
    write_comm_mode_plain_apdu_response = tag.transceive(write_comm_mode_plain_apdu)
    print(f'write_comm_mode_plain: {write_comm_mode_plain_apdu_response.hex()}')




    # SUN 기능 구현
    try:
        print('실행')
    except Exception as e:
        print(f"SUN 기능 구현 중 오류 발생: {e}")
        print("상세 오류 정보:", str(e))
    return True


def main():
    backend = usb.backend.libusb1.get_backend(find_library=lambda x: "/opt/homebrew/lib/libusb-1.0.dylib")
    dev = usb.core.find(idVendor=0x072f, idProduct=0x2200, backend=backend)
    if dev is None:
        raise ValueError("장치를 찾을 수 없습니다.")
    if dev.is_kernel_driver_active(0):
        dev.detach_kernel_driver(0)
    dev.set_configuration()

    clf = nfc.ContactlessFrontend('usb:072f:2200')
    try:
        clf.connect(rdwr={'on-connect': on_connect})
    finally:
        clf.close()


if __name__ == "__main__":
    main()