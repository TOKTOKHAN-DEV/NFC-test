import ndef
import os
import nfc
import usb.core
import usb.util
import usb.backend.libusb1
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import cmac
from Crypto.Util.Padding import pad

key = b'\x00' * 16
IV = b'\x00' * 16


def truncate_mac(mac):
    mac_bytes = bytes.fromhex(mac)

    truncated_mac = bytes([mac_bytes[i] for i in range(1, len(mac_bytes), 2)])

    # 8바이트로 자르기
    return truncated_mac[:8]

def rotate_left_by_one_byte(byte_array):
    return byte_array[1:] + byte_array[:1]


def calculate_cmac(key, hex_message):
    # Convert the hex message to bytes
    message = unhexlify(hex_message)

    # Create a CMAC object using AES
    c = cmac.CMAC(algorithms.AES(key))

    # Update the CMAC with the message
    c.update(message)

    # Finalize the CMAC calculation and return the result
    return c.finalize()


def hex_xor(hex1, hex2):
    # 두 입력을 정수로 변환
    num1 = int(hex1, 16)
    num2 = int(hex2, 16)

    # XOR 연산 수행
    xor_result = num1 ^ num2

    # 결과를 16진수 문자열로 변환하여 반환 (0x 제거)
    return hex(xor_result)[2:].upper()

def calculate_sv1(rndA,rndB):
    part1 = rndA[0:4]
    part2 = hex_xor(rndA[4:16],rndB[0:12])
    part3 = rndB[12:]
    part4 = rndA[16:]
    return "A55A00010080"+part1+part2+part3+part4
def calculate_sv2(rndA,rndB):
    part1 = rndA[0:4]
    part2 = hex_xor(rndA[4:16], rndB[0:12])
    part3 = rndB[12:]
    part4 = rndA[16:]
    return "5AA500010080" + part1 + part2 + part3 + part4

def authenticate_ev2_first(tag):
    # Key and IV (should be securely managed in a real scenario)
    key = b'\x00' * 16
    IV = b'\x00' * 16

    # Step 1: Send AuthenticateEV2First command
    authenticate_apdu = bytes.fromhex('9071000002000000')
    authenticate_apdu_response = tag.transceive(authenticate_apdu)
    print(f'AuthenticateEV2First response: {authenticate_apdu_response.hex()}')

    # Step 2: Decrypt RndB
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    e_rndB = authenticate_apdu_response[:-2]  # Exclude status bytes
    rndB = cipher.decrypt(e_rndB)
    print(f'Decrypted RndB: {rndB.hex().upper()}')

    # Step 3: Generate RndA
    rndA = os.urandom(16)
    print(f'Generated RndA: {rndA}')

    # Step 4: Rotate RndB
    rndB_rotated = rotate_left_by_one_byte(rndB)
    print(f'Rotated RndB: {rndB_rotated.hex().upper()}')

    # Step 5: Encrypt RndA + rotated RndB
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    encrypt_rndA_rndB = cipher.encrypt(rndA + rndB_rotated)

    # Step 6: Send AuthenticateEV2Part2 command
    authenticate_part2_apdu = bytes.fromhex('90AF000020') + encrypt_rndA_rndB + bytes.fromhex('00')
    authenticate_apdu_response_2 = tag.transceive(authenticate_part2_apdu)
    print(f'AuthenticateEV2Part2 response: {authenticate_apdu_response_2.hex()}')
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    e_reponse = authenticate_apdu_response_2[:-2]
    d_reponse = cipher.decrypt(e_reponse)
    print(f'Decrypted Reponse: {d_reponse.hex().upper()}')
    TI = d_reponse[0:4].hex()
    print(f'TI: {TI}')
    print(f'Decrypted RndA: {rndA.hex().upper()}')
    SV_1 = calculate_sv1(rndA.hex(), rndB.hex())
    SV_2 = calculate_sv2(rndA.hex(), rndB.hex())
    print(f'SV_1 = {SV_1.upper()}')
    print(f'SV_2 = {SV_2.upper()}')
    # pass
    KSesAuthEnc = calculate_cmac(key, SV_1)
    KSesAuthMAC = calculate_cmac(key, SV_2)
    print(f'KSesAuthEnc: {KSesAuthEnc.hex().upper()}')
    print(f'KSesAuthMAC: {KSesAuthMAC.hex().upper()}')
    return KSesAuthEnc, KSesAuthMAC, TI

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
    get_version_apdu2 = bytes.fromhex('90AF000000')
    get_version_apdu2_response = tag.transceive(get_version_apdu2)
    print(f'get_version_apdu2: {get_version_apdu2_response.hex()}')
    get_version_apdu3 = bytes.fromhex('90AF000000')
    get_version_apdu3_response = tag.transceive(get_version_apdu3)
    print(f'get_version_apdu3: {get_version_apdu3_response.hex()}')

    # # AuthenticateEV2First with key 0x00
    KSesAuthEnc, KSesAuthMAC,TI = authenticate_ev2_first(tag)


    # Change NDEF File Settings
    cmd = '5F'
    cmdHeader = '02'
    cmdCtr = '0100'
    cmdData = '4000E0C1F121200000430000430000'
    cipher = AES.new(KSesAuthEnc, AES.MODE_CBC, IV=IV)
    input_IVc = bytes.fromhex('A55A'+TI+cmdCtr+'0000000000000000')
    IVc = cipher.encrypt(input_IVc)
    print(f'IVc: {IVc.hex()}')
    cipher2 = AES.new(KSesAuthEnc, AES.MODE_CBC, IV=IVc)
    e_cmdData = cipher2.encrypt(unhexlify(cmdData+'80')).hex()
    print(f'e_cmdData: {e_cmdData}')
    mac_data_input = cmd + cmdCtr + TI + cmdHeader + e_cmdData
    print(f'mac_data_input: {mac_data_input}')
    cmac = calculate_cmac(KSesAuthMAC, mac_data_input).hex()
    print(f'cmac: {cmac}')
    Mact = truncate_mac(cmac).hex()
    print(f'Mact: {Mact}')
    change_file_setting_adpu = bytes.fromhex('90'+cmd+'0000'+'1902'+e_cmdData+Mact+'00')
    print(f'change_file_setting_adpu: {change_file_setting_adpu.hex().upper()}')
    change_file_setting_response = tag.transceive(change_file_setting_adpu)
    print(f'Change file setting: {change_file_setting_response.hex()}')

    # # Write NDEF File - using Cmd.WriteData
    # cmd = '8D'
    # cmdHeader = "02000000800000"
    # cmdCtr = '0000'
    # cmdData = "0051D1014D550463686F6F73652E75726C2E636F6D2F6E7461673432343F653D303030303030303030303030303030303030303030303030303030303030303026633D3030303030303030303030303030303000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000"
    # padded_cmdData = pad(unhexlify(cmdData), AES.block_size)
    #
    # cipher = AES.new(KSesAuthEnc, AES.MODE_CBC, IV=IV)
    # input_IVc = bytes.fromhex('A55A'+TI+cmdCtr+'0000000000000000')
    # IVc = cipher.encrypt(input_IVc) # 9
    # print(f'IVc: {IVc.hex()}')
    # cipher2 = AES.new(KSesAuthEnc, AES.MODE_CBC, IV=IVc)
    # e_cmd_data = cipher2.encrypt(padded_cmdData).hex() # E(KSesAuthENC, IVc, CmdData || Padding (if necessary))
    # print(f'e_cmd_data: {e_cmd_data}')
    # prev_e_cmd_data = cmd+cmdCtr+TI+cmdHeader
    # cmd_cmdCounter_T1_cmdHeader_e_cmd_data = prev_e_cmd_data + e_cmd_data
    # mac = calculate_cmac(KSesAuthMAC, cmd_cmdCounter_T1_cmdHeader_e_cmd_data) # MAC(KSesAuthMAC, Cmd ||CmdCounter || TI || CmdHeader ||E(KSesAuthENC, CmdData) )
    # print(f'mac_data: {mac.hex()}')
    # MACt = truncate_mac(mac.hex()).hex()
    # print(f'MACt: {MACt.upper()}')
    # write_data_apdu = bytes.fromhex("90" + cmd_cmdCounter_T1_cmdHeader_e_cmd_data + MACt + "00")
    # write_data_apdu_response = tag.transceive(write_data_apdu)
    # print(f'write_data_apdu_response: {write_data_apdu_response.hex()}')




    #  Write to CC - using Cmd.WriteData, CommMode.PLAIN
    # comm_mode_plain_option = "00D6000053"
    # write_comm_mode_plain_apdu = bytes.fromhex('908D000019010E0000120000FF0506E1050080828300000000000000000000')
    # write_comm_mode_plain_apdu_response = tag.transceive(write_comm_mode_plain_apdu)
    # print(f'write_comm_mode_plain: {write_comm_mode_plain_apdu_response.hex()}')




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