import ndef
import nfc
import usb.core
import usb.util
import usb.backend.libusb1
from pylibsdm.tag.ntag424dna import Tag, FileSettings, SDMAccessRights, AccessCondition, FileOption, AccessRights, \
    SDMOptions, CommMode


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
    print("태그 유형:", tag.type)

    manufacturer = get_manufacturer_info(tag)
    print("추정 제조사:", manufacturer)

    if hasattr(tag, 'ndef') and tag.ndef:
        print("태그 용량:", tag.ndef.capacity, "바이트")

    if hasattr(tag, 'sens_res'):
        print("ATQA (sens_res):", hex(tag.sens_res))
    if hasattr(tag, 'sel_res'):
        print("SAK (sel_res):", hex(tag.sel_res))

    for attr in dir(tag):
        if not attr.startswith('__') and not callable(getattr(tag, attr)):
            try:
                value = getattr(tag, attr)
                print(f"{attr}: {value}")
            except:
                pass

    if hasattr(tag, 'ndef') and tag.ndef:
        print("NDEF 메시지가 감지되었습니다!")
        for record in tag.ndef.records:
            print("레코드 타입:", record.type)
            print("레코드 데이터:", record.data)
    else:
        print("NDEF 메시지가 없습니다.")

    # SUN 기능 구현
    if isinstance(tag, nfc.tag.tt4.Type4Tag):
        try:
            sdm_tag = Tag(tag)
            print('sdm tag product:', sdm_tag.tag.product)
            print('sdm tag type:', sdm_tag.tag.type)
            print('sdm tag clf:', sdm_tag.tag.clf)
            print('sdm tag is_authenticated:', sdm_tag.tag.is_authenticated)
            print('sdm tag target:', sdm_tag.tag.target)
            print('sdm tag identifier:', sdm_tag.tag.identifier)

            print('sdm tag ndef:', sdm_tag.tag.ndef)
            print('sdm tag ndef tag:', sdm_tag.tag.ndef.tag)
            print('sdm tag ndef length:', sdm_tag.tag.ndef.length)
            print('sdm tag ndef capacity:', sdm_tag.tag.ndef.capacity)
            print('sdm tag ndef.is_readable:', sdm_tag.tag.ndef.is_readable)
            print('sdm tag ndef.is_writeable:', sdm_tag.tag.ndef.is_writeable)
            print('sdm tag ndef records 0 index:', sdm_tag.tag.ndef.records[0])


            # 초기화
            try:
                sdm_tag.reset_session()
                print("초기화")
            except Exception as e:
                print(f"초기화 실패: {e}")

            try:
                # 초기 마스터 키 설정
                sdm_tag.set_key(0, b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")
                print("마스터 앱 키 0 설정 성공")
            except Exception as e:
                print(f"마스터 앱 키 0 설정 실패: {e}")

                # 앱 키 1과 2 변경
            try:
                # 기존 키를 새로운 값으로 변경
                key1 = bytes.fromhex("FBC9F75C9413C041DFEE452D3F0706D1")
                key2 = bytes.fromhex("F793EEB928278083BFDC8A5A7E0E0D25")

                sdm_tag.set_key(1, key1)
                print("앱 키 1 변경 성공")

                sdm_tag.set_key(2, key2)
                print("앱 키 2 변경 성공")
            except Exception as e:
                print(f"앱 키 변경 실패: {e}")

            file_option = FileOption(sdm_enabled=True, comm_mode=CommMode.FULL)

            access_rights = AccessRights(
                read=AccessCondition.FREE_ACCESS,
                write=AccessCondition.KEY_1,
                read_write = AccessCondition.KEY_1,
                change = AccessCondition.KEY_0,
            )

            sdm_acceess_rights = SDMAccessRights(
                file_read=AccessCondition.KEY_2,
                meta_read=AccessCondition.KEY_2,
                ctr_ret=AccessCondition.KEY_2,
            )

            print('sdm_acceess_rights', sdm_acceess_rights)
            print('file_option', file_option)

            sdm_options = SDMOptions(
                uid=True,
                read_ctr=True,
                read_ctr_limit=False,
                enc_file_data=False,
                tt_status=False,
                ascii_encoding=True,
            )

            file_settings = FileSettings(
                file_option=file_option,
                access_rights=access_rights,
                sdm_options=sdm_options,
                sdm_access_rights=sdm_acceess_rights,
                picc_data_offset=32,
                mac_input_offset=67,
                mac_offset=131,
                tt_status_offset=70,
                enc_offset=67,
                enc_length=32,
                read_ctr_limit=1000
            )

            # print(file_data, file_data)
            print('file 세팅 전')
            sdm_tag.change_file_settings(2, file_settings)
            print('file 세팅 후')
            # sdm_tag.tag.records = [ndef.UriRecord(file_data)]
        except Exception as e:
            print(f"SUN 기능 구현 중 오류 발생: {e}")
            print("상세 오류 정보:", str(e))
    else:
        print("이 태그는 Type4Tag가 아니므로 SUN 기능을 구현할 수 없습니다.")

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