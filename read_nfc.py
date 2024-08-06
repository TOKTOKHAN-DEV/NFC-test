import nfc
import usb.core
import usb.util
import usb.backend.libusb1
from pylibsdm.tag.ntag424dna import Tag
from pylibsdm.tag.ntag424dna import FileOption, SDMOptions, AccessRights, SDMAccessRights, FileSettings
from pylibsdm.tag.ntag424dna import AccessCondition, CommMode


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

            # 태그 정보 확인
            print("태그 제품 정보:", sdm_tag.get_product_info())
            print("태그 버전 정보:", sdm_tag.get_version_info())

            # 마스터 앱 키 0 설정
            sdm_tag.set_key(0, b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")

            # 앱 키 1과 2 변경
            sdm_tag.change_key(1, 16 * b"\xaa")
            sdm_tag.change_key(2, 16 * b"\xbb")

            # 미러링을 위한 속성 구성
            file_option = FileOption(sdm_enabled=True, comm_mode=CommMode.PLAIN)
            sdm_options = SDMOptions(
                uid=True,
                read_ctr=True,
                read_ctr_limit=False,
                enc_file_data=False,
                tt_status=False,
                ascii_encoding=True,
            )

            # 액세스 권한 설정
            access_rights = AccessRights(
                read=AccessCondition.FREE_ACCESS,
                write=AccessCondition.KEY_1,
                read_write=AccessCondition.KEY_1,
                change=AccessCondition.KEY_0,
            )
            sdm_access_rights = SDMAccessRights(
                file_read=AccessCondition.KEY_2,
                meta_read=AccessCondition.KEY_2,
                ctr_ret=AccessCondition.KEY_2,
            )

            # 파일 설정 구성
            file_settings = FileSettings(
                file_option=file_option,
                access_rights=access_rights,
                sdm_options=sdm_options,
                sdm_access_rights=sdm_access_rights,
                picc_data_offset=32,
                mac_offset=67,
                mac_input_offset=67,
            )

            # 파일 설정 변경
            sdm_tag.change_file_settings(2, file_settings)

            # NDEF 메시지 준비 및 쓰기
            ndef_message = b"\xD1\x01\x0C\x55\x01\x6E\x74\x61\x67\x2E\x6E\x78\x70\x2E\x63\x6F\x6D\x2F\x34\x32\x34"
            sdm_tag.update_binary(0, ndef_message)

            # SUN 메시지 읽기
            sun_message = sdm_tag.read_sdm_file()
            print("SUN 메시지:", sun_message)
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