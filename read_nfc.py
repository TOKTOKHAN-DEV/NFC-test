import nfc
import usb.core
import usb.util
import usb.backend.libusb1


def on_connect(tag):
    print("태그가 감지되었습니다!")
    print("ID:", tag.identifier.hex().upper())

    if tag.ndef:
        print("NDEF 메시지가 감지되었습니다!")
        for record in tag.ndef.records:
            print("레코드 타입:", record.type)
            print("레코드 데이터:", record.data)
    else:
        print("NDEF 메시지가 없습니다.")

    return True


def main():
    # libusb 백엔드 명시적 지정
    backend = usb.backend.libusb1.get_backend(find_library=lambda x: "/opt/homebrew/lib/libusb-1.0.dylib")

    # USB 장치 초기화
    dev = usb.core.find(idVendor=0x072f, idProduct=0x2200, backend=backend)
    if dev is None:
        raise ValueError("장치를 찾을 수 없습니다.")

    # USB 장치 권한 설정
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