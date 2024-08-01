"""
윈도우 환경에서 드라이버 설치하고 진행하기
pip install nfcpy pylibsdm

"""



import nfc
from pylibsdm.tag.ntag424dna import Tag, FileSettings

def on_connect(tag):
    try:
        if isinstance(tag, nfc.tag.tt4.Type4Tag):
            print("Type4Tag connected")

            # SDM 태그 설정
            sdm_tag = Tag(tag)

            # 마스터 애플리케이션 키 설정 (예시 키 사용)
            sdm_tag.set_key(0, b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")

            # NDEF 메시지 읽기
            ndef_message = tag.ndef.message
            if ndef_message:
                for record in ndef_message:
                    print("NDEF record type:", record.type)
                    print("NDEF record data:", record.data)

            # SDM 데이터 검증 (필요한 경우)
            # 여기서 sdm_tag를 사용하여 추가 검증 및 처리

        else:
            print("Not a Type4Tag")

    except Exception as e:
        print(f"Error: {e}")

def main():
    clf = nfc.ContactlessFrontend('usb')
    clf.connect(rdwr={'on-connect': on_connect})

if __name__ == "__main__":
    main()
