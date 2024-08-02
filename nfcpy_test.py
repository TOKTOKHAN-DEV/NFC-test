import nfc

def on_connect(tag):
    try:
        if isinstance(tag, nfc.tag.tt4.Type4Tag):
            print("Type4Tag connected")
            # 추가적인 태그 처리 로직
        else:
            print("Not a Type4Tag")
    except Exception as e:
        print(f"Error: {e}")

def main():
    try:
        clf = nfc.ContactlessFrontend('usb:072f:2200')
        print("clf", clf)
        clf.connect(rdwr={'on-connect': on_connect})
    except PermissionError:
        print("Permission denied: Please run the script with elevated permissions.")
    except Exception as e:
        print(f"Failed to initialize NFC reader: {e}")

if __name__ == "__main__":
    main()
